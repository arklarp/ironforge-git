mod git;
mod graphql;
mod http;
mod mcp;
mod rest;
mod store;
mod util;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::http::{
    try_parse_request, HttpResponse, ParseResult, ParsedRequest, ReadState, CONTINUE_100_RESP,
    HEALTHZ_RESP, INITIAL_CONN_READ_CAP, NOT_FOUND_RESP, SHRINK_THRESHOLD,
};
use crate::store::Store;

const NUM_WORKERS: usize = 2;
const WAKEUP_TOKEN: u64 = u64::MAX;
const MAX_FREE_BUFS: usize = 64;

struct WorkerInbox {
    wakeup_fd: RawFd,
    notified: AtomicBool,
    fds: Mutex<Vec<RawFd>>,
}

enum PendingWrite {
    Static { data: &'static [u8], pos: usize },
    Shared { data: Arc<[u8]>, pos: usize },
    Owned { data: Vec<u8>, pos: usize },
}

impl PendingWrite {
    #[inline]
    fn slice(&self) -> &[u8] {
        match self {
            PendingWrite::Static { data, pos } => &data[*pos..],
            PendingWrite::Shared { data, pos } => &data[*pos..],
            PendingWrite::Owned { data, pos } => &data[*pos..],
        }
    }

    #[inline]
    fn advance(&mut self, n: usize) {
        match self {
            PendingWrite::Static { pos, .. }
            | PendingWrite::Shared { pos, .. }
            | PendingWrite::Owned { pos, .. } => *pos += n,
        }
    }
}

struct Conn {
    fd: RawFd,
    read: ReadState,
    write_pending: Option<PendingWrite>,
    write_is_100: bool,
    close_after_write: bool,
    want_write: bool,
    peer_eof: bool,
}

impl Conn {
    #[inline]
    fn new(fd: RawFd, buf: Vec<u8>) -> Self {
        Self {
            fd,
            read: ReadState::new(buf),
            write_pending: None,
            write_is_100: false,
            close_after_write: false,
            want_write: false,
            peer_eof: false,
        }
    }
}

enum ConnAction {
    Keep,
    WantWrite,
    StillWrite,
    WantRead,
    Close,
}

enum RecvOut {
    Bytes(usize),
    Eof,
    WouldBlock,
    Err,
}

enum SendOut {
    Done,
    Partial(usize),
    Err,
}

enum FlushRes {
    Done,
    Pending,
    Err,
}

enum ParseLoopOut {
    NeedMore { handled_any: bool },
    Close,
    WaitWritable,
    Sent100Now,
}

fn main() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let env_url = match std::env::var("MAKEFUN_ENV_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim_end_matches('/').to_owned(),
        _ => {
            eprintln!("[entry] MAKEFUN_ENV_URL is not set");
            std::process::exit(1);
        }
    };
    let token = std::env::var("MAKEFUN_SHOP_TOKEN").unwrap_or_default();

    let listener = TcpListener::bind("0.0.0.0:0").expect("bind ephemeral port");
    unsafe {
        libc::listen(listener.as_raw_fd(), 512);
    }
    let port = listener.local_addr().expect("local_addr").port();
    let store = Arc::new(Store::new(token));

    let mut epfds = [0i32; NUM_WORKERS];
    let mut wakeups = [0i32; NUM_WORKERS];
    for i in 0..NUM_WORKERS {
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(epfd >= 0, "epoll_create1 failed");
        let wfd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(wfd >= 0, "eventfd failed");
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: WAKEUP_TOKEN,
        };
        let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wfd, &mut ev) };
        assert!(rc == 0, "epoll_ctl add wakeup failed");
        epfds[i] = epfd;
        wakeups[i] = wfd;
    }

    let inboxes = Arc::new([
        WorkerInbox {
            wakeup_fd: wakeups[0],
            notified: AtomicBool::new(false),
            fds: Mutex::new(Vec::with_capacity(64)),
        },
        WorkerInbox {
            wakeup_fd: wakeups[1],
            notified: AtomicBool::new(false),
            fds: Mutex::new(Vec::with_capacity(64)),
        },
    ]);

    for i in 0..NUM_WORKERS {
        let epfd = epfds[i];
        let inboxes_ref = Arc::clone(&inboxes);
        let store_ref = Arc::clone(&store);
        let _ = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || run_worker(epfd, &inboxes_ref[i], store_ref));
    }

    let accept_inboxes = Arc::clone(&inboxes);
    let _ = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || run_acceptor(listener, accept_inboxes));

    register_port(&env_url, port);
    poll_done(&env_url);
    std::process::exit(0);
}

#[inline]
fn write_eventfd(fd: RawFd) {
    let val: u64 = 1;
    loop {
        let n = unsafe { libc::write(fd, &val as *const u64 as *const libc::c_void, 8) };
        if n >= 0 {
            break;
        }
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err != libc::EINTR {
            break;
        }
    }
}

#[inline]
fn drain_eventfd(fd: RawFd) {
    let mut val: u64 = 0;
    loop {
        let n = unsafe { libc::read(fd, &mut val as *mut u64 as *mut libc::c_void, 8) };
        if n >= 0 {
            break;
        }
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == libc::EINTR {
            continue;
        }
        break;
    }
}

fn run_acceptor(listener: TcpListener, inboxes: Arc<[WorkerInbox; NUM_WORKERS]>) {
    let listen_fd = listener.as_raw_fd();
    let mut rr = 0usize;
    loop {
        let fd = unsafe {
            libc::accept4(
                listen_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EINTR {
                continue;
            }
            if err == libc::EMFILE || err == libc::ENFILE {
                std::thread::sleep(Duration::from_millis(5));
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
            continue;
        }
        let inbox = &inboxes[rr & 1];
        rr = rr.wrapping_add(1);
        {
            let mut guard = inbox.fds.lock().unwrap();
            guard.push(fd);
        }
        if !inbox.notified.swap(true, Ordering::SeqCst) {
            write_eventfd(inbox.wakeup_fd);
        }
    }
}

fn run_worker(epfd: RawFd, inbox: &WorkerInbox, store: Arc<Store>) {
    let mut conns: Vec<Option<Conn>> = Vec::with_capacity(256);
    let mut free_bufs: Vec<Vec<u8>> = Vec::with_capacity(MAX_FREE_BUFS);
    let mut write_buf: Vec<u8> = Vec::with_capacity(65536);
    let mut local_fds: Vec<RawFd> = Vec::with_capacity(64);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 128];

    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, -1) };
        if n < 0 {
            let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EINTR {
                continue;
            }
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }

        for i in 0..(n as usize) {
            // epoll_event is repr(packed) on x86_64; copy fields by value.
            let ev_flags = events[i].events;
            let token = events[i].u64;

            if token == WAKEUP_TOKEN {
                drain_eventfd(inbox.wakeup_fd);
                inbox.notified.store(false, Ordering::SeqCst);
                {
                    let mut guard = inbox.fds.lock().unwrap();
                    std::mem::swap(&mut *guard, &mut local_fds);
                }
                for &fd in &local_fds {
                    if fd < 0 {
                        continue;
                    }
                    let nodelay: libc::c_int = 1;
                    unsafe {
                        libc::setsockopt(
                            fd,
                            libc::IPPROTO_TCP,
                            libc::TCP_NODELAY,
                            &nodelay as *const libc::c_int as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        );
                    }
                    let mut ev = libc::epoll_event {
                        events: (libc::EPOLLIN | libc::EPOLLRDHUP) as u32,
                        u64: fd as u64,
                    };
                    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
                    if rc < 0 {
                        unsafe {
                            libc::close(fd);
                        }
                        continue;
                    }
                    let idx = fd as usize;
                    if idx >= conns.len() {
                        conns.resize_with(idx + 1, || None);
                    }
                    let buf = match free_bufs.pop() {
                        Some(mut b) => {
                            if b.len() < INITIAL_CONN_READ_CAP {
                                b.resize(INITIAL_CONN_READ_CAP, 0);
                            }
                            b
                        }
                        None => vec![0u8; INITIAL_CONN_READ_CAP],
                    };
                    conns[idx] = Some(Conn::new(fd, buf));
                }
                local_fds.clear();
                continue;
            }

            let fd = token as RawFd;
            let idx = fd as usize;
            let Some(conn) = conns.get_mut(idx).and_then(Option::as_mut) else {
                continue;
            };

            let action = if conn.write_pending.is_some() {
                if (ev_flags & (libc::EPOLLERR | libc::EPOLLHUP) as u32) != 0 {
                    ConnAction::Close
                } else if (ev_flags & libc::EPOLLOUT as u32) != 0 {
                    on_writable(conn, &mut write_buf, &store)
                } else {
                    ConnAction::Keep
                }
            } else if (ev_flags & libc::EPOLLERR as u32) != 0
                || ((ev_flags & libc::EPOLLHUP as u32) != 0
                    && (ev_flags & libc::EPOLLIN as u32) == 0)
            {
                ConnAction::Close
            } else {
                on_readable(conn, &mut write_buf, &store)
            };

            match action {
                ConnAction::Keep | ConnAction::StillWrite => {}
                ConnAction::WantWrite => {
                    if !conn.want_write {
                        conn.want_write = true;
                        let mut ev = libc::epoll_event {
                            events: (libc::EPOLLOUT | libc::EPOLLRDHUP) as u32,
                            u64: fd as u64,
                        };
                        if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_MOD, fd, &mut ev) } < 0 {
                            close_conn(&mut conns, &mut free_bufs, fd);
                        }
                    }
                }
                ConnAction::WantRead => {
                    if conn.want_write {
                        conn.want_write = false;
                        let mut ev = libc::epoll_event {
                            events: (libc::EPOLLIN | libc::EPOLLRDHUP) as u32,
                            u64: fd as u64,
                        };
                        if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_MOD, fd, &mut ev) } < 0 {
                            close_conn(&mut conns, &mut free_bufs, fd);
                        }
                    }
                }
                ConnAction::Close => {
                    close_conn(&mut conns, &mut free_bufs, fd);
                }
            }
        }
    }
}

#[inline]
fn close_conn(conns: &mut [Option<Conn>], free_bufs: &mut Vec<Vec<u8>>, fd: RawFd) {
    let idx = fd as usize;
    if idx < conns.len() {
        if let Some(mut conn) = conns[idx].take() {
            if free_bufs.len() < MAX_FREE_BUFS {
                if conn.read.buf.len() > SHRINK_THRESHOLD {
                    conn.read.buf.truncate(INITIAL_CONN_READ_CAP);
                    conn.read.buf.shrink_to(INITIAL_CONN_READ_CAP);
                }
                free_bufs.push(conn.read.buf);
            }
        }
    }
    unsafe {
        libc::close(fd);
    }
}

#[inline]
fn recv_nonblock(fd: RawFd, buf: &mut [u8]) -> RecvOut {
    loop {
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n > 0 {
            return RecvOut::Bytes(n as usize);
        }
        if n == 0 {
            return RecvOut::Eof;
        }
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == libc::EINTR {
            continue;
        }
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
            return RecvOut::WouldBlock;
        }
        return RecvOut::Err;
    }
}

#[inline]
fn send_slice_all(fd: RawFd, slice: &[u8]) -> SendOut {
    let mut sent = 0usize;
    while sent < slice.len() {
        let n = unsafe {
            libc::send(
                fd,
                slice.as_ptr().add(sent) as *const libc::c_void,
                slice.len() - sent,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if n > 0 {
            sent += n as usize;
        } else if n == 0 {
            return SendOut::Partial(sent);
        } else {
            let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EINTR {
                continue;
            }
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                return SendOut::Partial(sent);
            }
            return SendOut::Err;
        }
    }
    SendOut::Done
}

#[inline]
fn send_response_now(
    conn: &mut Conn,
    write_buf: &Vec<u8>,
    resp: HttpResponse,
    close_after: bool,
) -> FlushRes {
    let slice: &[u8] = match &resp {
        HttpResponse::Static(s) => s,
        HttpResponse::Shared(arc) => arc.as_ref(),
        HttpResponse::Owned => write_buf.as_slice(),
    };
    match send_slice_all(conn.fd, slice) {
        SendOut::Done => FlushRes::Done,
        SendOut::Partial(off) => {
            conn.write_pending = Some(match resp {
                HttpResponse::Static(s) => PendingWrite::Static { data: s, pos: off },
                HttpResponse::Shared(arc) => PendingWrite::Shared {
                    data: arc,
                    pos: off,
                },
                HttpResponse::Owned => PendingWrite::Owned {
                    data: write_buf[off..].to_vec(),
                    pos: 0,
                },
            });
            conn.write_is_100 = false;
            conn.close_after_write = close_after;
            FlushRes::Pending
        }
        SendOut::Err => FlushRes::Err,
    }
}

#[inline]
fn dispatch_request(
    buf: &[u8],
    req: &ParsedRequest,
    write_buf: &mut Vec<u8>,
    store: &Store,
) -> HttpResponse {
    let method = req.method.slice(buf);
    let path = req.path.slice(buf);
    let query = req.query.slice(buf);
    let auth = req.authorization.map(|s| s.slice(buf));
    let host = req.host.map(|s| s.slice(buf));
    let git_proto = req.git_protocol.map(|s| s.slice(buf));
    let body = req.body(buf);

    if method == b"GET" && path == b"/healthz" {
        HttpResponse::Static(HEALTHZ_RESP)
    } else if path.starts_with(b"/api/v3") {
        rest::handle_rest(write_buf, store, method, path, query, auth, host, body)
    } else if path == b"/api/graphql" {
        graphql::handle_graphql(write_buf, store, auth, body)
    } else if path == b"/mcp" {
        mcp::handle_mcp(write_buf, store, method, auth, body)
    } else if path.contains(&b'.') && path.windows(5).any(|w| w == b".git/") {
        git::handle_git(write_buf, store, method, path, query, auth, git_proto, body)
    } else {
        HttpResponse::Static(NOT_FOUND_RESP)
    }
}

fn run_parse_loop(conn: &mut Conn, write_buf: &mut Vec<u8>, store: &Store) -> ParseLoopOut {
    let mut handled_any = false;
    loop {
        match try_parse_request(&mut conn.read) {
            ParseResult::Complete(req) => {
                handled_any = true;
                let keep_alive = req.keep_alive;
                let next_pos = req.next_pos;
                let resp = dispatch_request(&conn.read.buf, &req, write_buf, store);
                conn.read.advance(next_pos);
                match send_response_now(conn, write_buf, resp, !keep_alive) {
                    FlushRes::Done => {
                        if !keep_alive {
                            return ParseLoopOut::Close;
                        }
                        if conn.read.pos >= conn.read.len {
                            return ParseLoopOut::NeedMore { handled_any: true };
                        }
                    }
                    FlushRes::Pending => return ParseLoopOut::WaitWritable,
                    FlushRes::Err => return ParseLoopOut::Close,
                }
            }
            ParseResult::Send100Continue => match send_slice_all(conn.fd, CONTINUE_100_RESP) {
                SendOut::Done => return ParseLoopOut::Sent100Now,
                SendOut::Partial(off) => {
                    conn.write_pending = Some(PendingWrite::Static {
                        data: CONTINUE_100_RESP,
                        pos: off,
                    });
                    conn.write_is_100 = true;
                    conn.close_after_write = false;
                    return ParseLoopOut::WaitWritable;
                }
                SendOut::Err => return ParseLoopOut::Close,
            },
            ParseResult::NeedMore => return ParseLoopOut::NeedMore { handled_any },
            ParseResult::Error => return ParseLoopOut::Close,
        }
    }
}

fn on_readable(conn: &mut Conn, write_buf: &mut Vec<u8>, store: &Store) -> ConnAction {
    'io: loop {
        if !conn.read.ensure_space() {
            return ConnAction::Close;
        }
        match recv_nonblock(conn.fd, &mut conn.read.buf[conn.read.len..]) {
            RecvOut::Bytes(k) => {
                conn.read.len += k;
            }
            RecvOut::Eof => {
                conn.peer_eof = true;
            }
            RecvOut::WouldBlock => {
                if conn.peer_eof && conn.read.pos >= conn.read.len {
                    return ConnAction::Close;
                }
                return ConnAction::Keep;
            }
            RecvOut::Err => return ConnAction::Close,
        }

        match run_parse_loop(conn, write_buf, store) {
            ParseLoopOut::NeedMore { handled_any } => {
                if conn.peer_eof {
                    return ConnAction::Close;
                }
                if handled_any && conn.read.pos >= conn.read.len {
                    return ConnAction::Keep;
                }
                continue 'io;
            }
            ParseLoopOut::Sent100Now => {
                if conn.peer_eof {
                    return ConnAction::Close;
                }
                continue 'io;
            }
            ParseLoopOut::WaitWritable => return ConnAction::WantWrite,
            ParseLoopOut::Close => return ConnAction::Close,
        }
    }
}

fn on_writable(conn: &mut Conn, write_buf: &mut Vec<u8>, store: &Store) -> ConnAction {
    let Some(ref mut pw) = conn.write_pending else {
        return ConnAction::WantRead;
    };
    match send_slice_all(conn.fd, pw.slice()) {
        SendOut::Done => {
            conn.write_pending = None;
            let was_100 = conn.write_is_100;
            conn.write_is_100 = false;
            if conn.close_after_write {
                return ConnAction::Close;
            }
            if was_100 {
                return ConnAction::WantRead;
            }
            if conn.read.pos < conn.read.len {
                match run_parse_loop(conn, write_buf, store) {
                    ParseLoopOut::NeedMore { .. } | ParseLoopOut::Sent100Now => {
                        if conn.peer_eof {
                            return ConnAction::Close;
                        }
                        ConnAction::WantRead
                    }
                    ParseLoopOut::WaitWritable => ConnAction::StillWrite,
                    ParseLoopOut::Close => ConnAction::Close,
                }
            } else {
                ConnAction::WantRead
            }
        }
        SendOut::Partial(n) => {
            pw.advance(n);
            ConnAction::StillWrite
        }
        SendOut::Err => ConnAction::Close,
    }
}

fn parse_http_url(url: &str) -> (String, String) {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, base_path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].trim_end_matches('/')),
        None => (rest, ""),
    };
    let addr = if host_port.contains(':') {
        host_port.to_owned()
    } else {
        format!("{}:80", host_port)
    };
    (addr, base_path.to_owned())
}

fn env_http_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(addr).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut req = Vec::with_capacity(256);
    req.extend_from_slice(method.as_bytes());
    req.push(b' ');
    req.extend_from_slice(path.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(addr.as_bytes());
    req.extend_from_slice(b"\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.extend_from_slice(b"Content-Type: application/json\r\nContent-Length: ");
        req.extend_from_slice(b.len().to_string().as_bytes());
        req.extend_from_slice(b"\r\n\r\n");
        req.extend_from_slice(b);
    } else {
        req.extend_from_slice(b"\r\n");
    }
    stream.write_all(&req).ok()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let hdr_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let hdr = std::str::from_utf8(&raw[..hdr_end]).ok()?;
    let first_line = hdr.lines().next()?;
    let status = first_line
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    let resp_body = String::from_utf8_lossy(&raw[hdr_end + 4..]).into_owned();
    Some((status, resp_body))
}

fn register_port(env_url: &str, port: u16) {
    let (addr, base_path) = parse_http_url(env_url);
    let path = format!("{}/register", base_path);
    let payload = format!("{{\"port\":{}}}", port);
    let mut delay_ms = 50u64;
    loop {
        if let Some((status, resp)) =
            env_http_request(&addr, "POST", &path, Some(payload.as_bytes()))
        {
            if status == 200 || status == 409 {
                return;
            }
            if status == 400 || status == 405 {
                eprintln!("[entry] register rejected HTTP {}: {}", status, resp);
                std::process::exit(1);
            }
        }
        std::thread::sleep(Duration::from_millis(delay_ms));
        delay_ms = (delay_ms * 2).min(1000);
    }
}

fn poll_done(env_url: &str) {
    let (addr, base_path) = parse_http_url(env_url);
    let path = format!("{}/done", base_path);
    loop {
        if let Some((200, body)) = env_http_request(&addr, "GET", &path, None) {
            if body.contains("\"done\":true") || body.contains("\"done\": true") {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
