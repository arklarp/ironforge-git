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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::http::{
    try_parse_request, HttpResponse, ParseResult, ParsedRequest, ReadState, CONTINUE_100_RESP,
    HEALTHZ_RESP, INITIAL_CONN_READ_CAP, NOT_FOUND_RESP, SHRINK_THRESHOLD,
};
use crate::store::Store;

const PREWARMED_WORKERS: usize = 72;
const MAX_WORKERS: usize = 112;
const WORKER_STACK_SIZE: usize = 64 * 1024;
const INITIAL_WRITE_CAP: usize = 16 * 1024;

struct Shared {
    listen_fd: RawFd,
    accept_lock: Mutex<()>,
    store: Store,
    busy: AtomicUsize,
    total: AtomicUsize,
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
    let shared = Arc::new(Shared {
        listen_fd: listener.as_raw_fd(),
        accept_lock: Mutex::new(()),
        store: Store::new(token),
        busy: AtomicUsize::new(0),
        total: AtomicUsize::new(PREWARMED_WORKERS),
    });

    let ready = Arc::new(AtomicUsize::new(0));
    let mut spawned = 0usize;
    for _ in 0..PREWARMED_WORKERS {
        if spawn_worker(Arc::clone(&shared), Some(Arc::clone(&ready))) {
            spawned += 1;
        }
    }
    shared.total.store(spawned, Ordering::Release);
    while ready.load(Ordering::Acquire) < spawned {
        std::thread::yield_now();
    }

    register_port(&env_url, port);
    poll_done(&env_url);
    drop(listener);
    std::process::exit(0);
}

#[inline]
fn spawn_worker(shared: Arc<Shared>, ready: Option<Arc<AtomicUsize>>) -> bool {
    std::thread::Builder::new()
        .stack_size(WORKER_STACK_SIZE)
        .spawn(move || worker_loop(shared, ready))
        .is_ok()
}

fn worker_loop(shared: Arc<Shared>, ready: Option<Arc<AtomicUsize>>) {
    let mut rs = ReadState::new(vec![0u8; INITIAL_CONN_READ_CAP]);
    let mut write_buf = Vec::with_capacity(INITIAL_WRITE_CAP);
    if let Some(r) = ready {
        r.fetch_add(1, Ordering::Release);
    }

    loop {
        let fd = {
            let _guard = shared.accept_lock.lock().unwrap();
            accept_blocking(shared.listen_fd)
        };
        if fd < 0 {
            continue;
        }

        let busy = shared.busy.fetch_add(1, Ordering::AcqRel) + 1;
        let total = shared.total.load(Ordering::Acquire);
        if busy >= total && total < MAX_WORKERS {
            let add = (MAX_WORKERS - total).min(8);
            if shared
                .total
                .compare_exchange(total, total + add, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let mut actual = 0usize;
                for _ in 0..add {
                    if spawn_worker(Arc::clone(&shared), None) {
                        actual += 1;
                    }
                }
                if actual < add {
                    shared.total.fetch_sub(add - actual, Ordering::AcqRel);
                }
            }
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

        handle_connection(fd, &mut rs, &mut write_buf, &shared.store);

        unsafe {
            libc::close(fd);
        }
        if write_buf.capacity() > SHRINK_THRESHOLD {
            write_buf = Vec::with_capacity(INITIAL_WRITE_CAP);
        }
        shared.busy.fetch_sub(1, Ordering::AcqRel);
    }
}

#[inline]
fn accept_blocking(listen_fd: RawFd) -> RawFd {
    loop {
        let fd = unsafe {
            libc::accept4(
                listen_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd >= 0 {
            return fd;
        }
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == libc::EINTR {
            continue;
        }
        if err == libc::EMFILE || err == libc::ENFILE {
            std::thread::sleep(Duration::from_millis(5));
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[inline]
fn recv_blocking(fd: RawFd, buf: &mut [u8]) -> Option<usize> {
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n >= 0 {
            return Some(n as usize);
        }
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == libc::EINTR {
            continue;
        }
        return None;
    }
}

#[inline]
fn send_all_blocking(fd: RawFd, slice: &[u8]) -> bool {
    let mut sent = 0usize;
    while sent < slice.len() {
        let n = unsafe {
            libc::send(
                fd,
                slice.as_ptr().add(sent) as *const libc::c_void,
                slice.len() - sent,
                libc::MSG_NOSIGNAL,
            )
        };
        if n > 0 {
            sent += n as usize;
        } else if n == 0 {
            return false;
        } else {
            let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EINTR {
                continue;
            }
            return false;
        }
    }
    true
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

fn handle_connection(
    fd: RawFd,
    rs: &mut ReadState,
    write_buf: &mut Vec<u8>,
    store: &Store,
) {
    rs.reset_for_new_conn();
    loop {
        loop {
            match try_parse_request(rs) {
                ParseResult::Complete(req) => {
                    let keep_alive = req.keep_alive;
                    let next_pos = req.next_pos;
                    let resp = dispatch_request(&rs.buf, &req, write_buf, store);
                    rs.advance(next_pos);
                    let slice: &[u8] = match &resp {
                        HttpResponse::Static(s) => s,
                        HttpResponse::Shared(arc) => arc.as_ref(),
                        HttpResponse::Owned => write_buf.as_slice(),
                    };
                    if !send_all_blocking(fd, slice) || !keep_alive {
                        return;
                    }
                    if rs.pos >= rs.len {
                        break;
                    }
                }
                ParseResult::Send100Continue => {
                    if !send_all_blocking(fd, CONTINUE_100_RESP) {
                        return;
                    }
                    break;
                }
                ParseResult::NeedMore => break,
                ParseResult::Error => return,
            }
        }

        if !rs.ensure_space() {
            return;
        }
        match recv_blocking(fd, &mut rs.buf[rs.len..]) {
            Some(k) if k > 0 => rs.len += k,
            _ => return,
        }
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
