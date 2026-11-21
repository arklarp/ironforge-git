mod git;
mod graphql;
mod http;
mod mcp;
mod rest;
mod store;
mod util;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::http::{
    read_http_request, write_preframed, ConnBufs, HEALTHZ_RESP, NOT_FOUND_RESP,
};
use crate::store::Store;

const BASE_WORKERS: usize = 2;
const MAX_WORKERS: usize = 64;

fn main() {
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

    let listener = Arc::new(listener);
    let store = Arc::new(Store::new(token));
    let busy_workers = Arc::new(AtomicUsize::new(0));
    let total_workers = Arc::new(AtomicUsize::new(BASE_WORKERS));

    for _ in 0..BASE_WORKERS {
        spawn_worker(
            Arc::clone(&listener),
            Arc::clone(&store),
            Arc::clone(&busy_workers),
            Arc::clone(&total_workers),
        );
    }

    register_port(&env_url, port);
    poll_done(&env_url);
    std::process::exit(0);
}

fn spawn_worker(
    listener: Arc<TcpListener>,
    store: Arc<Store>,
    busy_workers: Arc<AtomicUsize>,
    total_workers: Arc<AtomicUsize>,
) {
    let _ = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let mut bufs = ConnBufs::new();
            loop {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                let busy = busy_workers.fetch_add(1, Ordering::AcqRel) + 1;
                let total = total_workers.load(Ordering::Acquire);
                if busy >= total && total < MAX_WORKERS {
                    let add = (MAX_WORKERS - total).min(4);
                    if total_workers
                        .compare_exchange(total, total + add, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        for _ in 0..add {
                            spawn_worker(
                                Arc::clone(&listener),
                                Arc::clone(&store),
                                Arc::clone(&busy_workers),
                                Arc::clone(&total_workers),
                            );
                        }
                    }
                }

                handle_connection(&mut stream, &mut bufs, &store, &busy_workers);
                busy_workers.fetch_sub(1, Ordering::AcqRel);
            }
        });
}

fn handle_connection(
    stream: &mut TcpStream,
    bufs: &mut ConnBufs,
    store: &Store,
    busy_workers: &AtomicUsize,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    bufs.read_pos = 0;
    bufs.read_len = 0;

    loop {
        let req = match read_http_request(stream, bufs) {
            Ok(Some(r)) => r,
            Ok(None) | Err(_) => break,
        };

        let keep_alive = req.keep_alive;
        let next_pos = req.next_pos;
        let mut force_close = false;

        let res = {
            let buf = bufs.read_buf.as_slice();
            let write_buf = &mut bufs.write_buf;
            let method = req.method.slice(buf);
            let path = req.path.slice(buf);
            let query = req.query.slice(buf);
            let auth = req.authorization.map(|s| s.slice(buf));
            let host = req.host.map(|s| s.slice(buf));
            let git_proto = req.git_protocol.map(|s| s.slice(buf));
            let body = req.body(buf);

            if method == b"GET" && path == b"/healthz" {
                write_preframed(stream, HEALTHZ_RESP)
            } else if path.starts_with(b"/api/v3") {
                rest::handle_rest(stream, write_buf, store, method, path, query, auth, host, body)
            } else if path == b"/api/graphql" {
                graphql::handle_graphql(stream, write_buf, store, auth, body)
            } else if path == b"/mcp" {
                mcp::handle_mcp(stream, write_buf, store, method, auth, body)
            } else if path.contains(&b'.') && path.windows(5).any(|w| w == b".git/") {
                let busy = busy_workers.load(Ordering::Relaxed);
                let is_git_upload = path.ends_with(b"/git-upload-pack")
                    || (path.ends_with(b"/info/refs")
                        && !query.windows(16).any(|w| w == b"git-receive-pack"));
                force_close = is_git_upload && busy >= 24;
                git::handle_git(
                    stream,
                    write_buf,
                    store,
                    method,
                    path,
                    query,
                    auth,
                    git_proto,
                    body,
                    force_close,
                )
            } else {
                write_preframed(stream, NOT_FOUND_RESP)
            }
        };

        bufs.read_pos = next_pos;
        bufs.reset_if_empty();

        if res.is_err() || !keep_alive || force_close {
            break;
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
