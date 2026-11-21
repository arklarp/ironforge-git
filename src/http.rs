use std::borrow::Cow;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::util::write_u64_ascii;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const INITIAL_READ_CAP: usize = 65536;

pub const HEALTHZ_RESP: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
pub const UNAUTH_RESP: &[u8] =
    b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\nContent-Length: 26\r\n\r\n{\"message\":\"Unauthorized\"}";
pub const NOT_FOUND_RESP: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\nContent-Length: 23\r\n\r\n{\"message\":\"Not Found\"}";
pub const BAD_JSON_RESP: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\nContent-Length: 26\r\n\r\n{\"message\":\"Invalid JSON\"}";
pub const NO_CONTENT_RESP: &[u8] =
    b"HTTP/1.1 204 No Content\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\nContent-Length: 0\r\n\r\n";

pub struct ConnBufs {
    pub read_buf: Vec<u8>,
    pub read_pos: usize,
    pub read_len: usize,
    pub write_buf: Vec<u8>,
}

impl ConnBufs {
    pub fn new() -> Self {
        Self {
            read_buf: vec![0u8; INITIAL_READ_CAP],
            read_pos: 0,
            read_len: 0,
            write_buf: Vec::with_capacity(65536),
        }
    }

    #[inline]
    pub fn reset_if_empty(&mut self) {
        if self.read_pos >= self.read_len {
            self.read_pos = 0;
            self.read_len = 0;
            if self.read_buf.len() > 1024 * 1024 {
                self.read_buf.truncate(INITIAL_READ_CAP);
                self.read_buf.shrink_to(INITIAL_READ_CAP);
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    #[inline]
    pub fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.start..self.end]
    }
}

pub struct ParsedRequest {
    pub method: Span,
    pub path: Span,
    pub query: Span,
    pub authorization: Option<Span>,
    pub host: Option<Span>,
    pub git_protocol: Option<Span>,
    pub body_span: Span,
    pub chunked_body: Option<Vec<u8>>,
    pub next_pos: usize,
    pub keep_alive: bool,
}

impl ParsedRequest {
    #[inline]
    pub fn body<'a>(&'a self, buf: &'a [u8]) -> &'a [u8] {
        match &self.chunked_body {
            Some(v) => v.as_slice(),
            None => &buf[self.body_span.start..self.body_span.end],
        }
    }
}

#[inline]
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let mut i = 0;
    let limit = buf.len() - 3;
    while i < limit {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[inline]
fn trim_ascii(buf: &[u8], mut s: usize, mut e: usize) -> (usize, usize) {
    while s < e && matches!(buf[s], b' ' | b'\t') {
        s += 1;
    }
    while e > s && matches!(buf[e - 1], b' ' | b'\t') {
        e -= 1;
    }
    (s, e)
}

#[inline]
fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[inline]
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

#[inline]
fn parse_usize_ascii(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(val)
}

fn read_more(stream: &mut TcpStream, bufs: &mut ConnBufs) -> io::Result<usize> {
    if bufs.read_len == bufs.read_buf.len() {
        let new_len = bufs.read_buf.len().saturating_mul(2).max(bufs.read_len + 16384);
        bufs.read_buf.resize(new_len, 0);
    }
    match stream.read(&mut bufs.read_buf[bufs.read_len..]) {
        Ok(n) => {
            bufs.read_len += n;
            Ok(n)
        }
        Err(e) => Err(e),
    }
}

pub fn read_http_request(stream: &mut TcpStream, bufs: &mut ConnBufs) -> io::Result<Option<ParsedRequest>> {
    if bufs.read_pos > 0 {
        if bufs.read_pos >= bufs.read_len {
            bufs.read_pos = 0;
            bufs.read_len = 0;
        } else if bufs.read_pos > 4096 {
            let rem = bufs.read_len - bufs.read_pos;
            bufs.read_buf.copy_within(bufs.read_pos..bufs.read_len, 0);
            bufs.read_pos = 0;
            bufs.read_len = rem;
        }
    }

    let hdr_end = loop {
        let avail = &bufs.read_buf[bufs.read_pos..bufs.read_len];
        if let Some(rel_end) = find_header_end(avail) {
            break bufs.read_pos + rel_end;
        }
        if avail.len() >= MAX_HEADER_BYTES {
            return Err(io::Error::new(ErrorKind::InvalidData, "headers too large"));
        }
        match read_more(stream, bufs) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock
                        | ErrorKind::TimedOut
                        | ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                        | ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    };

    let base = bufs.read_pos;
    let body_start = hdr_end + 4;
    let hdr_bytes = &bufs.read_buf[base..hdr_end];

    let line_end = hdr_bytes
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(hdr_bytes.len());
    let req_line = &hdr_bytes[..line_end];

    let sp1 = req_line
        .iter()
        .position(|&b| b == b' ')
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "bad request line"))?;
    let rest_after_method = &req_line[sp1 + 1..];
    let sp2_rel = rest_after_method
        .iter()
        .position(|&b| b == b' ')
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "bad request target"))?;
    let target_start = base + sp1 + 1;
    let target_end = target_start + sp2_rel;
    let version = &rest_after_method[sp2_rel + 1..];
    let is_http_11 = version.starts_with(b"HTTP/1.1");

    let target_slice = &bufs.read_buf[target_start..target_end];
    let (path_span, query_span) = match target_slice.iter().position(|&b| b == b'?') {
        Some(q) => (
            Span {
                start: target_start,
                end: target_start + q,
            },
            Span {
                start: target_start + q + 1,
                end: target_end,
            },
        ),
        None => (
            Span {
                start: target_start,
                end: target_end,
            },
            Span { start: 0, end: 0 },
        ),
    };

    let mut authorization = None;
    let mut host = None;
    let mut git_protocol = None;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut expect_100 = false;
    let mut conn_close = false;
    let mut conn_keep = false;

    let mut cur = line_end + 2;
    while cur < hdr_bytes.len() {
        let next_crlf = hdr_bytes[cur..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(hdr_bytes.len() - cur);
        let line = &hdr_bytes[cur..cur + next_crlf];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = &line[..colon];
            let (vs, ve) = trim_ascii(bufs.read_buf.as_slice(), base + cur + colon + 1, base + cur + next_crlf);
            let val = &bufs.read_buf[vs..ve];
            if eq_ignore_ascii_case(name, b"content-length") {
                content_length = parse_usize_ascii(val);
            } else if eq_ignore_ascii_case(name, b"authorization") {
                authorization = Some(Span { start: vs, end: ve });
            } else if eq_ignore_ascii_case(name, b"host") {
                host = Some(Span { start: vs, end: ve });
            } else if eq_ignore_ascii_case(name, b"git-protocol") {
                git_protocol = Some(Span { start: vs, end: ve });
            } else if eq_ignore_ascii_case(name, b"transfer-encoding") {
                if contains_ignore_ascii_case(val, b"chunked") {
                    chunked = true;
                }
            } else if eq_ignore_ascii_case(name, b"connection") {
                if contains_ignore_ascii_case(val, b"close") {
                    conn_close = true;
                } else if contains_ignore_ascii_case(val, b"keep-alive") {
                    conn_keep = true;
                }
            } else if eq_ignore_ascii_case(name, b"expect") {
                if contains_ignore_ascii_case(val, b"100-continue") {
                    expect_100 = true;
                }
            }
        }
        cur += next_crlf + 2;
    }

    let keep_alive = if conn_close {
        false
    } else if conn_keep {
        true
    } else {
        is_http_11
    };

    if expect_100 && ((chunked) || content_length.unwrap_or(0) > 0) {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }

    if chunked {
        let (body, next_pos) = read_chunked_body(stream, bufs, body_start)?;
        return Ok(Some(ParsedRequest {
            method: Span {
                start: base,
                end: base + sp1,
            },
            path: path_span,
            query: query_span,
            authorization,
            host,
            git_protocol,
            body_span: Span { start: 0, end: 0 },
            chunked_body: Some(body),
            next_pos,
            keep_alive,
        }));
    }

    let cl = content_length.unwrap_or(0);
    if cl > MAX_BODY_BYTES {
        return Err(io::Error::new(ErrorKind::InvalidData, "body too large"));
    }
    let body_end = body_start + cl;
    if bufs.read_buf.len() < body_end {
        bufs.read_buf.resize(body_end, 0);
    }
    while bufs.read_len < body_end {
        match read_more(stream, bufs) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(Some(ParsedRequest {
        method: Span {
            start: base,
            end: base + sp1,
        },
        path: path_span,
        query: query_span,
        authorization,
        host,
        git_protocol,
        body_span: Span {
            start: body_start,
            end: body_end,
        },
        chunked_body: None,
        next_pos: body_end,
        keep_alive,
    }))
}

fn read_chunked_body(
    stream: &mut TcpStream,
    bufs: &mut ConnBufs,
    mut cursor: usize,
) -> io::Result<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    loop {
        let crlf_pos = loop {
            if let Some(pos) = bufs.read_buf[cursor..bufs.read_len]
                .windows(2)
                .position(|w| w == b"\r\n")
            {
                break cursor + pos;
            }
            match read_more(stream, bufs) {
                Ok(0) => return Err(io::Error::new(ErrorKind::UnexpectedEof, "eof in chunk header")),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        };
        let size_line = &bufs.read_buf[cursor..crlf_pos];
        let hex_part = match size_line.iter().position(|&b| b == b';') {
            Some(semi) => &size_line[..semi],
            None => size_line,
        };
        let hex_str = std::str::from_utf8(hex_part)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "bad chunk size"))?
            .trim();
        let chunk_len = usize::from_str_radix(hex_str, 16)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "bad chunk hex"))?;
        cursor = crlf_pos + 2;
        if chunk_len == 0 {
            loop {
                if bufs.read_len >= cursor + 2 && &bufs.read_buf[cursor..cursor + 2] == b"\r\n" {
                    return Ok((out, cursor + 2));
                }
                if let Some(pos) = bufs.read_buf[cursor..bufs.read_len]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                {
                    return Ok((out, cursor + pos + 4));
                }
                match read_more(stream, bufs) {
                    Ok(0) => return Ok((out, bufs.read_len)),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        if out.len() + chunk_len > MAX_BODY_BYTES {
            return Err(io::Error::new(ErrorKind::InvalidData, "chunked body too large"));
        }
        let need_end = cursor + chunk_len + 2;
        if bufs.read_buf.len() < need_end {
            bufs.read_buf.resize(need_end, 0);
        }
        while bufs.read_len < need_end {
            match read_more(stream, bufs) {
                Ok(0) => return Err(io::Error::new(ErrorKind::UnexpectedEof, "eof in chunk data")),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        out.extend_from_slice(&bufs.read_buf[cursor..cursor + chunk_len]);
        cursor = need_end;
    }
}

#[inline]
pub fn status_line(status: u16) -> &'static [u8] {
    match status {
        200 => b"HTTP/1.1 200 OK\r\n",
        201 => b"HTTP/1.1 201 Created\r\n",
        202 => b"HTTP/1.1 202 Accepted\r\n",
        204 => b"HTTP/1.1 204 No Content\r\n",
        400 => b"HTTP/1.1 400 Bad Request\r\n",
        401 => b"HTTP/1.1 401 Unauthorized\r\n",
        404 => b"HTTP/1.1 404 Not Found\r\n",
        405 => b"HTTP/1.1 405 Method Not Allowed\r\n",
        409 => b"HTTP/1.1 409 Conflict\r\n",
        422 => b"HTTP/1.1 422 Unprocessable Entity\r\n",
        _ => b"HTTP/1.1 500 Internal Server Error\r\n",
    }
}

pub fn build_preframed_http(status: u16, content_type: &[u8], body: &[u8]) -> Arc<[u8]> {
    let mut out = Vec::with_capacity(128 + body.len());
    out.extend_from_slice(status_line(status));
    out.extend_from_slice(b"Content-Type: ");
    out.extend_from_slice(content_type);
    out.extend_from_slice(b"\r\nX-GitHub-Request-Id: 1\r\nContent-Length: ");
    write_u64_ascii(&mut out, body.len() as u64);
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(body);
    Arc::from(out)
}

#[inline]
pub fn write_raw_resp(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    status: u16,
    content_type: &[u8],
    extra_headers: &[u8],
    body: &[u8],
) -> io::Result<()> {
    write_buf.clear();
    write_buf.extend_from_slice(status_line(status));
    write_buf.extend_from_slice(b"Content-Type: ");
    write_buf.extend_from_slice(content_type);
    write_buf.extend_from_slice(b"\r\nX-GitHub-Request-Id: 1\r\n");
    write_buf.extend_from_slice(extra_headers);
    write_buf.extend_from_slice(b"Content-Length: ");
    write_u64_ascii(write_buf, body.len() as u64);
    write_buf.extend_from_slice(b"\r\n\r\n");
    write_buf.extend_from_slice(body);
    stream.write_all(write_buf)
}

#[inline]
pub fn write_json_resp(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    status: u16,
    extra_headers: &[u8],
    body: &[u8],
) -> io::Result<()> {
    write_raw_resp(stream, write_buf, status, b"application/json", extra_headers, body)
}

#[inline]
pub fn write_json_message(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    status: u16,
    msg: &str,
) -> io::Result<()> {
    let mut body = Vec::with_capacity(msg.len() + 16);
    body.extend_from_slice(b"{\"message\":");
    crate::util::write_json_str(&mut body, msg);
    body.push(b'}');
    write_json_resp(stream, write_buf, status, b"", &body)
}

#[inline]
pub fn write_preframed(stream: &mut TcpStream, frame: &[u8]) -> io::Result<()> {
    stream.write_all(frame)
}

#[inline]
pub fn write_preframed_opt_close(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    frame: &[u8],
    force_close: bool,
) -> io::Result<()> {
    if !force_close {
        return stream.write_all(frame);
    }
    write_buf.clear();
    if let Some(pos) = frame.windows(2).position(|w| w == b"\r\n") {
        write_buf.extend_from_slice(&frame[..pos + 2]);
        write_buf.extend_from_slice(b"Connection: close\r\n");
        write_buf.extend_from_slice(&frame[pos + 2..]);
    } else {
        write_buf.extend_from_slice(frame);
    }
    stream.write_all(write_buf)
}

pub fn host_str<'a>(host_hdr: Option<&'a [u8]>) -> Cow<'a, str> {
    match host_hdr {
        Some(h) if !h.is_empty() => String::from_utf8_lossy(h),
        _ => Cow::Borrowed("127.0.0.1"),
    }
}
