use std::borrow::Cow;
use std::sync::Arc;

use crate::util::write_u64_ascii;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_BUF_BYTES: usize = MAX_BODY_BYTES + MAX_HEADER_BYTES + 4096;
pub const INITIAL_CONN_READ_CAP: usize = 16 * 1024;
pub const SHRINK_THRESHOLD: usize = 256 * 1024;

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
pub const CONTINUE_100_RESP: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

pub enum HttpResponse {
    Static(&'static [u8]),
    Shared(Arc<[u8]>),
    Owned,
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

pub struct HeaderMeta {
    pub method: Span,
    pub path: Span,
    pub query: Span,
    pub authorization: Option<Span>,
    pub host: Option<Span>,
    pub git_protocol: Option<Span>,
    pub body_start: usize,
    pub content_length: usize,
    pub chunked: bool,
    pub expect_100: bool,
    pub keep_alive: bool,
    pub sent_100: bool,
}

pub struct ReadState {
    pub buf: Vec<u8>,
    pub pos: usize,
    pub len: usize,
    pub header: Option<HeaderMeta>,
}

impl ReadState {
    #[inline]
    pub fn new(buf: Vec<u8>) -> Self {
        Self {
            buf,
            pos: 0,
            len: 0,
            header: None,
        }
    }

    #[inline]
    pub fn ensure_space(&mut self) -> bool {
        if self.len < self.buf.len() {
            return true;
        }
        if self.header.is_none() && self.pos > 0 {
            if self.pos >= self.len {
                self.pos = 0;
                self.len = 0;
                return true;
            }
            let rem = self.len - self.pos;
            self.buf.copy_within(self.pos..self.len, 0);
            self.pos = 0;
            self.len = rem;
            return true;
        }
        if self.len >= MAX_BUF_BYTES {
            return false;
        }
        let new_len = self
            .buf
            .len()
            .saturating_mul(2)
            .max(self.len + 16384)
            .min(MAX_BUF_BYTES);
        if new_len <= self.len {
            return false;
        }
        self.buf.resize(new_len, 0);
        true
    }

    #[inline]
    pub fn reset_for_new_conn(&mut self) {
        self.pos = 0;
        self.len = 0;
        self.header = None;
        if self.buf.len() > SHRINK_THRESHOLD {
            self.buf.truncate(INITIAL_CONN_READ_CAP);
            self.buf.shrink_to(INITIAL_CONN_READ_CAP);
        }
    }

    #[inline]
    pub fn advance(&mut self, next_pos: usize) {
        self.pos = next_pos;
        self.header = None;
        if self.pos >= self.len {
            self.pos = 0;
            self.len = 0;
            if self.buf.len() > SHRINK_THRESHOLD {
                self.buf.truncate(INITIAL_CONN_READ_CAP);
                self.buf.shrink_to(INITIAL_CONN_READ_CAP);
            }
        } else if self.pos > 4096 {
            let rem = self.len - self.pos;
            self.buf.copy_within(self.pos..self.len, 0);
            self.pos = 0;
            self.len = rem;
        }
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

pub enum ParseResult {
    Complete(ParsedRequest),
    NeedMore,
    Send100Continue,
    Error,
}

#[inline]
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let mut i = 1usize;
    let limit = buf.len() - 2;
    while i < limit {
        let rel = buf[i..limit].iter().position(|&b| b == b'\n')?;
        let pos = i + rel;
        if buf[pos - 1] == b'\r' && buf[pos + 1] == b'\r' && buf[pos + 2] == b'\n' {
            return Some(pos - 1);
        }
        i = pos + 1;
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
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
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

pub fn try_parse_request(rs: &mut ReadState) -> ParseResult {
    if rs.header.is_none() {
        if rs.pos >= rs.len {
            rs.pos = 0;
            rs.len = 0;
            return ParseResult::NeedMore;
        }
        if rs.pos > 4096 {
            let rem = rs.len - rs.pos;
            rs.buf.copy_within(rs.pos..rs.len, 0);
            rs.pos = 0;
            rs.len = rem;
        }

        let avail = &rs.buf[rs.pos..rs.len];
        let Some(rel_end) = find_header_end(avail) else {
            if avail.len() >= MAX_HEADER_BYTES {
                return ParseResult::Error;
            }
            return ParseResult::NeedMore;
        };
        if rel_end >= MAX_HEADER_BYTES {
            return ParseResult::Error;
        }

        let base = rs.pos;
        let hdr_end = base + rel_end;
        let body_start = hdr_end + 4;
        let hdr_bytes = &rs.buf[base..hdr_end];

        let (line_end, mut cur) = match hdr_bytes.iter().position(|&b| b == b'\n') {
            Some(lf) => {
                let end = if lf > 0 && hdr_bytes[lf - 1] == b'\r' {
                    lf - 1
                } else {
                    lf
                };
                (end, lf + 1)
            }
            None => (hdr_bytes.len(), hdr_bytes.len()),
        };
        let req_line = &hdr_bytes[..line_end];

        let Some(sp1) = req_line.iter().position(|&b| b == b' ') else {
            return ParseResult::Error;
        };
        let rest_after_method = &req_line[sp1 + 1..];
        let Some(sp2_rel) = rest_after_method.iter().position(|&b| b == b' ') else {
            return ParseResult::Error;
        };
        let target_start = base + sp1 + 1;
        let target_end = target_start + sp2_rel;
        let version = &rest_after_method[sp2_rel + 1..];
        let is_http_11 = version.starts_with(b"HTTP/1.1");

        let target_slice = &rs.buf[target_start..target_end];
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

        while cur < hdr_bytes.len() {
            let (line_rel_end, next_cur) = match hdr_bytes[cur..].iter().position(|&b| b == b'\n') {
                Some(lf) => {
                    let end = if lf > 0 && hdr_bytes[cur + lf - 1] == b'\r' {
                        lf - 1
                    } else {
                        lf
                    };
                    (end, cur + lf + 1)
                }
                None => (hdr_bytes.len() - cur, hdr_bytes.len()),
            };
            let line = &hdr_bytes[cur..cur + line_rel_end];
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                let name = &line[..colon];
                match name.len() {
                    4 if name.eq_ignore_ascii_case(b"host") => {
                        let (vs, ve) = trim_ascii(
                            rs.buf.as_slice(),
                            base + cur + colon + 1,
                            base + cur + line_rel_end,
                        );
                        host = Some(Span { start: vs, end: ve });
                    }
                    6 if name.eq_ignore_ascii_case(b"expect") => {
                        let (vs, ve) = trim_ascii(
                            rs.buf.as_slice(),
                            base + cur + colon + 1,
                            base + cur + line_rel_end,
                        );
                        if contains_ignore_ascii_case(&rs.buf[vs..ve], b"100-continue") {
                            expect_100 = true;
                        }
                    }
                    10 if name.eq_ignore_ascii_case(b"connection") => {
                        let (vs, ve) = trim_ascii(
                            rs.buf.as_slice(),
                            base + cur + colon + 1,
                            base + cur + line_rel_end,
                        );
                        let val = &rs.buf[vs..ve];
                        if contains_ignore_ascii_case(val, b"close") {
                            conn_close = true;
                        } else if contains_ignore_ascii_case(val, b"keep-alive") {
                            conn_keep = true;
                        }
                    }
                    12 if name.eq_ignore_ascii_case(b"git-protocol") => {
                        let (vs, ve) = trim_ascii(
                            rs.buf.as_slice(),
                            base + cur + colon + 1,
                            base + cur + line_rel_end,
                        );
                        git_protocol = Some(Span { start: vs, end: ve });
                    }
                    13 if name.eq_ignore_ascii_case(b"authorization") => {
                        let (vs, ve) = trim_ascii(
                            rs.buf.as_slice(),
                            base + cur + colon + 1,
                            base + cur + line_rel_end,
                        );
                        authorization = Some(Span { start: vs, end: ve });
                    }
                    14 if name.eq_ignore_ascii_case(b"content-length") => {
                        let (vs, ve) = trim_ascii(
                            rs.buf.as_slice(),
                            base + cur + colon + 1,
                            base + cur + line_rel_end,
                        );
                        content_length = parse_usize_ascii(&rs.buf[vs..ve]);
                    }
                    17 if name.eq_ignore_ascii_case(b"transfer-encoding") => {
                        let (vs, ve) = trim_ascii(
                            rs.buf.as_slice(),
                            base + cur + colon + 1,
                            base + cur + line_rel_end,
                        );
                        if contains_ignore_ascii_case(&rs.buf[vs..ve], b"chunked") {
                            chunked = true;
                        }
                    }
                    _ => {}
                }
            }
            cur = next_cur;
        }

        let keep_alive = if conn_close {
            false
        } else if conn_keep {
            true
        } else {
            is_http_11
        };

        let cl = content_length.unwrap_or(0);
        if !chunked && cl > MAX_BODY_BYTES {
            return ParseResult::Error;
        }

        rs.header = Some(HeaderMeta {
            method: Span {
                start: base,
                end: base + sp1,
            },
            path: path_span,
            query: query_span,
            authorization,
            host,
            git_protocol,
            body_start,
            content_length: cl,
            chunked,
            expect_100,
            keep_alive,
            sent_100: false,
        });
    }

    let meta = rs.header.as_mut().unwrap();
    if !meta.chunked {
        let body_end = meta.body_start + meta.content_length;
        if rs.len < body_end {
            if meta.expect_100 && !meta.sent_100 && meta.content_length > 0 {
                meta.sent_100 = true;
                return ParseResult::Send100Continue;
            }
            let target = body_end.min(rs.len + 2 * 1024 * 1024);
            if rs.buf.len() < target {
                rs.buf.resize(target, 0);
            }
            return ParseResult::NeedMore;
        }
        let meta = rs.header.take().unwrap();
        return ParseResult::Complete(ParsedRequest {
            method: meta.method,
            path: meta.path,
            query: meta.query,
            authorization: meta.authorization,
            host: meta.host,
            git_protocol: meta.git_protocol,
            body_span: Span {
                start: meta.body_start,
                end: body_end,
            },
            chunked_body: None,
            next_pos: body_end,
            keep_alive: meta.keep_alive,
        });
    }

    match try_parse_chunked(&rs.buf[meta.body_start..rs.len]) {
        ChunkedRes::Complete(body, consumed) => {
            let meta = rs.header.take().unwrap();
            ParseResult::Complete(ParsedRequest {
                method: meta.method,
                path: meta.path,
                query: meta.query,
                authorization: meta.authorization,
                host: meta.host,
                git_protocol: meta.git_protocol,
                body_span: Span { start: 0, end: 0 },
                chunked_body: Some(body),
                next_pos: meta.body_start + consumed,
                keep_alive: meta.keep_alive,
            })
        }
        ChunkedRes::NeedMore => {
            if meta.expect_100 && !meta.sent_100 {
                meta.sent_100 = true;
                return ParseResult::Send100Continue;
            }
            ParseResult::NeedMore
        }
        ChunkedRes::Error => ParseResult::Error,
    }
}

enum ChunkedRes {
    Complete(Vec<u8>, usize),
    NeedMore,
    Error,
}

fn try_parse_chunked(data: &[u8]) -> ChunkedRes {
    // Pass 1: validate framing & compute decoded length without allocating on partial data
    let mut total_len = 0usize;
    let mut cursor = 0usize;
    let consumed = loop {
        let Some(crlf_rel) = data[cursor..].windows(2).position(|w| w == b"\r\n") else {
            return ChunkedRes::NeedMore;
        };
        let crlf_pos = cursor + crlf_rel;
        let size_line = &data[cursor..crlf_pos];
        let hex_part = match size_line.iter().position(|&b| b == b';') {
            Some(semi) => &size_line[..semi],
            None => size_line,
        };
        let Ok(hex_str) = std::str::from_utf8(hex_part) else {
            return ChunkedRes::Error;
        };
        let Ok(chunk_len) = usize::from_str_radix(hex_str.trim(), 16) else {
            return ChunkedRes::Error;
        };
        cursor = crlf_pos + 2;
        if chunk_len == 0 {
            if data.len() >= cursor + 2 && &data[cursor..cursor + 2] == b"\r\n" {
                break cursor + 2;
            }
            if let Some(pos) = data[cursor..].windows(4).position(|w| w == b"\r\n\r\n") {
                break cursor + pos + 4;
            }
            return ChunkedRes::NeedMore;
        }
        if total_len.saturating_add(chunk_len) > MAX_BODY_BYTES {
            return ChunkedRes::Error;
        }
        let need_end = cursor + chunk_len + 2;
        if data.len() < need_end {
            return ChunkedRes::NeedMore;
        }
        if &data[cursor + chunk_len..need_end] != b"\r\n" {
            return ChunkedRes::Error;
        }
        total_len += chunk_len;
        cursor = need_end;
    };

    // Pass 2: assemble decoded body into a single exact-sized allocation
    let mut out = Vec::with_capacity(total_len);
    let mut c = 0usize;
    while c < consumed {
        let crlf_rel = data[c..].windows(2).position(|w| w == b"\r\n").unwrap();
        let size_line = &data[c..c + crlf_rel];
        let hex_part = match size_line.iter().position(|&b| b == b';') {
            Some(semi) => &size_line[..semi],
            None => size_line,
        };
        let hex_str = unsafe { std::str::from_utf8_unchecked(hex_part) };
        let chunk_len = usize::from_str_radix(hex_str.trim(), 16).unwrap();
        c += crlf_rel + 2;
        if chunk_len == 0 {
            break;
        }
        out.extend_from_slice(&data[c..c + chunk_len]);
        c += chunk_len + 2;
    }
    ChunkedRes::Complete(out, consumed)
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
    write_buf: &mut Vec<u8>,
    status: u16,
    content_type: &[u8],
    extra_headers: &[u8],
    body: &[u8],
) -> HttpResponse {
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
    HttpResponse::Owned
}

#[inline]
pub fn write_json_resp(
    write_buf: &mut Vec<u8>,
    status: u16,
    extra_headers: &[u8],
    body: &[u8],
) -> HttpResponse {
    write_raw_resp(write_buf, status, b"application/json", extra_headers, body)
}

#[inline]
pub fn write_json_message(write_buf: &mut Vec<u8>, status: u16, msg: &str) -> HttpResponse {
    let mut body = Vec::with_capacity(msg.len() + 16);
    body.extend_from_slice(b"{\"message\":");
    crate::util::write_json_str(&mut body, msg);
    body.push(b'}');
    write_json_resp(write_buf, status, b"", &body)
}

pub fn host_str<'a>(host_hdr: Option<&'a [u8]>) -> Cow<'a, str> {
    match host_hdr {
        Some(h) if !h.is_empty() => String::from_utf8_lossy(h),
        _ => Cow::Borrowed("127.0.0.1"),
    }
}
