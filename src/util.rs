use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

pub type Oid = [u8; 20];
pub const ZERO_OID: Oid = [0u8; 20];

#[derive(Default)]
pub struct OidHasher(u64);

impl Hasher for OidHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() >= 8 {
            self.0 = u64::from_ne_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
        } else {
            let mut v = 0u64;
            for &b in bytes {
                v = (v << 8) | (b as u64);
            }
            self.0 ^= v;
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

pub type OidMap<V> = HashMap<Oid, V, BuildHasherDefault<OidHasher>>;
pub type OidSet = HashSet<Oid, BuildHasherDefault<OidHasher>>;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[inline]
pub fn oid_to_hex(oid: &Oid) -> [u8; 40] {
    let mut out = [0u8; 40];
    for (i, &b) in oid.iter().enumerate() {
        out[i * 2] = HEX_LOWER[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_LOWER[(b & 0x0f) as usize];
    }
    out
}

#[inline]
pub fn oid_hex_string(oid: &Oid) -> String {
    let hex = oid_to_hex(oid);
    // Safety: HEX_LOWER only contains ASCII bytes.
    unsafe { String::from_utf8_unchecked(hex.to_vec()) }
}

#[inline]
pub fn write_oid_hex(oid: &Oid, out: &mut Vec<u8>) {
    let hex = oid_to_hex(oid);
    out.extend_from_slice(&hex);
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[inline]
pub fn hex_to_oid(bytes: &[u8]) -> Option<Oid> {
    if bytes.len() != 40 {
        return None;
    }
    let mut oid = [0u8; 20];
    for i in 0..20 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        oid[i] = (hi << 4) | lo;
    }
    Some(oid)
}

const B64_ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64_ENC[((n >> 18) & 63) as usize] as char);
        out.push(B64_ENC[((n >> 12) & 63) as usize] as char);
        out.push(B64_ENC[((n >> 6) & 63) as usize] as char);
        out.push(B64_ENC[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(B64_ENC[((n >> 18) & 63) as usize] as char);
        out.push(B64_ENC[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64_ENC[((n >> 18) & 63) as usize] as char);
        out.push(B64_ENC[((n >> 12) & 63) as usize] as char);
        out.push(B64_ENC[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

pub fn b64_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut clean = Vec::with_capacity(input.len());
    for &b in input {
        if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            clean.push(b);
        }
    }
    if clean.len() % 4 != 0 {
        return None;
    }
    if clean.is_empty() {
        return Some(Vec::new());
    }
    let dec = |b: u8| -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    let chunks = clean.len() / 4;
    for c in 0..chunks {
        let b0 = clean[c * 4];
        let b1 = clean[c * 4 + 1];
        let b2 = clean[c * 4 + 2];
        let b3 = clean[c * 4 + 3];
        let v0 = dec(b0)?;
        let v1 = dec(b1)?;
        if b2 == b'=' {
            if b3 != b'=' || c + 1 != chunks {
                return None;
            }
            out.push((v0 << 2) | (v1 >> 4));
        } else if b3 == b'=' {
            if c + 1 != chunks {
                return None;
            }
            let v2 = dec(b2)?;
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
        } else {
            let v2 = dec(b2)?;
            let v3 = dec(b3)?;
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
            out.push((v2 << 6) | v3);
        }
    }
    Some(out)
}

pub fn percent_decode_path(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(h), Some(l)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn percent_decode_query(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(h), Some(l)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            out.push(input[i]);
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_query_param(query: &[u8], key: &[u8]) -> Option<String> {
    if query.is_empty() {
        return None;
    }
    for pair in query.split(|&b| b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.iter().position(|&b| b == b'=') {
            Some(pos) => (&pair[..pos], &pair[pos + 1..]),
            None => (pair, &[][..]),
        };
        if k == key {
            return Some(percent_decode_query(v));
        }
    }
    None
}

#[inline]
pub fn write_json_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut last = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x08 => b"\\b",
            0x0c => b"\\f",
            0x00..=0x1f => {
                if i > last {
                    out.extend_from_slice(&bytes[last..i]);
                }
                out.extend_from_slice(b"\\u00");
                out.push(HEX_LOWER[(b >> 4) as usize]);
                out.push(HEX_LOWER[(b & 0x0f) as usize]);
                last = i + 1;
                continue;
            }
            _ => continue,
        };
        if i > last {
            out.extend_from_slice(&bytes[last..i]);
        }
        out.extend_from_slice(esc);
        last = i + 1;
    }
    if last < bytes.len() {
        out.extend_from_slice(&bytes[last..]);
    }
    out.push(b'"');
}

#[inline]
pub fn write_u64_ascii(out: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos = 20;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&buf[pos..]);
}

#[inline]
pub fn write_u32_ascii(out: &mut Vec<u8>, n: u32) {
    write_u64_ascii(out, n as u64);
}

#[inline]
pub fn write_pkt_len(out: &mut Vec<u8>, total_len: usize) {
    let len = total_len as u16;
    out.push(HEX_LOWER[((len >> 12) & 0x0f) as usize]);
    out.push(HEX_LOWER[((len >> 8) & 0x0f) as usize]);
    out.push(HEX_LOWER[((len >> 4) & 0x0f) as usize]);
    out.push(HEX_LOWER[(len & 0x0f) as usize]);
}

pub fn write_pkt_line(out: &mut Vec<u8>, payload: &[u8]) {
    write_pkt_len(out, payload.len() + 4);
    out.extend_from_slice(payload);
}

pub struct FastIssueInput<'a> {
    pub title: Cow<'a, str>,
    pub body: Cow<'a, str>,
    pub labels: Option<Vec<String>>,
}

#[inline]
fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

#[inline]
fn scan_plain_json_str(b: &[u8], i: usize) -> Option<(&str, usize)> {
    if i >= b.len() || b[i] != b'"' {
        return None;
    }
    let mut j = i + 1;
    while j < b.len() {
        let c = b[j];
        if c == b'"' {
            let s = std::str::from_utf8(&b[i + 1..j]).ok()?;
            return Some((s, j + 1));
        }
        if c == b'\\' || c < 0x20 {
            return None;
        }
        j += 1;
    }
    None
}

pub fn parse_fast_issue_body(raw: &[u8]) -> Result<FastIssueInput<'_>, ()> {
    if let Some(fast) = try_parse_fast_issue(raw) {
        return Ok(fast);
    }
    let val: serde_json::Value = serde_json::from_slice(raw).map_err(|_| ())?;
    let obj = val.as_object().ok_or(())?;
    let title = match obj.get("title") {
        Some(v) => v.as_str().ok_or(())?.to_owned(),
        None => String::new(),
    };
    let body = match obj.get("body") {
        Some(serde_json::Value::Null) | None => String::new(),
        Some(v) => v.as_str().ok_or(())?.to_owned(),
    };
    let labels = match obj.get("labels") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                if let Some(s) = item.as_str() {
                    out.push(s.to_owned());
                } else if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                    out.push(name.to_owned());
                } else {
                    return Err(());
                }
            }
            Some(out)
        }
        _ => return Err(()),
    };
    Ok(FastIssueInput {
        title: Cow::Owned(title),
        body: Cow::Owned(body),
        labels,
    })
}

#[inline]
fn try_parse_fast_issue(b: &[u8]) -> Option<FastIssueInput<'_>> {
    let mut i = skip_ws(b, 0);
    if i >= b.len() || b[i] != b'{' {
        return None;
    }
    i = skip_ws(b, i + 1);
    if i < b.len() && b[i] == b'}' {
        i = skip_ws(b, i + 1);
        if i == b.len() {
            return Some(FastIssueInput {
                title: Cow::Borrowed(""),
                body: Cow::Borrowed(""),
                labels: None,
            });
        }
        return None;
    }

    let mut title: Option<&str> = None;
    let mut body: Option<&str> = None;
    let mut labels: Option<Vec<String>> = None;

    loop {
        let (key, next_i) = scan_plain_json_str(b, i)?;
        i = skip_ws(b, next_i);
        if i >= b.len() || b[i] != b':' {
            return None;
        }
        i = skip_ws(b, i + 1);
        match key {
            "title" => {
                let (val, ni) = scan_plain_json_str(b, i)?;
                title = Some(val);
                i = ni;
            }
            "body" => {
                if b[i..].starts_with(b"null") {
                    body = Some("");
                    i += 4;
                } else {
                    let (val, ni) = scan_plain_json_str(b, i)?;
                    body = Some(val);
                    i = ni;
                }
            }
            "labels" => {
                if i >= b.len() || b[i] != b'[' {
                    return None;
                }
                i = skip_ws(b, i + 1);
                let mut list = Vec::new();
                if i < b.len() && b[i] == b']' {
                    i += 1;
                } else {
                    loop {
                        let (lbl, ni) = scan_plain_json_str(b, i)?;
                        list.push(lbl.to_owned());
                        i = skip_ws(b, ni);
                        if i >= b.len() {
                            return None;
                        }
                        if b[i] == b',' {
                            i = skip_ws(b, i + 1);
                        } else if b[i] == b']' {
                            i += 1;
                            break;
                        } else {
                            return None;
                        }
                    }
                }
                labels = Some(list);
            }
            _ => return None,
        }
        i = skip_ws(b, i);
        if i >= b.len() {
            return None;
        }
        if b[i] == b',' {
            i = skip_ws(b, i + 1);
        } else if b[i] == b'}' {
            i = skip_ws(b, i + 1);
            if i != b.len() {
                return None;
            }
            break;
        } else {
            return None;
        }
    }

    Some(FastIssueInput {
        title: Cow::Borrowed(title.unwrap_or("")),
        body: Cow::Borrowed(body.unwrap_or("")),
        labels,
    })
}
