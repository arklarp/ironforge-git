use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;

use flate2::write::ZlibEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};
use rustc_hash::FxHashMap;
use sha1::{Digest, Sha1};

use crate::http::{
    build_preframed_http, write_json_message, write_raw_resp, HttpResponse, NOT_FOUND_RESP,
    UNAUTH_RESP,
};
use crate::store::{parse_tag_target, parse_tree, ObjType, ReceiveRefsCache, Repo, Store};
use crate::util::{
    hex_to_oid, oid_to_hex, parse_query_param, percent_decode_path, write_oid_hex, write_pkt_len,
    write_pkt_line, Oid, OidMap, OidSet, ZERO_OID,
};

const GIT_V2_INFO_REFS_BODY: &[u8] = b"000eversion 2\n0013ls-refs=unborn\n0012fetch=shallow\n0000";
const _: () = assert!(GIT_V2_INFO_REFS_BODY.len() == 55);
const GIT_V2_INFO_REFS_RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nX-GitHub-Request-Id: 1\r\nContent-Length: 55\r\n\r\n000eversion 2\n0013ls-refs=unborn\n0012fetch=shallow\n0000";

const PKT_MAX_SIDEBAND_PAYLOAD: usize = 65515;

struct PackScratch {
    decomp: Decompress,
    buf: Vec<u8>,
}

thread_local! {
    static INFLATE_SCRATCH: RefCell<PackScratch> = RefCell::new(PackScratch {
        decomp: Decompress::new(true),
        buf: vec![0u8; 65536],
    });
}

pub fn handle_git(
    write_buf: &mut Vec<u8>,
    store: &Store,
    method: &[u8],
    path: &[u8],
    query: &[u8],
    auth: Option<&[u8]>,
    git_protocol: Option<&[u8]>,
    body: &[u8],
) -> HttpResponse {
    if !store.check_auth(auth) {
        return HttpResponse::Static(UNAUTH_RESP);
    }

    let path_str = std::str::from_utf8(path).unwrap_or("");
    let trimmed = path_str.strip_prefix('/').unwrap_or(path_str);
    let Some(slash1) = trimmed.find('/') else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let owner = percent_decode_path(trimmed[..slash1].as_bytes());
    let rest1 = &trimmed[slash1 + 1..];
    let Some(dot_git_pos) = rest1.find(".git/") else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let repo_name = percent_decode_path(rest1[..dot_git_pos].as_bytes());
    let endpoint = &rest1[dot_git_pos + 4..];

    let Some(repo_arc) = store.get_repo_arc(&owner, &repo_name) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };

    match (method, endpoint) {
        (b"GET", "/info/refs") => {
            let service_alloc;
            let service: Option<&str> = if query == b"service=git-upload-pack" {
                Some("git-upload-pack")
            } else if query == b"service=git-receive-pack" {
                Some("git-receive-pack")
            } else {
                service_alloc = parse_query_param(query, b"service");
                service_alloc.as_deref()
            };
            match service {
                Some("git-upload-pack") => {
                    let is_v2 = git_protocol
                        .map(|gp| gp.windows(9).any(|w| w == b"version=2"))
                        .unwrap_or(false);
                    if is_v2 {
                        return HttpResponse::Static(GIT_V2_INFO_REFS_RESP);
                    }
                    let pkt = {
                        let repo = repo_arc.read().unwrap();
                        build_v0_upload_refs(&repo)
                    };
                    write_raw_resp(
                        write_buf,
                        200,
                        b"application/x-git-upload-pack-advertisement",
                        b"",
                        &pkt,
                    )
                }
                Some("git-receive-pack") => {
                    {
                        let repo = repo_arc.read().unwrap();
                        if let Some(ref cached) = repo.cache_receive_refs {
                            write_buf.clear();
                            write_buf.extend_from_slice(&cached.bytes);
                            return HttpResponse::Owned;
                        }
                    }
                    let mut repo = repo_arc.write().unwrap();
                    if let Some(ref cached) = repo.cache_receive_refs {
                        write_buf.clear();
                        write_buf.extend_from_slice(&cached.bytes);
                        return HttpResponse::Owned;
                    }
                    let cached = build_receive_refs_cache(&repo);
                    write_buf.clear();
                    write_buf.extend_from_slice(&cached.bytes);
                    repo.cache_receive_refs = Some(cached);
                    HttpResponse::Owned
                }
                _ => HttpResponse::Static(NOT_FOUND_RESP),
            }
        }
        (b"POST", "/git-upload-pack") => {
            let is_v2 = git_protocol
                .map(|gp| gp.windows(9).any(|w| w == b"version=2"))
                .unwrap_or(false);
            if is_v2 {
                handle_upload_pack_v2(write_buf, &repo_arc, body)
            } else {
                handle_upload_pack_v0(write_buf, &repo_arc, body)
            }
        }
        (b"POST", "/git-receive-pack") => handle_receive_pack(write_buf, &repo_arc, body),
        _ => HttpResponse::Static(NOT_FOUND_RESP),
    }
}

fn build_v0_upload_refs(repo: &Repo) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    write_pkt_line(&mut out, b"# service=git-upload-pack\n");
    out.extend_from_slice(b"0000");

    let head_target = format!("refs/heads/{}", repo.default_branch);
    let caps = format!(
        "multi_ack_detailed side-band-64k thin-pack ofs-delta shallow symref=HEAD:{} agent=ironforge/1.0",
        head_target
    );

    if repo.refs.is_empty() {
        let mut line = Vec::with_capacity(64 + caps.len());
        write_oid_hex(&ZERO_OID, &mut line);
        line.extend_from_slice(b" capabilities^{}\0");
        line.extend_from_slice(caps.as_bytes());
        line.push(b'\n');
        write_pkt_line(&mut out, &line);
        out.extend_from_slice(b"0000");
        return out;
    }

    let mut first = true;
    if let Some(&head_oid) = repo.refs.get(&head_target) {
        let mut line = Vec::with_capacity(64 + caps.len());
        write_oid_hex(&head_oid, &mut line);
        line.extend_from_slice(b" HEAD\0");
        line.extend_from_slice(caps.as_bytes());
        line.push(b'\n');
        write_pkt_line(&mut out, &line);
        first = false;
    }

    for (name, &oid) in &repo.refs {
        let mut line = Vec::with_capacity(48 + name.len() + if first { caps.len() + 1 } else { 0 });
        write_oid_hex(&oid, &mut line);
        line.push(b' ');
        line.extend_from_slice(name.as_bytes());
        if first {
            line.push(0);
            line.extend_from_slice(caps.as_bytes());
            first = false;
        }
        line.push(b'\n');
        write_pkt_line(&mut out, &line);

        if let Some(obj) = repo.objects.get(&oid) {
            if obj.kind == ObjType::Tag {
                if let Some(peeled) = repo.peel_oid(oid) {
                    let mut p_line = Vec::with_capacity(48 + name.len());
                    write_oid_hex(&peeled, &mut p_line);
                    p_line.push(b' ');
                    p_line.extend_from_slice(name.as_bytes());
                    p_line.extend_from_slice(b"^{}\n");
                    write_pkt_line(&mut out, &p_line);
                }
            }
        }
    }
    out.extend_from_slice(b"0000");
    out
}

fn build_receive_refs_cache(repo: &Repo) -> ReceiveRefsCache {
    let mut body = Vec::with_capacity(256);
    write_pkt_line(&mut body, b"# service=git-receive-pack\n");
    body.extend_from_slice(b"0000");

    // Omit agent and report-status-v2 so client uses compact report-status
    const CAPS: &[u8] = b"report-status side-band-64k delete-refs ofs-delta";

    let mut single_ref_name = None;
    let mut oid_offset_in_body = 0;

    if repo.refs.is_empty() {
        let mut line = Vec::with_capacity(64 + CAPS.len());
        write_oid_hex(&ZERO_OID, &mut line);
        line.extend_from_slice(b" capabilities^{}\0");
        line.extend_from_slice(CAPS);
        line.push(b'\n');
        write_pkt_line(&mut body, &line);
    } else {
        let is_single = repo.refs.len() == 1;
        let mut first = true;
        for (name, &oid) in &repo.refs {
            let pkt_start = body.len();
            let mut line = Vec::with_capacity(48 + name.len() + if first { CAPS.len() + 1 } else { 0 });
            write_oid_hex(&oid, &mut line);
            line.push(b' ');
            line.extend_from_slice(name.as_bytes());
            if first {
                line.push(0);
                line.extend_from_slice(CAPS);
                first = false;
            }
            line.push(b'\n');
            write_pkt_line(&mut body, &line);
            if is_single {
                single_ref_name = Some(name.clone());
                oid_offset_in_body = pkt_start + 4;
            }
        }
    }
    body.extend_from_slice(b"0000");

    let frame = build_preframed_http(200, b"application/x-git-receive-pack-advertisement", &body);
    let hdr_len = frame.len() - body.len();
    ReceiveRefsCache {
        bytes: frame.to_vec(),
        single_ref_name,
        oid_offset: hdr_len + oid_offset_in_body,
    }
}

enum Pkt<'a> {
    Flush,
    Delim,
    ResponseEnd,
    Data(&'a [u8]),
}

fn parse_pkt_stream(mut data: &[u8]) -> Result<Vec<Pkt<'_>>, ()> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err(());
        }
        let hex_str = std::str::from_utf8(&data[..4]).map_err(|_| ())?;
        let len = usize::from_str_radix(hex_str, 16).map_err(|_| ())?;
        if len == 0 {
            out.push(Pkt::Flush);
            data = &data[4..];
        } else if len == 1 {
            out.push(Pkt::Delim);
            data = &data[4..];
        } else if len == 2 {
            out.push(Pkt::ResponseEnd);
            data = &data[4..];
        } else if len < 4 || len > data.len() {
            return Err(());
        } else {
            out.push(Pkt::Data(&data[4..len]));
            data = &data[len..];
        }
    }
    Ok(out)
}

fn handle_upload_pack_v2(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    mut data: &[u8],
) -> HttpResponse {
    let mut command: &[u8] = b"";
    let mut in_args = false;

    let mut peel = false;
    let mut symrefs = false;
    let mut unborn = false;
    let mut prefixes: Vec<&str> = Vec::new();

    let mut first_want: Option<Oid> = None;
    let mut extra_wants: Vec<Oid> = Vec::new();
    let mut haves: Vec<Oid> = Vec::new();
    let mut client_shallow: Vec<Oid> = Vec::new();
    let mut depth: Option<usize> = None;
    let mut done = false;

    while !data.is_empty() {
        if data.len() < 4 {
            return write_json_message(write_buf, 400, "Invalid pkt-line");
        }
        let Ok(hex_str) = std::str::from_utf8(&data[..4]) else {
            return write_json_message(write_buf, 400, "Invalid pkt-line");
        };
        let Ok(len) = usize::from_str_radix(hex_str, 16) else {
            return write_json_message(write_buf, 400, "Invalid pkt-line");
        };
        if len == 0 {
            break;
        } else if len == 1 {
            in_args = true;
            data = &data[4..];
            continue;
        } else if len == 2 {
            data = &data[4..];
            continue;
        } else if len < 4 || len > data.len() {
            return write_json_message(write_buf, 400, "Invalid pkt-line");
        }
        let d = &data[4..len];
        data = &data[len..];
        let d = d.strip_suffix(b"\n").unwrap_or(d);
        if !in_args {
            if let Some(cmd) = d.strip_prefix(b"command=") {
                command = cmd;
            }
        } else if command == b"ls-refs" {
            if d == b"peel" {
                peel = true;
            } else if d == b"symrefs" {
                symrefs = true;
            } else if d == b"unborn" {
                unborn = true;
            } else if let Some(p) = d.strip_prefix(b"ref-prefix ") {
                if let Ok(s) = std::str::from_utf8(p) {
                    prefixes.push(s);
                }
            }
        } else if command == b"fetch" {
            if let Some(h) = d.strip_prefix(b"want ") {
                if let Some(oid) = hex_to_oid(h) {
                    if first_want.is_none() {
                        first_want = Some(oid);
                    } else {
                        extra_wants.push(oid);
                    }
                }
            } else if let Some(h) = d.strip_prefix(b"have ") {
                if let Some(oid) = hex_to_oid(h) {
                    haves.push(oid);
                }
            } else if let Some(h) = d.strip_prefix(b"shallow ") {
                if let Some(oid) = hex_to_oid(h) {
                    client_shallow.push(oid);
                }
            } else if let Some(dp) = d.strip_prefix(b"deepen ") {
                if let Ok(s) = std::str::from_utf8(dp) {
                    depth = s.parse::<usize>().ok();
                }
            } else if d == b"done" {
                done = true;
            }
        }
    }

    match command {
        b"ls-refs" => {
            if prefixes.is_empty() && peel && symrefs {
                {
                    let repo = repo_arc.read().unwrap();
                    if let Some(ref cached) = repo.cache_ls_refs_full {
                        return HttpResponse::Shared(Arc::clone(cached));
                    }
                }
                let mut repo = repo_arc.write().unwrap();
                if let Some(ref cached) = repo.cache_ls_refs_full {
                    return HttpResponse::Shared(Arc::clone(cached));
                }
                let resp_body = build_ls_refs_body(&repo, true, true, true, &[]);
                let frame =
                    build_preframed_http(200, b"application/x-git-upload-pack-result", &resp_body);
                repo.cache_ls_refs_full = Some(Arc::clone(&frame));
                return HttpResponse::Shared(frame);
            }

            let resp = {
                let repo = repo_arc.read().unwrap();
                build_ls_refs_body(&repo, peel, symrefs, unborn, &prefixes)
            };
            write_raw_resp(
                write_buf,
                200,
                b"application/x-git-upload-pack-result",
                b"",
                &resp,
            )
        }
        b"fetch" => {
            // Fast path: depth=1 single want clone with no haves/shallow
            if let Some(tip) = first_want {
                if extra_wants.is_empty()
                    && haves.is_empty()
                    && client_shallow.is_empty()
                    && depth == Some(1)
                    && done
                {
                    {
                        let repo = repo_arc.read().unwrap();
                        if let Some((cached_tip, ref frame)) = repo.cache_fetch_depth1 {
                            if cached_tip == tip {
                                return HttpResponse::Shared(Arc::clone(frame));
                            }
                        }
                    }
                    let mut repo = repo_arc.write().unwrap();
                    if let Some((cached_tip, ref frame)) = repo.cache_fetch_depth1 {
                        if cached_tip == tip {
                            return HttpResponse::Shared(Arc::clone(frame));
                        }
                    }
                    if repo.objects.contains_key(&tip) {
                        let frame = build_depth1_cached_fetch(&repo, tip);
                        repo.cache_fetch_depth1 = Some((tip, Arc::clone(&frame)));
                        return HttpResponse::Shared(frame);
                    }
                }
            }

            let mut wants =
                Vec::with_capacity(if first_want.is_some() { 1 + extra_wants.len() } else { 0 });
            if let Some(w0) = first_want {
                wants.push(w0);
                wants.extend_from_slice(&extra_wants);
            }
            let resp = {
                let repo = repo_arc.read().unwrap();
                build_v2_fetch_body(&repo, &wants, &haves, &client_shallow, depth, done)
            };
            write_raw_resp(
                write_buf,
                200,
                b"application/x-git-upload-pack-result",
                b"",
                &resp,
            )
        }
        _ => write_json_message(write_buf, 400, "Unknown git command"),
    }
}

fn build_ls_refs_body(
    repo: &Repo,
    peel: bool,
    symrefs: bool,
    unborn: bool,
    prefixes: &[&str],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    let matches_prefix = |name: &str| -> bool {
        prefixes.is_empty() || prefixes.iter().any(|p| name.starts_with(p))
    };

    let head_target = format!("refs/heads/{}", repo.default_branch);
    if matches_prefix("HEAD") {
        if let Some(&head_oid) = repo.refs.get(&head_target) {
            let mut line = Vec::with_capacity(80);
            write_oid_hex(&head_oid, &mut line);
            line.extend_from_slice(b" HEAD");
            if symrefs {
                line.extend_from_slice(b" symref-target:");
                line.extend_from_slice(head_target.as_bytes());
            }
            line.push(b'\n');
            write_pkt_line(&mut out, &line);
        } else if unborn {
            let mut line = Vec::with_capacity(64);
            line.extend_from_slice(b"unborn HEAD");
            if symrefs {
                line.extend_from_slice(b" symref-target:");
                line.extend_from_slice(head_target.as_bytes());
            }
            line.push(b'\n');
            write_pkt_line(&mut out, &line);
        }
    }

    for (name, &oid) in &repo.refs {
        if !matches_prefix(name) {
            continue;
        }
        let mut line = Vec::with_capacity(96);
        write_oid_hex(&oid, &mut line);
        line.push(b' ');
        line.extend_from_slice(name.as_bytes());
        if peel {
            if let Some(obj) = repo.objects.get(&oid) {
                if obj.kind == ObjType::Tag {
                    if let Some(peeled) = repo.peel_oid(oid) {
                        line.extend_from_slice(b" peeled:");
                        write_oid_hex(&peeled, &mut line);
                    }
                }
            }
        }
        line.push(b'\n');
        write_pkt_line(&mut out, &line);
    }

    out.extend_from_slice(b"0000");
    out
}

fn build_depth1_cached_fetch(repo: &Repo, tip: Oid) -> Arc<[u8]> {
    let (to_send, new_shallow, _) = compute_fetch_objects(repo, &[tip], &[], &[], Some(1));
    let pack = build_pack(repo, &to_send, Compression::best());
    let mut body = Vec::with_capacity(128 + pack.len());
    if !new_shallow.is_empty() {
        write_pkt_line(&mut body, b"shallow-info\n");
        for oid in &new_shallow {
            let mut line = Vec::with_capacity(50);
            line.extend_from_slice(b"shallow ");
            write_oid_hex(oid, &mut line);
            line.push(b'\n');
            write_pkt_line(&mut body, &line);
        }
        body.extend_from_slice(b"0001");
    }
    write_pkt_line(&mut body, b"packfile\n");
    write_sideband_pack(&mut body, &pack);
    body.extend_from_slice(b"0000");
    build_preframed_http(200, b"application/x-git-upload-pack-result", &body)
}

fn build_v2_fetch_body(
    repo: &Repo,
    wants: &[Oid],
    haves: &[Oid],
    client_shallow: &[Oid],
    depth: Option<usize>,
    done: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    if !done {
        write_pkt_line(&mut out, b"acknowledgments\n");
        let mut any_ack = false;
        for h in haves {
            if repo.objects.contains_key(h) {
                let mut line = Vec::with_capacity(48);
                line.extend_from_slice(b"ACK ");
                write_oid_hex(h, &mut line);
                line.push(b'\n');
                write_pkt_line(&mut out, &line);
                any_ack = true;
            }
        }
        if !any_ack {
            write_pkt_line(&mut out, b"NAK\n");
        }
        out.extend_from_slice(b"0000");
        return out;
    }

    let (to_send, new_shallow, unshallow) =
        compute_fetch_objects(repo, wants, haves, client_shallow, depth);

    if !new_shallow.is_empty() || !unshallow.is_empty() {
        write_pkt_line(&mut out, b"shallow-info\n");
        for oid in &new_shallow {
            let mut line = Vec::with_capacity(50);
            line.extend_from_slice(b"shallow ");
            write_oid_hex(oid, &mut line);
            line.push(b'\n');
            write_pkt_line(&mut out, &line);
        }
        for oid in &unshallow {
            let mut line = Vec::with_capacity(52);
            line.extend_from_slice(b"unshallow ");
            write_oid_hex(oid, &mut line);
            line.push(b'\n');
            write_pkt_line(&mut out, &line);
        }
        out.extend_from_slice(b"0001");
    }

    let pack = build_pack(repo, &to_send, Compression::fast());
    write_pkt_line(&mut out, b"packfile\n");
    write_sideband_pack(&mut out, &pack);
    out.extend_from_slice(b"0000");
    out
}

fn handle_upload_pack_v0(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    body: &[u8],
) -> HttpResponse {
    let Ok(pkts) = parse_pkt_stream(body) else {
        return write_json_message(write_buf, 400, "Invalid pkt-line");
    };
    let mut wants = Vec::new();
    let mut haves = Vec::new();
    let mut client_shallow = Vec::new();
    let mut depth: Option<usize> = None;

    for p in pkts {
        if let Pkt::Data(d) = p {
            let line = d.strip_suffix(b"\n").unwrap_or(d);
            let line = match line.iter().position(|&b| b == 0) {
                Some(z) => &line[..z],
                None => line,
            };
            let main_part = if let Some(rest) = line.strip_prefix(b"want ") {
                let hex = &rest[..rest.len().min(40)];
                if let Some(oid) = hex_to_oid(hex) {
                    wants.push(oid);
                }
                continue;
            } else {
                line
            };
            if let Some(rest) = main_part.strip_prefix(b"have ") {
                if let Some(oid) = hex_to_oid(&rest[..rest.len().min(40)]) {
                    haves.push(oid);
                }
            } else if let Some(rest) = main_part.strip_prefix(b"shallow ") {
                if let Some(oid) = hex_to_oid(&rest[..rest.len().min(40)]) {
                    client_shallow.push(oid);
                }
            } else if let Some(d_bytes) = main_part.strip_prefix(b"deepen ") {
                if let Ok(s) = std::str::from_utf8(d_bytes) {
                    depth = s.parse::<usize>().ok();
                }
            }
        }
    }

    let out = {
        let repo = repo_arc.read().unwrap();
        let (to_send, new_shallow, unshallow) =
            compute_fetch_objects(&repo, &wants, &haves, &client_shallow, depth);
        let mut out = Vec::new();
        if !new_shallow.is_empty() || !unshallow.is_empty() {
            for oid in &new_shallow {
                let mut line = Vec::with_capacity(50);
                line.extend_from_slice(b"shallow ");
                write_oid_hex(oid, &mut line);
                line.push(b'\n');
                write_pkt_line(&mut out, &line);
            }
            for oid in &unshallow {
                let mut line = Vec::with_capacity(52);
                line.extend_from_slice(b"unshallow ");
                write_oid_hex(oid, &mut line);
                line.push(b'\n');
                write_pkt_line(&mut out, &line);
            }
            out.extend_from_slice(b"0000");
        }
        write_pkt_line(&mut out, b"NAK\n");
        let pack = build_pack(&repo, &to_send, Compression::fast());
        write_sideband_pack(&mut out, &pack);
        out.extend_from_slice(b"0000");
        out
    };

    write_raw_resp(
        write_buf,
        200,
        b"application/x-git-upload-pack-result",
        b"",
        &out,
    )
}

fn collect_tree_closure(repo: &Repo, tree_oid: Oid, seen: &mut OidSet, out: Option<&mut Vec<Oid>>) {
    let mut stack = vec![tree_oid];
    let mut out_opt = out;
    while let Some(tid) = stack.pop() {
        if !seen.insert(tid) {
            continue;
        }
        let Some(obj) = repo.objects.get(&tid) else {
            continue;
        };
        if let Some(ref mut list) = out_opt {
            list.push(tid);
        }
        if obj.kind != ObjType::Tree {
            continue;
        }
        for e in parse_tree(&obj.data) {
            if e.mode == "160000" {
                continue;
            }
            if e.mode == "40000" {
                stack.push(e.oid);
            } else if seen.insert(e.oid) {
                if repo.objects.contains_key(&e.oid) {
                    if let Some(ref mut list) = out_opt {
                        list.push(e.oid);
                    }
                }
            }
        }
    }
}

fn compute_fetch_objects(
    repo: &Repo,
    wants: &[Oid],
    haves: &[Oid],
    client_shallow: &[Oid],
    depth: Option<usize>,
) -> (Vec<Oid>, Vec<Oid>, Vec<Oid>) {
    let mut client_shallow_set = OidSet::default();
    for &s in client_shallow {
        client_shallow_set.insert(s);
    }

    // 1. Collect objects the client already has (stopping at client_shallow boundaries)
    let mut client_has_objects = OidSet::default();
    let mut have_commits = OidSet::default();
    let mut hq = VecDeque::new();
    for &h in haves {
        if repo.objects.contains_key(&h) && have_commits.insert(h) {
            hq.push_back(h);
        }
    }
    while let Some(oid) = hq.pop_front() {
        let Some(obj) = repo.objects.get(&oid) else {
            continue;
        };
        client_has_objects.insert(oid);
        if obj.kind == ObjType::Commit {
            if let Some(&tree_oid) = repo.commit_trees.get(&oid) {
                collect_tree_closure(repo, tree_oid, &mut client_has_objects, None);
            }
            if !client_shallow_set.contains(&oid) {
                if let Some(parents) = repo.commit_parents.get(&oid) {
                    for &p in parents.as_slice() {
                        if have_commits.insert(p) {
                            hq.push_back(p);
                        }
                    }
                }
            }
        } else if obj.kind == ObjType::Tag {
            if let Some(target) = parse_tag_target(&obj.data) {
                if have_commits.insert(target) {
                    hq.push_back(target);
                }
            }
        }
    }

    // 2. Walk wants
    let mut to_send = Vec::new();
    let mut send_seen = client_has_objects;
    let mut visited_commits = OidSet::default();
    let mut new_shallow = Vec::new();
    let mut new_shallow_set = OidSet::default();

    let mut wq: VecDeque<(Oid, usize)> = VecDeque::new();
    for &w in wants {
        if let Some(obj) = repo.objects.get(&w) {
            if obj.kind == ObjType::Tag {
                let mut cur = w;
                for _ in 0..16 {
                    if send_seen.insert(cur) {
                        to_send.push(cur);
                    }
                    let Some(tobj) = repo.objects.get(&cur) else {
                        break;
                    };
                    if tobj.kind != ObjType::Tag {
                        if tobj.kind == ObjType::Commit && visited_commits.insert(cur) {
                            wq.push_back((cur, 1));
                        }
                        break;
                    }
                    let Some(t) = parse_tag_target(&tobj.data) else {
                        break;
                    };
                    cur = t;
                }
            } else if obj.kind == ObjType::Commit {
                if visited_commits.insert(w) {
                    wq.push_back((w, 1));
                }
            } else if send_seen.insert(w) {
                to_send.push(w);
            }
        }
    }

    while let Some((cid, d)) = wq.pop_front() {
        if send_seen.insert(cid) {
            to_send.push(cid);
        }
        if let Some(&tree_oid) = repo.commit_trees.get(&cid) {
            collect_tree_closure(repo, tree_oid, &mut send_seen, Some(&mut to_send));
        }
        let parents = repo.commit_parents.get(&cid);
        let has_parents = parents.map(|p| !p.is_empty()).unwrap_or(false);
        if let Some(max_d) = depth {
            if d >= max_d {
                if has_parents && new_shallow_set.insert(cid) {
                    new_shallow.push(cid);
                }
                continue;
            }
        }
        if let Some(ps) = parents {
            for &p in ps.as_slice() {
                if depth.is_none() && have_commits.contains(&p) {
                    continue;
                }
                if visited_commits.insert(p) {
                    wq.push_back((p, d + 1));
                }
            }
        }
    }

    let mut unshallow = Vec::new();
    if depth.is_some() {
        for &cs in client_shallow {
            if visited_commits.contains(&cs) && !new_shallow_set.contains(&cs) {
                unshallow.push(cs);
            }
        }
    }

    (to_send, new_shallow, unshallow)
}

fn build_pack(repo: &Repo, oids: &[Oid], level: Compression) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + oids.len() * 128);
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(oids.len() as u32).to_be_bytes());

    for oid in oids {
        let Some(obj) = repo.objects.get(oid) else {
            continue;
        };
        let code = obj.kind as u8;
        let mut size = obj.data.len();
        let mut first = (code << 4) | ((size & 0x0f) as u8);
        size >>= 4;
        while size > 0 {
            out.push(first | 0x80);
            first = (size & 0x7f) as u8;
            size >>= 7;
        }
        out.push(first);

        let mut enc = ZlibEncoder::new(out, level);
        let _ = enc.write_all(&obj.data);
        out = enc.finish().unwrap();
    }

    let trailer: [u8; 20] = Sha1::digest(&out).into();
    out.extend_from_slice(&trailer);
    out
}

fn write_sideband_pack(out: &mut Vec<u8>, pack: &[u8]) {
    let mut off = 0;
    while off < pack.len() {
        let take = (pack.len() - off).min(PKT_MAX_SIDEBAND_PAYLOAD);
        write_pkt_len(out, 4 + 1 + take);
        out.push(1);
        out.extend_from_slice(&pack[off..off + take]);
        off += take;
    }
}

struct PushCmd<'a> {
    old_oid: Oid,
    new_oid: Oid,
    ref_name: &'a str,
}

fn handle_receive_pack(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    mut body: &[u8],
) -> HttpResponse {
    let mut cmds: Vec<PushCmd<'_>> = Vec::new();
    let mut sideband = false;
    let mut first = true;

    loop {
        if body.len() < 4 {
            return write_json_message(write_buf, 400, "Invalid pkt-line");
        }
        let Ok(hex_str) = std::str::from_utf8(&body[..4]) else {
            return write_json_message(write_buf, 400, "Invalid pkt-line");
        };
        let Ok(len) = usize::from_str_radix(hex_str, 16) else {
            return write_json_message(write_buf, 400, "Invalid pkt-line");
        };
        if len == 0 {
            body = &body[4..];
            break;
        }
        if len < 4 || len > body.len() {
            return write_json_message(write_buf, 400, "Truncated pkt-line");
        }
        let payload = &body[4..len];
        body = &body[len..];

        let (cmd_bytes, caps_bytes) = match payload.iter().position(|&b| b == 0) {
            Some(z) => (&payload[..z], Some(&payload[z + 1..])),
            None => (payload.strip_suffix(b"\n").unwrap_or(payload), None),
        };
        if first {
            if let Some(caps) = caps_bytes {
                sideband = caps.split(|&b| b == b' ' || b == b'\n').any(|c| c == b"side-band-64k");
            }
            first = false;
        }

        let Some(old_oid) = cmd_bytes.get(0..40).and_then(hex_to_oid) else {
            return write_json_message(write_buf, 400, "Bad old oid");
        };
        if cmd_bytes.get(40) != Some(&b' ') {
            return write_json_message(write_buf, 400, "Bad command");
        }
        let Some(new_oid) = cmd_bytes.get(41..81).and_then(hex_to_oid) else {
            return write_json_message(write_buf, 400, "Bad new oid");
        };
        if cmd_bytes.get(81) != Some(&b' ') {
            return write_json_message(write_buf, 400, "Bad command");
        }
        let Ok(ref_name) = std::str::from_utf8(&cmd_bytes[82..]) else {
            return write_json_message(write_buf, 400, "Bad ref name");
        };
        cmds.push(PushCmd {
            old_oid,
            new_oid,
            ref_name,
        });
    }

    let pack_bytes = body;
    let mut repo = repo_arc.write().unwrap();

    if !pack_bytes.is_empty() {
        if let Err(err) = unpack_into_repo(&mut repo, pack_bytes) {
            drop(repo);
            let mut report = Vec::with_capacity(256);
            let msg = format!("unpack {}\n", err);
            write_pkt_line(&mut report, msg.as_bytes());
            for c in &cmds {
                let line = format!("ng {} unpacker error\n", c.ref_name);
                write_pkt_line(&mut report, line.as_bytes());
            }
            report.extend_from_slice(b"0000");
            return send_push_report(write_buf, sideband, &report);
        }
    }

    let mut report = Vec::with_capacity(128 + cmds.len() * 64);
    write_pkt_line(&mut report, b"unpack ok\n");

    let mut any_changed = false;
    let mut single_patched_ref: Option<(&str, Oid)> = None;

    for c in &cmds {
        if c.new_oid == ZERO_OID {
            // Delete ref
            let cur = repo.refs.get(c.ref_name).copied().unwrap_or(ZERO_OID);
            if cur == ZERO_OID || (c.old_oid != ZERO_OID && cur != c.old_oid) {
                let line = format!("ng {} non-fast-forward\n", c.ref_name);
                write_pkt_line(&mut report, line.as_bytes());
            } else {
                repo.refs.remove(c.ref_name);
                any_changed = true;
                let line = format!("ok {}\n", c.ref_name);
                write_pkt_line(&mut report, line.as_bytes());
            }
        } else if c.old_oid == ZERO_OID {
            // Create ref
            if repo.refs.contains_key(c.ref_name) {
                let line = format!("ng {} non-fast-forward\n", c.ref_name);
                write_pkt_line(&mut report, line.as_bytes());
            } else if !repo.objects.contains_key(&c.new_oid) {
                let line = format!("ng {} missing object\n", c.ref_name);
                write_pkt_line(&mut report, line.as_bytes());
            } else {
                repo.refs.insert(c.ref_name.to_owned(), c.new_oid);
                any_changed = true;
                let line = format!("ok {}\n", c.ref_name);
                write_pkt_line(&mut report, line.as_bytes());
            }
        } else {
            // Update ref: must match current and be fast-forward
            let cur = repo.refs.get(c.ref_name).copied().unwrap_or(ZERO_OID);
            let ok_ff = cur == c.old_oid
                && cur != ZERO_OID
                && repo.objects.contains_key(&c.new_oid)
                && repo.is_ancestor(cur, c.new_oid);
            if ok_ff {
                repo.refs.insert(c.ref_name.to_owned(), c.new_oid);
                any_changed = true;
                if cmds.len() == 1 {
                    single_patched_ref = Some((c.ref_name, c.new_oid));
                }
                let line = format!("ok {}\n", c.ref_name);
                write_pkt_line(&mut report, line.as_bytes());
            } else {
                let line = format!("ng {} non-fast-forward\n", c.ref_name);
                write_pkt_line(&mut report, line.as_bytes());
            }
        }
    }

    if any_changed {
        repo.cache_ls_refs_full = None;
        repo.cache_fetch_depth1 = None;
        if let Some((ref_name, new_oid)) = single_patched_ref {
            let mut patched = false;
            if let Some(ref mut cache) = repo.cache_receive_refs {
                if cache.single_ref_name.as_deref() == Some(ref_name) {
                    let hex = oid_to_hex(&new_oid);
                    cache.bytes[cache.oid_offset..cache.oid_offset + 40]
                        .copy_from_slice(&hex);
                    patched = true;
                }
            }
            if !patched {
                repo.cache_receive_refs = None;
            }
        } else {
            repo.cache_receive_refs = None;
        }
    }
    drop(repo);

    report.extend_from_slice(b"0000");
    send_push_report(write_buf, sideband, &report)
}

#[inline]
fn send_push_report(
    write_buf: &mut Vec<u8>,
    sideband: bool,
    report: &[u8],
) -> HttpResponse {
    if sideband {
        let mut framed = Vec::with_capacity(report.len() + 12);
        write_pkt_len(&mut framed, 4 + 1 + report.len());
        framed.push(1);
        framed.extend_from_slice(report);
        framed.extend_from_slice(b"0000");
        write_raw_resp(
            write_buf,
            200,
            b"application/x-git-receive-pack-result",
            b"",
            &framed,
        )
    } else {
        write_raw_resp(
            write_buf,
            200,
            b"application/x-git-receive-pack-result",
            b"",
            report,
        )
    }
}

struct UnpackedEntry {
    type_code: u8,
    base_offset: usize,
    base_oid: Oid,
    data: Vec<u8>,
    resolved: Option<(ObjType, Vec<u8>, Oid)>,
}

fn unpack_into_repo(repo: &mut Repo, pack: &[u8]) -> Result<(), &'static str> {
    if pack.len() < 32 || &pack[0..4] != b"PACK" {
        return Err("bad pack header");
    }
    let version = u32::from_be_bytes([pack[4], pack[5], pack[6], pack[7]]);
    if version != 2 && version != 3 {
        return Err("unsupported pack version");
    }
    let count = u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]]) as usize;
    let trailer_start = pack.len() - 20;
    let computed: [u8; 20] = Sha1::digest(&pack[..trailer_start]).into();
    if computed != pack[trailer_start..] {
        return Err("checksum mismatch");
    }

    let mut entries: Vec<UnpackedEntry> = Vec::with_capacity(count);
    let mut by_offset: FxHashMap<usize, usize> = FxHashMap::default();
    let mut pos = 12usize;

    for idx in 0..count {
        let entry_offset = pos;
        if pos >= trailer_start {
            return Err("truncated pack entry");
        }
        let first = pack[pos];
        pos += 1;
        let type_code = (first >> 4) & 0x07;
        let mut expected_size: usize = (first & 0x0f) as usize;
        let mut shift = 4usize;
        let mut b = first;
        while (b & 0x80) != 0 {
            if pos >= trailer_start || shift > 56 {
                return Err("bad varint");
            }
            b = pack[pos];
            pos += 1;
            expected_size += ((b & 0x7f) as usize) << shift;
            shift += 7;
        }

        let mut base_offset = 0usize;
        let mut base_oid = ZERO_OID;

        if type_code == 6 {
            if pos >= trailer_start {
                return Err("truncated ofs-delta");
            }
            let mut db = pack[pos];
            pos += 1;
            let mut val = (db & 0x7f) as usize;
            while (db & 0x80) != 0 {
                if pos >= trailer_start {
                    return Err("truncated ofs-delta");
                }
                db = pack[pos];
                pos += 1;
                val = ((val + 1) << 7) + ((db & 0x7f) as usize);
            }
            if val == 0 || val > entry_offset {
                return Err("invalid ofs-delta");
            }
            base_offset = entry_offset - val;
        } else if type_code == 7 {
            if pos + 20 > trailer_start {
                return Err("truncated ref-delta");
            }
            base_oid.copy_from_slice(&pack[pos..pos + 20]);
            pos += 20;
        } else if ObjType::from_code(type_code).is_none() {
            return Err("bad object type");
        }

        let (data, next_pos) = inflate_pack_entry(&pack[pos..trailer_start], expected_size)?;
        pos += next_pos;
        by_offset.insert(entry_offset, idx);
        entries.push(UnpackedEntry {
            type_code,
            base_offset,
            base_oid,
            data,
            resolved: None,
        });
    }

    if pos != trailer_start {
        return Err("trailing bytes in pack");
    }

    let mut resolved_by_oid: OidMap<usize> = OidMap::default();
    for idx in 0..entries.len() {
        resolve_pack_entry(idx, &mut entries, &by_offset, &mut resolved_by_oid, repo)?;
    }

    for entry in entries {
        if let Some((kind, data, oid)) = entry.resolved {
            if !repo.objects.contains_key(&oid) {
                repo.insert_known_object(oid, kind, data);
            }
        }
    }
    Ok(())
}

fn inflate_pack_entry(input: &[u8], expected_size: usize) -> Result<(Vec<u8>, usize), &'static str> {
    INFLATE_SCRATCH.with(|cell| {
        let mut s = cell.borrow_mut();
        s.decomp.reset(true);
        if s.buf.len() < expected_size.max(4096) {
            s.buf.resize(expected_size.max(4096), 0);
        }
        let mut in_off = 0usize;
        let mut out_off = 0usize;
        loop {
            if out_off >= s.buf.len() {
                let new_len = s.buf.len() * 2;
                s.buf.resize(new_len, 0);
            }
            let before_in = s.decomp.total_in() as usize;
            let before_out = s.decomp.total_out() as usize;
            let res = {
                let PackScratch { decomp, buf } = &mut *s;
                decomp.decompress(&input[in_off..], &mut buf[out_off..], FlushDecompress::None)
            };
            let consumed = (s.decomp.total_in() as usize) - before_in;
            let produced = (s.decomp.total_out() as usize) - before_out;
            in_off += consumed;
            out_off += produced;
            match res {
                Ok(Status::StreamEnd) => {
                    if out_off != expected_size {
                        return Err("size mismatch");
                    }
                    return Ok((s.buf[..out_off].to_vec(), in_off));
                }
                Ok(Status::Ok) | Ok(Status::BufError) => {
                    if consumed == 0 && produced == 0 && in_off >= input.len() {
                        return Err("truncated zlib stream");
                    }
                }
                Err(_) => return Err("zlib error"),
            }
        }
    })
}

fn resolve_pack_entry(
    idx: usize,
    entries: &mut [UnpackedEntry],
    by_offset: &FxHashMap<usize, usize>,
    resolved_by_oid: &mut OidMap<usize>,
    repo: &Repo,
) -> Result<(), &'static str> {
    if entries[idx].resolved.is_some() {
        return Ok(());
    }
    let tc = entries[idx].type_code;
    if let Some(kind) = ObjType::from_code(tc) {
        let oid = crate::store::hash_object(kind, &entries[idx].data);
        let data = std::mem::take(&mut entries[idx].data);
        entries[idx].resolved = Some((kind, data, oid));
        resolved_by_oid.insert(oid, idx);
        return Ok(());
    }
    if tc == 6 {
        let base_off = entries[idx].base_offset;
        let Some(&base_idx) = by_offset.get(&base_off) else {
            return Err("missing ofs-delta base");
        };
        if base_idx == idx {
            return Err("delta cycle");
        }
        resolve_pack_entry(base_idx, entries, by_offset, resolved_by_oid, repo)?;
        let (base_kind, target_bytes) = {
            let (bk, bd, _) = entries[base_idx].resolved.as_ref().unwrap();
            (*bk, apply_delta(bd, &entries[idx].data)?)
        };
        let oid = crate::store::hash_object(base_kind, &target_bytes);
        entries[idx].data = Vec::new();
        entries[idx].resolved = Some((base_kind, target_bytes, oid));
        resolved_by_oid.insert(oid, idx);
        return Ok(());
    }
    if tc == 7 {
        let base_oid = entries[idx].base_oid;
        if let Some(&base_idx) = resolved_by_oid.get(&base_oid) {
            if base_idx == idx {
                return Err("delta cycle");
            }
            resolve_pack_entry(base_idx, entries, by_offset, resolved_by_oid, repo)?;
            let (base_kind, target_bytes) = {
                let (bk, bd, _) = entries[base_idx].resolved.as_ref().unwrap();
                (*bk, apply_delta(bd, &entries[idx].data)?)
            };
            let oid = crate::store::hash_object(base_kind, &target_bytes);
            entries[idx].data = Vec::new();
            entries[idx].resolved = Some((base_kind, target_bytes, oid));
            resolved_by_oid.insert(oid, idx);
            return Ok(());
        }
        if let Some(ext) = repo.objects.get(&base_oid) {
            let target_bytes = apply_delta(&ext.data, &entries[idx].data)?;
            let oid = crate::store::hash_object(ext.kind, &target_bytes);
            entries[idx].data = Vec::new();
            entries[idx].resolved = Some((ext.kind, target_bytes, oid));
            resolved_by_oid.insert(oid, idx);
            return Ok(());
        }
        return Err("missing ref-delta base");
    }
    Err("unknown type")
}

fn read_delta_varint(d: &[u8], pos: &mut usize) -> Result<usize, &'static str> {
    let mut val = 0usize;
    let mut shift = 0usize;
    loop {
        if *pos >= d.len() || shift > 56 {
            return Err("truncated delta varint");
        }
        let b = d[*pos];
        *pos += 1;
        val += ((b & 0x7f) as usize) << shift;
        if (b & 0x80) == 0 {
            return Ok(val);
        }
        shift += 7;
    }
}

fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut pos = 0usize;
    let src_size = read_delta_varint(delta, &mut pos)?;
    let dst_size = read_delta_varint(delta, &mut pos)?;
    if src_size != base.len() {
        return Err("delta base size mismatch");
    }
    let mut out = Vec::with_capacity(dst_size);
    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;
        if (op & 0x80) != 0 {
            let mut copy_off = 0usize;
            let mut copy_len = 0usize;
            for bit in 0..4 {
                if (op & (1 << bit)) != 0 {
                    if pos >= delta.len() {
                        return Err("truncated delta copy");
                    }
                    copy_off |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if (op & (1 << (bit + 4))) != 0 {
                    if pos >= delta.len() {
                        return Err("truncated delta copy");
                    }
                    copy_len |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            if copy_len == 0 {
                copy_len = 0x10000;
            }
            if copy_off + copy_len > base.len() || out.len() + copy_len > dst_size {
                return Err("delta copy out of bounds");
            }
            out.extend_from_slice(&base[copy_off..copy_off + copy_len]);
        } else if op != 0 {
            let lit = op as usize;
            if pos + lit > delta.len() || out.len() + lit > dst_size {
                return Err("delta insert out of bounds");
            }
            out.extend_from_slice(&delta[pos..pos + lit]);
            pos += lit;
        } else {
            return Err("invalid delta op 0");
        }
    }
    if out.len() != dst_size {
        return Err("delta output size mismatch");
    }
    Ok(out)
}
