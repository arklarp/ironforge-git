use std::io;
use std::net::TcpStream;
use std::sync::atomic::Ordering;

use serde_json::{json, Value};

use crate::http::{
    write_json_resp, write_preframed, write_raw_resp, NOT_FOUND_RESP, NO_CONTENT_RESP, UNAUTH_RESP,
};
use crate::store::{
    format_issue_json, format_pr_json, format_repo_json, Issue, IssueState, MergeError,
    PullRequest, Store,
};

const TOOLS_LIST_JSON: &[u8] = br#"{"tools":[{"name":"create_repo","description":"Create a new repository","inputSchema":{"type":"object","properties":{"name":{"type":"string"},"description":{"type":"string"},"private":{"type":"boolean"}},"required":["name"]}},{"name":"get_repo","description":"Get repository metadata","inputSchema":{"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"}},"required":["owner","repo"]}},{"name":"create_issue","description":"Create an issue in a repository","inputSchema":{"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"},"title":{"type":"string"},"body":{"type":"string"}},"required":["owner","repo","title"]}},{"name":"list_issues","description":"List issues in a repository","inputSchema":{"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"},"state":{"type":"string"}},"required":["owner","repo"]}},{"name":"create_pull_request","description":"Create a pull request","inputSchema":{"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"},"title":{"type":"string"},"body":{"type":"string"},"head":{"type":"string"},"base":{"type":"string"}},"required":["owner","repo","title","head","base"]}},{"name":"merge_pull_request","description":"Squash merge a pull request","inputSchema":{"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"},"pull_number":{"type":"integer"}},"required":["owner","repo","pull_number"]}}]}"#;

pub fn handle_mcp(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    store: &Store,
    method: &[u8],
    auth: Option<&[u8]>,
    body: &[u8],
) -> io::Result<()> {
    if !store.check_auth(auth) {
        return write_preframed(stream, UNAUTH_RESP);
    }
    if method == b"DELETE" {
        return write_preframed(stream, NO_CONTENT_RESP);
    }
    if method != b"POST" {
        return write_preframed(stream, NOT_FOUND_RESP);
    }

    let Ok(val) = serde_json::from_slice::<Value>(body) else {
        return write_json_resp(
            stream,
            write_buf,
            400,
            b"",
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#,
        );
    };

    let Some(obj) = val.as_object() else {
        return write_json_resp(
            stream,
            write_buf,
            400,
            b"",
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}"#,
        );
    };

    let id = obj.get("id").cloned();
    let rpc_method = obj.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = obj.get("params");

    if id.is_none() || rpc_method == "notifications/initialized" {
        return write_raw_resp(stream, write_buf, 202, b"application/json", b"", b"");
    }
    let id = id.unwrap();

    match rpc_method {
        "server/discover" => {
            let resp = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "supportedVersions": ["2026-07-28", "2025-11-25", "2025-06-18"],
                    "serverInfo": { "name": "ironforge", "version": "1.0.0" },
                    "capabilities": { "tools": {} },
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": { "name": "ironforge", "version": "1.0.0" }
                    }
                }
            });
            let bytes = serde_json::to_vec(&resp).unwrap();
            write_json_resp(stream, write_buf, 200, b"", &bytes)
        }
        "initialize" => {
            let req_ver = params
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str())
                .unwrap_or("2025-11-25");
            let resp = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": req_ver,
                    "serverInfo": { "name": "ironforge", "version": "1.0.0" },
                    "capabilities": { "tools": {} }
                }
            });
            let bytes = serde_json::to_vec(&resp).unwrap();
            write_json_resp(stream, write_buf, 200, b"", &bytes)
        }
        "tools/list" => {
            let mut resp = Vec::with_capacity(TOOLS_LIST_JSON.len() + 64);
            resp.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":");
            let id_bytes = serde_json::to_vec(&id).unwrap();
            resp.extend_from_slice(&id_bytes);
            resp.extend_from_slice(b",\"result\":");
            resp.extend_from_slice(TOOLS_LIST_JSON);
            resp.push(b'}');
            write_json_resp(stream, write_buf, 200, b"", &resp)
        }
        "tools/call" => handle_tool_call(stream, write_buf, store, id, params),
        _ => send_rpc_err(stream, write_buf, id, -32601, "Method not found"),
    }
}

fn send_rpc_err(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    id: Value,
    code: i64,
    msg: &str,
) -> io::Result<()> {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": msg }
    });
    let bytes = serde_json::to_vec(&resp).unwrap();
    write_json_resp(stream, write_buf, 200, b"", &bytes)
}

fn send_tool_ok(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    id: Value,
    payload: Value,
) -> io::Result<()> {
    let text = serde_json::to_string(&payload).unwrap();
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": text }],
            "structuredContent": payload,
            "isError": false
        }
    });
    let bytes = serde_json::to_vec(&resp).unwrap();
    write_json_resp(stream, write_buf, 200, b"", &bytes)
}

fn send_tool_err(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    id: Value,
    msg: &str,
) -> io::Result<()> {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": msg }],
            "isError": true
        }
    });
    let bytes = serde_json::to_vec(&resp).unwrap();
    write_json_resp(stream, write_buf, 200, b"", &bytes)
}

fn handle_tool_call(
    stream: &mut TcpStream,
    write_buf: &mut Vec<u8>,
    store: &Store,
    id: Value,
    params: Option<&Value>,
) -> io::Result<()> {
    let Some(p) = params.and_then(|v| v.as_object()) else {
        return send_rpc_err(stream, write_buf, id, -32602, "Missing params");
    };
    let raw_name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let tool_name = raw_name.rsplit("__").next().unwrap_or(raw_name);
    let args = p
        .get("arguments")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let req_str = |k: &str| -> Option<String> {
        args.get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    match tool_name {
        "create_repo" => {
            let Some(name) = req_str("name") else {
                return send_rpc_err(stream, write_buf, id, -32602, "Missing required argument: name");
            };
            let description = args
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let private = args
                .get("private")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let Ok((owner, repo_arc)) = store.create_repo(name, private, description) else {
                return send_tool_err(stream, write_buf, id, "Repository already exists");
            };
            let repo = repo_arc.read().unwrap();
            let mut raw = Vec::with_capacity(256);
            format_repo_json(&mut raw, &owner, &repo);
            let val: Value = serde_json::from_slice(&raw).unwrap();
            send_tool_ok(stream, write_buf, id, val)
        }
        "get_repo" => {
            let (Some(owner), Some(repo_name)) = (req_str("owner"), req_str("repo")) else {
                return send_rpc_err(stream, write_buf, id, -32602, "Missing owner or repo");
            };
            let Some((owner_login, repo_arc)) = store.get_repo(&owner, &repo_name) else {
                return send_tool_err(stream, write_buf, id, "Repository not found");
            };
            let repo = repo_arc.read().unwrap();
            let mut raw = Vec::with_capacity(256);
            format_repo_json(&mut raw, &owner_login, &repo);
            let val: Value = serde_json::from_slice(&raw).unwrap();
            send_tool_ok(stream, write_buf, id, val)
        }
        "create_issue" => {
            let (Some(owner), Some(repo_name), Some(title)) =
                (req_str("owner"), req_str("repo"), req_str("title"))
            else {
                return send_rpc_err(
                    stream,
                    write_buf,
                    id,
                    -32602,
                    "Missing required arguments: owner, repo, title",
                );
            };
            let body = args
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let Some((_owner, repo_arc)) = store.get_repo(&owner, &repo_name) else {
                return send_tool_err(stream, write_buf, id, "Repository not found");
            };
            let mut repo = repo_arc.write().unwrap();
            let issue_id = store.next_issue_id.fetch_add(1, Ordering::Relaxed);
            let number = (repo.issues.len() + 1) as u32;
            let issue = Issue {
                id: issue_id,
                global_id: format!("I_{:x}_{:x}", repo.id, number),
                number,
                title,
                body,
                state: IssueState::Open,
                labels: Vec::new(),
                comments: Vec::new(),
                seq: issue_id,
            };
            let mut raw = Vec::with_capacity(256);
            format_issue_json(&mut raw, &issue);
            repo.issues.push(issue);
            repo.issue_http_cache.push(None);
            let val: Value = serde_json::from_slice(&raw).unwrap();
            send_tool_ok(stream, write_buf, id, val)
        }
        "list_issues" => {
            let (Some(owner), Some(repo_name)) = (req_str("owner"), req_str("repo")) else {
                return send_rpc_err(stream, write_buf, id, -32602, "Missing owner or repo");
            };
            let Some((_owner, repo_arc)) = store.get_repo(&owner, &repo_name) else {
                return send_tool_err(stream, write_buf, id, "Repository not found");
            };
            let state_filter = args.get("state").and_then(|v| v.as_str()).unwrap_or("open");
            let want = match state_filter {
                "closed" => Some(IssueState::Closed),
                "all" => None,
                _ => Some(IssueState::Open),
            };
            let repo = repo_arc.read().unwrap();
            let mut raw = Vec::with_capacity(512);
            raw.push(b'[');
            let mut first = true;
            for iss in &repo.issues {
                if want.map(|s| iss.state == s).unwrap_or(true) {
                    if !first {
                        raw.push(b',');
                    }
                    first = false;
                    format_issue_json(&mut raw, iss);
                }
            }
            raw.push(b']');
            let val: Value = serde_json::from_slice(&raw).unwrap();
            send_tool_ok(stream, write_buf, id, val)
        }
        "create_pull_request" => {
            let (Some(owner), Some(repo_name), Some(title), Some(head), Some(base)) = (
                req_str("owner"),
                req_str("repo"),
                req_str("title"),
                req_str("head"),
                req_str("base"),
            ) else {
                return send_rpc_err(stream, write_buf, id, -32602, "Missing required arguments");
            };
            let body = args
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let Some((_owner, repo_arc)) = store.get_repo(&owner, &repo_name) else {
                return send_tool_err(stream, write_buf, id, "Repository not found");
            };
            let mut repo = repo_arc.write().unwrap();
            let Some(head_sha) = repo.refs.get(&format!("refs/heads/{}", head)).copied() else {
                return send_tool_err(stream, write_buf, id, "Head branch not found");
            };
            let Some(base_sha) = repo.refs.get(&format!("refs/heads/{}", base)).copied() else {
                return send_tool_err(stream, write_buf, id, "Base branch not found");
            };
            let pr_id = store.next_pr_id.fetch_add(1, Ordering::Relaxed);
            let number = (repo.pulls.len() + 1) as u32;
            let pr = PullRequest {
                id: pr_id,
                global_id: format!("PR_{:x}_{:x}", repo.id, number),
                number,
                title,
                body,
                state: IssueState::Open,
                head_ref: head,
                head_sha,
                base_ref: base,
                base_sha,
                merged: false,
                merged_at: None,
                merge_commit_sha: None,
            };
            let mut raw = Vec::with_capacity(256);
            format_pr_json(&mut raw, &pr);
            repo.pulls.push(pr);
            let val: Value = serde_json::from_slice(&raw).unwrap();
            send_tool_ok(stream, write_buf, id, val)
        }
        "merge_pull_request" => {
            let (Some(owner), Some(repo_name)) = (req_str("owner"), req_str("repo")) else {
                return send_rpc_err(stream, write_buf, id, -32602, "Missing owner or repo");
            };
            let pull_number = match args.get("pull_number") {
                Some(Value::Number(n)) => n.as_u64().map(|v| v as u32),
                Some(Value::String(s)) => s.parse::<u32>().ok(),
                _ => None,
            };
            let Some(num) = pull_number else {
                return send_rpc_err(stream, write_buf, id, -32602, "Missing pull_number");
            };
            let Some((owner_login, repo_arc)) = store.get_repo(&owner, &repo_name) else {
                return send_tool_err(stream, write_buf, id, "Repository not found");
            };
            let mut repo = repo_arc.write().unwrap();
            match repo.squash_merge_pr(num, &store.commit_seq, None, &owner_login) {
                Ok(sha) => send_tool_ok(
                    stream,
                    write_buf,
                    id,
                    json!({
                        "sha": crate::util::oid_hex_string(&sha),
                        "merged": true,
                        "message": "Pull Request successfully merged"
                    }),
                ),
                Err(MergeError::NotFound) => {
                    send_tool_err(stream, write_buf, id, "Pull request not found")
                }
                Err(MergeError::Conflict) => send_tool_err(stream, write_buf, id, "Merge conflict"),
            }
        }
        _ => send_rpc_err(stream, write_buf, id, -32601, "Unknown tool"),
    }
}
