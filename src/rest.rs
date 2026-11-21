use std::borrow::Cow;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::http::{
    host_str, write_json_message, write_json_resp, HttpResponse, BAD_JSON_RESP, NOT_FOUND_RESP,
    NO_CONTENT_RESP, UNAUTH_RESP,
};
use crate::store::{
    build_commit, format_issue_json, format_pr_json, format_repo_json, parse_commit_message,
    parse_tree, Issue, IssueState, MergeError, ObjType, PullRequest, Repo, Store,
    SCENARIO_EPOCH_SEC,
};
use crate::util::{
    b64_decode, b64_encode, hex_to_oid, parse_fast_issue_body, parse_query_param,
    percent_decode_path, write_json_str, write_oid_hex, write_u64_ascii, Oid, OidSet,
};

pub fn handle_rest(
    write_buf: &mut Vec<u8>,
    store: &Store,
    method: &[u8],
    path: &[u8],
    query: &[u8],
    auth: Option<&[u8]>,
    host: Option<&[u8]>,
    body: &[u8],
) -> HttpResponse {
    if !store.check_auth(auth) {
        return HttpResponse::Static(UNAUTH_RESP);
    }

    // Hot paths for bench.read and bench.write: /api/v3/repos/{owner}/{repo}/issues[/{n}]
    if let Some(after_repos) = path.strip_prefix(b"/api/v3/repos/") {
        if let Some(s1) = after_repos.iter().position(|&b| b == b'/') {
            let owner_b = &after_repos[..s1];
            let rem1 = &after_repos[s1 + 1..];
            if let Some(s2) = rem1.iter().position(|&b| b == b'/') {
                let repo_b = &rem1[..s2];
                let tail = &rem1[s2..];
                if !owner_b.contains(&b'%') && !repo_b.contains(&b'%') {
                    if let (Ok(owner), Ok(repo_name)) =
                        (std::str::from_utf8(owner_b), std::str::from_utf8(repo_b))
                    {
                        if method == b"GET" && tail.starts_with(b"/issues/") {
                            let num_b = &tail[8..];
                            if !num_b.is_empty() && num_b.iter().all(|b| b.is_ascii_digit()) {
                                if let Ok(num) =
                                    unsafe { std::str::from_utf8_unchecked(num_b) }.parse::<u32>()
                                {
                                    return fast_get_issue(store, owner, repo_name, num);
                                }
                            }
                        } else if method == b"POST" && tail == b"/issues" {
                            return fast_create_issue(write_buf, store, owner, repo_name, body);
                        }
                    }
                }
            }
        }
    }

    // Root and metadata endpoints
    if method == b"GET" && (path == b"/api/v3" || path == b"/api/v3/") {
        return write_json_resp(
            write_buf,
            200,
            b"X-OAuth-Scopes: repo, read:org\r\n",
            b"{\"current_user_url\":\"/api/v3/user\"}",
        );
    }
    if method == b"GET" && path == b"/api/v3/meta" {
        return write_json_resp(
            write_buf,
            200,
            b"",
            b"{\"installed_version\":\"1.0.0\"}",
        );
    }
    if method == b"GET" && path == b"/api/v3/user" {
        let login = store.inner.read().unwrap().owner_login.clone();
        let mut json = Vec::with_capacity(64);
        json.extend_from_slice(b"{\"login\":");
        write_json_str(&mut json, &login);
        json.extend_from_slice(b",\"id\":1000}");
        return write_json_resp(write_buf, 200, b"", &json);
    }
    if path == b"/api/v3/user/repos" {
        return match method {
            b"GET" => list_user_repos(write_buf, store, query, host),
            b"POST" => create_user_repo(write_buf, store, body),
            _ => HttpResponse::Static(NOT_FOUND_RESP),
        };
    }

    let Some(after_repos) = path.strip_prefix(b"/api/v3/repos/") else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let Some(s1) = after_repos.iter().position(|&b| b == b'/') else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let owner = percent_decode_path(&after_repos[..s1]);
    let rem1 = &after_repos[s1 + 1..];
    let (repo_name, tail_bytes) = match rem1.iter().position(|&b| b == b'/') {
        Some(s2) => (percent_decode_path(&rem1[..s2]), &rem1[s2..]),
        None => (percent_decode_path(rem1), &b""[..]),
    };

    if tail_bytes.is_empty() || tail_bytes == b"/" {
        return match method {
            b"DELETE" => {
                if store.delete_repo(&owner, &repo_name) {
                    HttpResponse::Static(NO_CONTENT_RESP)
                } else {
                    HttpResponse::Static(NOT_FOUND_RESP)
                }
            }
            b"GET" => {
                let Some(repo_arc) = store.get_repo_arc(&owner, &repo_name) else {
                    return HttpResponse::Static(NOT_FOUND_RESP);
                };
                let repo = repo_arc.read().unwrap();
                let mut json = Vec::with_capacity(256);
                format_repo_json(&mut json, &owner, &repo);
                write_json_resp(write_buf, 200, b"", &json)
            }
            b"PATCH" => {
                let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
                    return HttpResponse::Static(BAD_JSON_RESP);
                };
                let Some(obj) = val.as_object() else {
                    return HttpResponse::Static(BAD_JSON_RESP);
                };
                let Some(repo_arc) = store.get_repo_arc(&owner, &repo_name) else {
                    return HttpResponse::Static(NOT_FOUND_RESP);
                };
                let mut repo = repo_arc.write().unwrap();
                if let Some(desc) = obj.get("description").and_then(|v| v.as_str()) {
                    repo.description = desc.to_owned();
                }
                if let Some(priv_flag) = obj.get("private").and_then(|v| v.as_bool()) {
                    repo.private = priv_flag;
                }
                if let Some(def_br) = obj.get("default_branch").and_then(|v| v.as_str()) {
                    if !def_br.is_empty() {
                        repo.default_branch = def_br.to_owned();
                    }
                }
                let mut json = Vec::with_capacity(256);
                format_repo_json(&mut json, &owner, &repo);
                write_json_resp(write_buf, 200, b"", &json)
            }
            _ => HttpResponse::Static(NOT_FOUND_RESP),
        };
    }

    let Some(repo_arc) = store.get_repo_arc(&owner, &repo_name) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };

    // Route remaining /repos/{o}/{r}/... endpoints
    if method == b"POST" && tail_bytes == b"/git/refs" {
        return create_git_ref(write_buf, &repo_arc, body);
    }
    if method == b"GET" && tail_bytes.starts_with(b"/git/refs/") {
        let sub = percent_decode_path(&tail_bytes[b"/git/refs/".len()..]);
        let full_ref = format!("refs/{}", sub);
        let repo = repo_arc.read().unwrap();
        let Some(&oid) = repo.refs.get(&full_ref) else {
            return HttpResponse::Static(NOT_FOUND_RESP);
        };
        let mut json = Vec::with_capacity(128);
        json.extend_from_slice(b"{\"ref\":");
        write_json_str(&mut json, &full_ref);
        json.extend_from_slice(b",\"object\":{\"sha\":\"");
        write_oid_hex(&oid, &mut json);
        json.extend_from_slice(b"\",\"type\":\"commit\"}}");
        return write_json_resp(write_buf, 200, b"", &json);
    }
    if method == b"GET" && tail_bytes == b"/branches" {
        let repo = repo_arc.read().unwrap();
        let mut json = Vec::with_capacity(256);
        json.push(b'[');
        let mut first = true;
        for (name, &oid) in &repo.refs {
            if let Some(br) = name.strip_prefix("refs/heads/") {
                if !first {
                    json.push(b',');
                }
                first = false;
                json.extend_from_slice(b"{\"name\":");
                write_json_str(&mut json, br);
                json.extend_from_slice(b",\"commit\":{\"sha\":\"");
                write_oid_hex(&oid, &mut json);
                json.extend_from_slice(b"\"}}");
            }
        }
        json.push(b']');
        return write_json_resp(write_buf, 200, b"", &json);
    }
    if method == b"GET" && tail_bytes.starts_with(b"/branches/") {
        let br = percent_decode_path(&tail_bytes[b"/branches/".len()..]);
        let repo = repo_arc.read().unwrap();
        let Some(&oid) = repo.refs.get(&format!("refs/heads/{}", br)) else {
            return HttpResponse::Static(NOT_FOUND_RESP);
        };
        let mut json = Vec::with_capacity(128);
        json.extend_from_slice(b"{\"name\":");
        write_json_str(&mut json, &br);
        json.extend_from_slice(b",\"commit\":{\"sha\":\"");
        write_oid_hex(&oid, &mut json);
        json.extend_from_slice(b"\"}}");
        return write_json_resp(write_buf, 200, b"", &json);
    }
    if method == b"GET" && tail_bytes == b"/commits" {
        return list_commits(write_buf, &repo_arc, query);
    }
    if tail_bytes == b"/contents" || tail_bytes.starts_with(b"/contents/") {
        let file_path: Cow<'_, str> = if tail_bytes.len() > b"/contents/".len() {
            percent_decode_path(&tail_bytes[b"/contents/".len()..])
        } else {
            Cow::Borrowed("")
        };
        return match method {
            b"GET" => get_contents(write_buf, &repo_arc, &file_path, query),
            b"PUT" => put_contents(write_buf, store, &owner, &repo_arc, &file_path, body),
            b"DELETE" => delete_contents(write_buf, store, &owner, &repo_arc, &file_path, body),
            _ => HttpResponse::Static(NOT_FOUND_RESP),
        };
    }
    if method == b"POST" && tail_bytes == b"/labels" {
        return create_label(write_buf, &repo_arc, body);
    }
    if tail_bytes == b"/issues" {
        return match method {
            b"GET" => list_issues(write_buf, &repo_arc, query),
            b"POST" => fast_create_issue_arc(write_buf, store, &repo_arc, body),
            _ => HttpResponse::Static(NOT_FOUND_RESP),
        };
    }
    if let Some(after_issues) = tail_bytes.strip_prefix(b"/issues/") {
        if let Some(slash) = after_issues.iter().position(|&b| b == b'/') {
            let num_str = std::str::from_utf8(&after_issues[..slash]).unwrap_or("");
            let Ok(num) = num_str.parse::<u32>() else {
                return HttpResponse::Static(NOT_FOUND_RESP);
            };
            let sub = &after_issues[slash..];
            if sub == b"/comments" {
                return match method {
                    b"GET" => list_comments(write_buf, &repo_arc, num),
                    b"POST" => create_comment(write_buf, store, &repo_arc, num, body),
                    _ => HttpResponse::Static(NOT_FOUND_RESP),
                };
            }
            return HttpResponse::Static(NOT_FOUND_RESP);
        } else {
            let num_str = std::str::from_utf8(after_issues).unwrap_or("");
            let Ok(num) = num_str.parse::<u32>() else {
                return HttpResponse::Static(NOT_FOUND_RESP);
            };
            return match method {
                b"GET" => get_issue_arc(&repo_arc, num),
                b"PATCH" => patch_issue(write_buf, &repo_arc, num, body),
                _ => HttpResponse::Static(NOT_FOUND_RESP),
            };
        }
    }

    if tail_bytes == b"/pulls" {
        return match method {
            b"GET" => list_pulls(write_buf, &repo_arc, query),
            b"POST" => create_pull(write_buf, store, &repo_arc, body),
            _ => HttpResponse::Static(NOT_FOUND_RESP),
        };
    }
    if let Some(after_pulls) = tail_bytes.strip_prefix(b"/pulls/") {
        if let Some(slash) = after_pulls.iter().position(|&b| b == b'/') {
            let num_str = std::str::from_utf8(&after_pulls[..slash]).unwrap_or("");
            let Ok(num) = num_str.parse::<u32>() else {
                return HttpResponse::Static(NOT_FOUND_RESP);
            };
            let sub = &after_pulls[slash..];
            if method == b"GET" && sub == b"/files" {
                return list_pull_files(write_buf, &repo_arc, num);
            }
            if method == b"PUT" && sub == b"/merge" {
                return merge_pull(write_buf, store, &owner, &repo_arc, num, body);
            }
            return HttpResponse::Static(NOT_FOUND_RESP);
        } else if method == b"GET" {
            let num_str = std::str::from_utf8(after_pulls).unwrap_or("");
            let Ok(num) = num_str.parse::<u32>() else {
                return HttpResponse::Static(NOT_FOUND_RESP);
            };
            let repo = repo_arc.read().unwrap();
            let Some(pr) = num.checked_sub(1).and_then(|i| repo.pulls.get(i as usize)) else {
                return HttpResponse::Static(NOT_FOUND_RESP);
            };
            let mut json = Vec::with_capacity(256);
            format_pr_json(&mut json, pr);
            return write_json_resp(write_buf, 200, b"", &json);
        }
    }

    HttpResponse::Static(NOT_FOUND_RESP)
}

#[inline]
fn fast_get_issue(
    store: &Store,
    owner: &str,
    repo_name: &str,
    num: u32,
) -> HttpResponse {
    let Some(repo_arc) = store.get_repo_arc(owner, repo_name) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    get_issue_arc(&repo_arc, num)
}

#[inline]
fn get_issue_arc(
    repo_arc: &std::sync::RwLock<Repo>,
    num: u32,
) -> HttpResponse {
    let Some(idx) = num.checked_sub(1).map(|i| i as usize) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let cached_opt = {
        let repo = repo_arc.read().unwrap();
        if idx >= repo.issues.len() {
            return HttpResponse::Static(NOT_FOUND_RESP);
        }
        repo.issue_http_cache
            .get(idx)
            .and_then(|o| o.as_ref().map(Arc::clone))
    };
    if let Some(cached) = cached_opt {
        return HttpResponse::Shared(cached);
    }
    let frame = {
        let mut repo = repo_arc.write().unwrap();
        repo.get_or_build_issue_http(num)
    };
    match frame {
        Some(f) => HttpResponse::Shared(f),
        None => HttpResponse::Static(NOT_FOUND_RESP),
    }
}

#[inline]
fn fast_create_issue(
    write_buf: &mut Vec<u8>,
    store: &Store,
    owner: &str,
    repo_name: &str,
    body: &[u8],
) -> HttpResponse {
    let Some(repo_arc) = store.get_repo_arc(owner, repo_name) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    fast_create_issue_arc(write_buf, store, &repo_arc, body)
}

#[inline]
fn fast_create_issue_arc(
    write_buf: &mut Vec<u8>,
    store: &Store,
    repo_arc: &std::sync::RwLock<Repo>,
    body: &[u8],
) -> HttpResponse {
    let Ok(input) = parse_fast_issue_body(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let mut repo = repo_arc.write().unwrap();
    if let Some(ref lbls) = input.labels {
        for l in lbls {
            if !repo.labels.contains_key(l) {
                drop(repo);
                return write_json_message(
                    write_buf,
                    422,
                    "Validation Failed: label does not exist",
                );
            }
        }
    }
    if repo.issues.is_empty() {
        repo.issues.reserve(1024);
        repo.issue_http_cache.reserve(1024);
    }
    let id = store.next_issue_id.fetch_add(1, Ordering::Relaxed);
    let number = (repo.issues.len() + 1) as u32;
    let issue = Issue {
        id,
        global_id: format!("I_{:x}_{:x}", repo.id, number),
        number,
        title: input.title.into_owned(),
        body: input.body.into_owned(),
        state: IssueState::Open,
        labels: input.labels.unwrap_or_default(),
        comments: Vec::new(),
        seq: id,
    };

    write_buf.clear();
    write_buf.extend_from_slice(
        b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nX-GitHub-Request-Id: 1\r\nContent-Length:       \r\n\r\n",
    );
    let cl_end = write_buf.len() - 4;
    let body_start = write_buf.len();
    format_issue_json(write_buf, &issue);
    repo.issues.push(issue);
    repo.issue_http_cache.push(None);
    drop(repo);

    let body_len = write_buf.len() - body_start;
    if body_len <= 999_999 {
        let mut n = body_len;
        let mut p = cl_end;
        loop {
            p -= 1;
            write_buf[p] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
    } else {
        let mut digits = [0u8; 20];
        let mut dpos = 20;
        let mut n = body_len;
        while n > 0 {
            dpos -= 1;
            digits[dpos] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        let dlen = 20 - dpos;
        let extra = dlen - 6;
        write_buf.resize(body_start + body_len + extra, 0);
        write_buf.copy_within(body_start..body_start + body_len, body_start + extra);
        let new_cl_end = cl_end + extra;
        write_buf[cl_end - 6..new_cl_end].copy_from_slice(&digits[dpos..]);
        write_buf[new_cl_end..new_cl_end + 4].copy_from_slice(b"\r\n\r\n");
    }
    HttpResponse::Owned
}

fn list_user_repos(
    write_buf: &mut Vec<u8>,
    store: &Store,
    query: &[u8],
    host: Option<&[u8]>,
) -> HttpResponse {
    let per_page = parse_query_param(query, b"per_page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(30)
        .clamp(1, 100);
    let page = parse_query_param(query, b"page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);

    let g = store.inner.read().unwrap();
    let total = g.repo_order.len();
    let start = (page - 1).saturating_mul(per_page);
    let end = start.saturating_add(per_page).min(total);

    let mut json = Vec::with_capacity(1024);
    json.push(b'[');
    if start < total {
        for (idx, name) in g.repo_order[start..end].iter().enumerate() {
            if idx > 0 {
                json.push(b',');
            }
            if let Some(repo_arc) = g.repos.get(name) {
                let repo = repo_arc.read().unwrap();
                format_repo_json(&mut json, &g.owner_login, &repo);
            }
        }
    }
    json.push(b']');

    let extra = if end < total {
        let h = host_str(host);
        format!(
            "Link: <http://{}/api/v3/user/repos?per_page={}&page={}>; rel=\"next\"\r\n",
            h,
            per_page,
            page + 1
        )
    } else {
        String::new()
    };

    write_json_resp(write_buf, 200, extra.as_bytes(), &json)
}

fn create_user_repo(write_buf: &mut Vec<u8>, store: &Store, body: &[u8]) -> HttpResponse {
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(obj) = val.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_owned();
    if name.is_empty() {
        return write_json_message(write_buf, 422, "Repository name is required");
    }
    let private = obj.get("private").and_then(|v| v.as_bool()).unwrap_or(false);
    let description = obj
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    let Ok((owner_login, repo_arc)) = store.create_repo(name, private, description) else {
        return write_json_message(write_buf, 422, "Repository already exists");
    };
    let repo = repo_arc.read().unwrap();
    let mut json = Vec::with_capacity(256);
    format_repo_json(&mut json, &owner_login, &repo);
    write_json_resp(write_buf, 201, b"", &json)
}

fn create_git_ref(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    body: &[u8],
) -> HttpResponse {
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(obj) = val.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(ref_name) = obj.get("ref").and_then(|v| v.as_str()) else {
        return write_json_message(write_buf, 422, "Missing ref");
    };
    let Some(sha_str) = obj.get("sha").and_then(|v| v.as_str()) else {
        return write_json_message(write_buf, 422, "Missing sha");
    };
    let Some(oid) = hex_to_oid(sha_str.as_bytes()) else {
        return write_json_message(write_buf, 422, "Invalid sha");
    };
    let mut repo = repo_arc.write().unwrap();
    if !repo.objects.contains_key(&oid) {
        return write_json_message(write_buf, 422, "Object does not exist");
    }
    if repo.refs.contains_key(ref_name) {
        return write_json_message(write_buf, 422, "Reference already exists");
    }
    repo.refs.insert(ref_name.to_owned(), oid);
    repo.invalidate_git_caches();

    let mut json = Vec::with_capacity(128);
    json.extend_from_slice(b"{\"ref\":");
    write_json_str(&mut json, ref_name);
    json.extend_from_slice(b",\"object\":{\"sha\":\"");
    write_oid_hex(&oid, &mut json);
    json.extend_from_slice(b"\",\"type\":\"commit\"}}");
    write_json_resp(write_buf, 201, b"", &json)
}

fn list_commits(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    query: &[u8],
) -> HttpResponse {
    let sha_param = parse_query_param(query, b"sha");
    let repo = repo_arc.read().unwrap();
    let start_oid = match sha_param {
        Some(ref spec) if !spec.is_empty() => match repo.resolve_ref_oid(spec) {
            Some(oid) => oid,
            None => return HttpResponse::Static(NOT_FOUND_RESP),
        },
        _ => match repo
            .refs
            .get(&format!("refs/heads/{}", repo.default_branch))
            .copied()
        {
            Some(oid) => oid,
            None => {
                return write_json_resp(write_buf, 200, b"", b"[]");
            }
        },
    };

    let mut json = Vec::with_capacity(512);
    json.push(b'[');
    let mut seen = OidSet::default();
    let mut queue = std::collections::VecDeque::new();
    seen.insert(start_oid);
    queue.push_back(start_oid);
    let mut first = true;
    let mut count = 0usize;

    while let Some(oid) = queue.pop_front() {
        if count >= 200 {
            break;
        }
        let Some(obj) = repo.objects.get(&oid) else {
            continue;
        };
        if obj.kind != ObjType::Commit {
            continue;
        }
        count += 1;
        if !first {
            json.push(b',');
        }
        first = false;
        let msg = parse_commit_message(&obj.data);
        json.extend_from_slice(b"{\"sha\":\"");
        write_oid_hex(&oid, &mut json);
        json.extend_from_slice(b"\",\"commit\":{\"message\":");
        write_json_str(&mut json, &msg);
        json.extend_from_slice(b"}}");

        if let Some(parents) = repo.commit_parents.get(&oid) {
            for &p in parents.as_slice() {
                if seen.insert(p) {
                    queue.push_back(p);
                }
            }
        }
    }
    json.push(b']');
    write_json_resp(write_buf, 200, b"", &json)
}

fn get_contents(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    file_path: &str,
    query: &[u8],
) -> HttpResponse {
    let ref_param = parse_query_param(query, b"ref");
    let repo = repo_arc.read().unwrap();
    let ref_name = ref_param.as_deref().unwrap_or(&repo.default_branch);
    let Some(commit_oid) = repo.resolve_ref_oid(ref_name) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let Some(&tree_oid) = repo.commit_trees.get(&commit_oid) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let clean_path = file_path.trim_matches('/');
    let segments: Vec<&str> = if clean_path.is_empty() {
        Vec::new()
    } else {
        clean_path.split('/').filter(|s| !s.is_empty()).collect()
    };
    let Some((mode, oid)) = repo.find_tree_entry_at_path(tree_oid, &segments) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };

    if mode == "40000" {
        let Some(tree_obj) = repo.objects.get(&oid) else {
            return HttpResponse::Static(NOT_FOUND_RESP);
        };
        let entries = parse_tree(&tree_obj.data);
        let mut json = Vec::with_capacity(entries.len() * 96 + 8);
        json.push(b'[');
        for (idx, e) in entries.iter().enumerate() {
            if idx > 0 {
                json.push(b',');
            }
            let ty = if e.mode == "40000" { "dir" } else { "file" };
            let entry_path = if clean_path.is_empty() {
                e.name.clone()
            } else {
                format!("{}/{}", clean_path, e.name)
            };
            let size = if e.mode == "40000" {
                0
            } else {
                repo.objects.get(&e.oid).map(|o| o.data.len()).unwrap_or(0)
            };
            json.extend_from_slice(b"{\"type\":\"");
            json.extend_from_slice(ty.as_bytes());
            json.extend_from_slice(b"\",\"name\":");
            write_json_str(&mut json, &e.name);
            json.extend_from_slice(b",\"path\":");
            write_json_str(&mut json, &entry_path);
            json.extend_from_slice(b",\"sha\":\"");
            write_oid_hex(&e.oid, &mut json);
            json.extend_from_slice(b"\",\"size\":");
            write_u64_ascii(&mut json, size as u64);
            json.push(b'}');
        }
        json.push(b']');
        write_json_resp(write_buf, 200, b"", &json)
    } else {
        let Some(blob_obj) = repo.objects.get(&oid) else {
            return HttpResponse::Static(NOT_FOUND_RESP);
        };
        let b64 = b64_encode(&blob_obj.data);
        let name = segments.last().copied().unwrap_or("");
        let mut json = Vec::with_capacity(b64.len() + 192);
        json.extend_from_slice(b"{\"type\":\"file\",\"encoding\":\"base64\",\"content\":");
        write_json_str(&mut json, &b64);
        json.extend_from_slice(b",\"sha\":\"");
        write_oid_hex(&oid, &mut json);
        json.extend_from_slice(b"\",\"size\":");
        write_u64_ascii(&mut json, blob_obj.data.len() as u64);
        json.extend_from_slice(b",\"name\":");
        write_json_str(&mut json, name);
        json.extend_from_slice(b",\"path\":");
        write_json_str(&mut json, clean_path);
        json.push(b'}');
        write_json_resp(write_buf, 200, b"", &json)
    }
}

fn put_contents(
    write_buf: &mut Vec<u8>,
    store: &Store,
    owner_login: &str,
    repo_arc: &std::sync::RwLock<Repo>,
    file_path: &str,
    body: &[u8],
) -> HttpResponse {
    let clean_path = file_path.trim_matches('/');
    if clean_path.is_empty() {
        return write_json_message(write_buf, 422, "Invalid path");
    }
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(obj) = val.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let message = obj
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("update file");
    let Some(content_b64) = obj.get("content").and_then(|v| v.as_str()) else {
        return write_json_message(write_buf, 422, "Missing content");
    };
    let Some(raw_bytes) = b64_decode(content_b64.as_bytes()) else {
        return write_json_message(write_buf, 422, "Invalid base64 content");
    };
    let provided_sha = match obj.get("sha") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str().and_then(|s| hex_to_oid(s.as_bytes())) {
            Some(oid) => Some(oid),
            None => return write_json_message(write_buf, 409, "Invalid sha"),
        },
    };

    let mut repo = repo_arc.write().unwrap();
    let branch = obj
        .get("branch")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&repo.default_branch)
        .to_owned();
    let full_ref = format!("refs/heads/{}", branch);
    let default_full_ref = format!("refs/heads/{}", repo.default_branch);

    let parent_tip = repo
        .refs
        .get(&full_ref)
        .copied()
        .or_else(|| repo.refs.get(&default_full_ref).copied());

    let mut files = match parent_tip {
        Some(tip) => repo.flatten_commit_tree(tip),
        None => std::collections::BTreeMap::new(),
    };

    let existing_oid = files.get(clean_path).map(|(_, oid)| *oid);
    let status = match existing_oid {
        Some(cur_oid) => {
            if provided_sha != Some(cur_oid) {
                return write_json_message(write_buf, 409, "sha does not match");
            }
            200
        }
        None => {
            if provided_sha.is_some() {
                return write_json_message(write_buf, 409, "sha does not match");
            }
            201
        }
    };

    let blob_size = raw_bytes.len();
    let blob_oid = repo.put_object(ObjType::Blob, raw_bytes);
    files.insert(clean_path.to_owned(), ("100644".to_owned(), blob_oid));
    let tree_oid = repo.build_tree_from_flat(&files);

    let seq = store.commit_seq.fetch_add(1, Ordering::Relaxed);
    let parents: &[Oid] = match parent_tip {
        Some(ref p) => std::slice::from_ref(p),
        None => &[],
    };
    let commit_bytes = build_commit(
        tree_oid,
        parents,
        owner_login,
        SCENARIO_EPOCH_SEC + seq,
        message,
    );
    let commit_oid = repo.put_object(ObjType::Commit, commit_bytes);
    repo.refs.insert(full_ref, commit_oid);
    repo.invalidate_git_caches();

    let name = clean_path.rsplit('/').next().unwrap_or(clean_path);
    let mut json = Vec::with_capacity(256);
    json.extend_from_slice(b"{\"content\":{\"name\":");
    write_json_str(&mut json, name);
    json.extend_from_slice(b",\"path\":");
    write_json_str(&mut json, clean_path);
    json.extend_from_slice(b",\"sha\":\"");
    write_oid_hex(&blob_oid, &mut json);
    json.extend_from_slice(b"\",\"size\":");
    write_u64_ascii(&mut json, blob_size as u64);
    json.extend_from_slice(b",\"encoding\":\"base64\"},\"commit\":{\"sha\":\"");
    write_oid_hex(&commit_oid, &mut json);
    json.extend_from_slice(b"\"}}");
    write_json_resp(write_buf, status, b"", &json)
}

fn delete_contents(
    write_buf: &mut Vec<u8>,
    store: &Store,
    owner_login: &str,
    repo_arc: &std::sync::RwLock<Repo>,
    file_path: &str,
    body: &[u8],
) -> HttpResponse {
    let clean_path = file_path.trim_matches('/');
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(obj) = val.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let message = obj
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("delete file");
    let provided_sha = obj
        .get("sha")
        .and_then(|v| v.as_str())
        .and_then(|s| hex_to_oid(s.as_bytes()));

    let mut repo = repo_arc.write().unwrap();
    let branch = obj
        .get("branch")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&repo.default_branch)
        .to_owned();
    let full_ref = format!("refs/heads/{}", branch);
    let Some(parent_tip) = repo.refs.get(&full_ref).copied() else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };

    let mut files = repo.flatten_commit_tree(parent_tip);
    let Some((_, cur_oid)) = files.get(clean_path).cloned() else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    if provided_sha != Some(cur_oid) {
        return write_json_message(write_buf, 409, "sha does not match");
    }

    files.remove(clean_path);
    let tree_oid = repo.build_tree_from_flat(&files);
    let seq = store.commit_seq.fetch_add(1, Ordering::Relaxed);
    let commit_bytes = build_commit(
        tree_oid,
        &[parent_tip],
        owner_login,
        SCENARIO_EPOCH_SEC + seq,
        message,
    );
    let commit_oid = repo.put_object(ObjType::Commit, commit_bytes);
    repo.refs.insert(full_ref, commit_oid);
    repo.invalidate_git_caches();

    let mut json = Vec::with_capacity(96);
    json.extend_from_slice(b"{\"commit\":{\"sha\":\"");
    write_oid_hex(&commit_oid, &mut json);
    json.extend_from_slice(b"\"}}");
    write_json_resp(write_buf, 200, b"", &json)
}

fn create_label(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    body: &[u8],
) -> HttpResponse {
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(obj) = val.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if name.is_empty() {
        return write_json_message(write_buf, 422, "Label name is required");
    }
    let color = obj
        .get("color")
        .and_then(|v| v.as_str())
        .unwrap_or("ededed")
        .to_owned();

    let mut repo = repo_arc.write().unwrap();
    repo.labels.insert(name.clone(), color.clone());

    let mut json = Vec::with_capacity(64 + name.len() + color.len());
    json.extend_from_slice(b"{\"name\":");
    write_json_str(&mut json, &name);
    json.extend_from_slice(b",\"color\":");
    write_json_str(&mut json, &color);
    json.push(b'}');
    write_json_resp(write_buf, 201, b"", &json)
}

fn list_issues(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    query: &[u8],
) -> HttpResponse {
    let state_param = parse_query_param(query, b"state");
    let dir_param = parse_query_param(query, b"direction");
    let per_page = parse_query_param(query, b"per_page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(30)
        .clamp(1, 100);
    let page = parse_query_param(query, b"page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);

    let want_state = match state_param.as_deref() {
        Some("closed") => Some(IssueState::Closed),
        Some("all") => None,
        _ => Some(IssueState::Open),
    };
    let asc = dir_param.as_deref() == Some("asc");

    let repo = repo_arc.read().unwrap();
    let mut matching: Vec<&Issue> = repo
        .issues
        .iter()
        .filter(|i| want_state.map(|s| i.state == s).unwrap_or(true))
        .collect();

    if asc {
        matching.sort_by_key(|i| (i.seq, i.number));
    } else {
        matching.sort_by(|a, b| (b.seq, b.number).cmp(&(a.seq, a.number)));
    }

    let start = (page - 1).saturating_mul(per_page);
    let end = start.saturating_add(per_page).min(matching.len());

    let mut json = Vec::with_capacity(512);
    json.push(b'[');
    if start < matching.len() {
        for (idx, issue) in matching[start..end].iter().enumerate() {
            if idx > 0 {
                json.push(b',');
            }
            format_issue_json(&mut json, issue);
        }
    }
    json.push(b']');
    write_json_resp(write_buf, 200, b"", &json)
}

fn patch_issue(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    num: u32,
    body: &[u8],
) -> HttpResponse {
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(obj) = val.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };

    let mut repo = repo_arc.write().unwrap();
    let Some(idx) = num.checked_sub(1).map(|i| i as usize) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    if idx >= repo.issues.len() {
        return HttpResponse::Static(NOT_FOUND_RESP);
    }

    if let Some(lbls) = obj.get("labels").and_then(|v| v.as_array()) {
        for item in lbls {
            let Some(name) = item.as_str() else {
                return write_json_message(write_buf, 422, "Invalid label");
            };
            if !repo.labels.contains_key(name) {
                return write_json_message(
                    write_buf,
                    422,
                    "Validation Failed: label does not exist",
                );
            }
        }
    }

    let issue = &mut repo.issues[idx];
    if let Some(t) = obj.get("title").and_then(|v| v.as_str()) {
        issue.title = t.to_owned();
    }
    if let Some(b) = obj.get("body").and_then(|v| v.as_str()) {
        issue.body = b.to_owned();
    }
    if let Some(s) = obj.get("state").and_then(|v| v.as_str()) {
        match s {
            "open" => issue.state = IssueState::Open,
            "closed" => issue.state = IssueState::Closed,
            _ => return write_json_message(write_buf, 422, "Invalid state"),
        }
    }
    if let Some(lbls) = obj.get("labels").and_then(|v| v.as_array()) {
        issue.labels = lbls
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
    }

    let mut json = Vec::with_capacity(256);
    format_issue_json(&mut json, issue);
    repo.invalidate_issue_cache(num);
    write_json_resp(write_buf, 200, b"", &json)
}

fn create_comment(
    write_buf: &mut Vec<u8>,
    store: &Store,
    repo_arc: &std::sync::RwLock<Repo>,
    num: u32,
    body: &[u8],
) -> HttpResponse {
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(obj) = val.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let comment_body = obj
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    let mut repo = repo_arc.write().unwrap();
    let Some(issue) = num.checked_sub(1).and_then(|i| repo.issues.get_mut(i as usize)) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let cid = store.next_comment_id.fetch_add(1, Ordering::Relaxed);
    let gid = format!("C_{:x}", cid);
    issue.comments.push(crate::store::Comment {
        id: cid,
        global_id: gid.clone(),
        body: comment_body.clone(),
    });

    let mut json = Vec::with_capacity(96 + comment_body.len());
    json.extend_from_slice(b"{\"id\":");
    write_u64_ascii(&mut json, cid);
    json.extend_from_slice(b",\"node_id\":\"");
    json.extend_from_slice(gid.as_bytes());
    json.extend_from_slice(b"\",\"body\":");
    write_json_str(&mut json, &comment_body);
    json.push(b'}');
    write_json_resp(write_buf, 201, b"", &json)
}

fn list_comments(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    num: u32,
) -> HttpResponse {
    let repo = repo_arc.read().unwrap();
    let Some(issue) = num.checked_sub(1).and_then(|i| repo.issues.get(i as usize)) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let mut json = Vec::with_capacity(256);
    json.push(b'[');
    for (idx, c) in issue.comments.iter().enumerate() {
        if idx > 0 {
            json.push(b',');
        }
        json.extend_from_slice(b"{\"id\":");
        write_u64_ascii(&mut json, c.id);
        json.extend_from_slice(b",\"node_id\":\"");
        json.extend_from_slice(c.global_id.as_bytes());
        json.extend_from_slice(b"\",\"body\":");
        write_json_str(&mut json, &c.body);
        json.push(b'}');
    }
    json.push(b']');
    write_json_resp(write_buf, 200, b"", &json)
}

fn create_pull(
    write_buf: &mut Vec<u8>,
    store: &Store,
    repo_arc: &std::sync::RwLock<Repo>,
    body: &[u8],
) -> HttpResponse {
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let Some(obj) = val.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let title = obj
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let pr_body = obj
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let head = obj
        .get("head")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .strip_prefix("refs/heads/")
        .unwrap_or_else(|| obj.get("head").and_then(|v| v.as_str()).unwrap_or(""))
        .to_owned();
    let base = obj
        .get("base")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .strip_prefix("refs/heads/")
        .unwrap_or_else(|| obj.get("base").and_then(|v| v.as_str()).unwrap_or(""))
        .to_owned();

    let mut repo = repo_arc.write().unwrap();
    let Some(head_sha) = repo.refs.get(&format!("refs/heads/{}", head)).copied() else {
        return write_json_message(write_buf, 422, "Head branch not found");
    };
    let Some(base_sha) = repo.refs.get(&format!("refs/heads/{}", base)).copied() else {
        return write_json_message(write_buf, 422, "Base branch not found");
    };

    let id = store.next_pr_id.fetch_add(1, Ordering::Relaxed);
    let number = (repo.pulls.len() + 1) as u32;
    let pr = PullRequest {
        id,
        global_id: format!("PR_{:x}_{:x}", repo.id, number),
        number,
        title,
        body: pr_body,
        state: IssueState::Open,
        head_ref: head,
        head_sha,
        base_ref: base,
        base_sha,
        merged: false,
        merged_at: None,
        merge_commit_sha: None,
    };

    let mut json = Vec::with_capacity(256);
    format_pr_json(&mut json, &pr);
    repo.pulls.push(pr);
    write_json_resp(write_buf, 201, b"", &json)
}

fn list_pulls(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    query: &[u8],
) -> HttpResponse {
    let state_param = parse_query_param(query, b"state");
    let per_page = parse_query_param(query, b"per_page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(30)
        .clamp(1, 100);
    let page = parse_query_param(query, b"page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);

    let want_state = match state_param.as_deref() {
        Some("closed") => Some(IssueState::Closed),
        Some("all") => None,
        _ => Some(IssueState::Open),
    };

    let repo = repo_arc.read().unwrap();
    let matching: Vec<&PullRequest> = repo
        .pulls
        .iter()
        .filter(|p| want_state.map(|s| p.state == s).unwrap_or(true))
        .collect();

    let start = (page - 1).saturating_mul(per_page);
    let end = start.saturating_add(per_page).min(matching.len());

    let mut json = Vec::with_capacity(512);
    json.push(b'[');
    if start < matching.len() {
        for (idx, pr) in matching[start..end].iter().enumerate() {
            if idx > 0 {
                json.push(b',');
            }
            format_pr_json(&mut json, pr);
        }
    }
    json.push(b']');
    write_json_resp(write_buf, 200, b"", &json)
}

fn list_pull_files(
    write_buf: &mut Vec<u8>,
    repo_arc: &std::sync::RwLock<Repo>,
    num: u32,
) -> HttpResponse {
    let repo = repo_arc.read().unwrap();
    let Some(pr) = num.checked_sub(1).and_then(|i| repo.pulls.get(i as usize)) else {
        return HttpResponse::Static(NOT_FOUND_RESP);
    };
    let files = repo.diff_pr_files(pr);
    let mut json = Vec::with_capacity(files.len() * 96 + 8);
    json.push(b'[');
    for (idx, f) in files.iter().enumerate() {
        if idx > 0 {
            json.push(b',');
        }
        json.extend_from_slice(b"{\"filename\":");
        write_json_str(&mut json, &f.filename);
        json.extend_from_slice(b",\"status\":\"");
        json.extend_from_slice(f.status.as_bytes());
        json.extend_from_slice(b"\",\"additions\":");
        write_u64_ascii(&mut json, f.additions as u64);
        json.extend_from_slice(b",\"deletions\":");
        write_u64_ascii(&mut json, f.deletions as u64);
        json.extend_from_slice(b",\"changes\":");
        write_u64_ascii(&mut json, f.changes as u64);
        json.push(b'}');
    }
    json.push(b']');
    write_json_resp(write_buf, 200, b"", &json)
}

fn merge_pull(
    write_buf: &mut Vec<u8>,
    store: &Store,
    owner_login: &str,
    repo_arc: &std::sync::RwLock<Repo>,
    num: u32,
    body: &[u8],
) -> HttpResponse {
    let commit_title = if body.iter().all(|b| b.is_ascii_whitespace()) {
        None
    } else {
        let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) else {
            return HttpResponse::Static(BAD_JSON_RESP);
        };
        let Some(obj) = val.as_object() else {
            return HttpResponse::Static(BAD_JSON_RESP);
        };
        obj.get("commit_title")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };

    let mut repo = repo_arc.write().unwrap();
    match repo.squash_merge_pr(num, &store.commit_seq, commit_title.as_deref(), owner_login) {
        Ok(sha) => {
            let mut json = Vec::with_capacity(128);
            json.extend_from_slice(b"{\"sha\":\"");
            write_oid_hex(&sha, &mut json);
            json.extend_from_slice(
                b"\",\"merged\":true,\"message\":\"Pull Request successfully merged\"}",
            );
            write_json_resp(write_buf, 200, b"", &json)
        }
        Err(MergeError::NotFound) => HttpResponse::Static(NOT_FOUND_RESP),
        Err(MergeError::Conflict) => write_json_message(write_buf, 405, "Merge conflict"),
    }
}
