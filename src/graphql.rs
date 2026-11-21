use std::sync::atomic::Ordering;

use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

use crate::http::{write_json_resp, HttpResponse, BAD_JSON_RESP, UNAUTH_RESP};
use crate::store::{Comment, IssueState, MergeError, PullRequest, Store};
use crate::util::oid_hex_string;

pub fn handle_graphql(
    write_buf: &mut Vec<u8>,
    store: &Store,
    auth: Option<&[u8]>,
    body: &[u8],
) -> HttpResponse {
    if !store.check_auth(auth) {
        return HttpResponse::Static(UNAUTH_RESP);
    }

    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };

    if let Some(arr) = parsed.as_array() {
        let mut results = Vec::with_capacity(arr.len());
        for item in arr {
            let Some(obj) = item.as_object() else {
                return HttpResponse::Static(BAD_JSON_RESP);
            };
            results.push(exec_one_request(store, obj));
        }
        let resp_bytes = serde_json::to_vec(&results).unwrap_or_else(|_| b"[]".to_vec());
        return write_json_resp(write_buf, 200, b"", &resp_bytes);
    }

    let Some(obj) = parsed.as_object() else {
        return HttpResponse::Static(BAD_JSON_RESP);
    };
    let result = exec_one_request(store, obj);
    let resp_bytes = serde_json::to_vec(&result).unwrap_or_else(|_| b"{}".to_vec());
    write_json_resp(write_buf, 200, b"", &resp_bytes)
}

fn exec_one_request(store: &Store, obj: &Map<String, Value>) -> Value {
    let query = obj.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let variables = obj
        .get("variables")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let op_name = obj.get("operationName").and_then(|v| v.as_str());

    let doc = match parse_document(query) {
        Ok(d) => d,
        Err(msg) => {
            return json!({
                "data": Value::Null,
                "errors": [{ "message": msg }]
            });
        }
    };

    let op = if doc.operations.is_empty() {
        return json!({ "data": Value::Null, "errors": [{ "message": "No operation in query" }] });
    } else if let Some(name) = op_name {
        match doc
            .operations
            .iter()
            .find(|o| o.name.as_deref() == Some(name))
        {
            Some(o) => o,
            None => &doc.operations[0],
        }
    } else {
        &doc.operations[0]
    };

    let mut errors: Vec<Value> = Vec::new();
    let data = if op.is_mutation {
        exec_mutation(store, &doc.fragments, &variables, &op.selections, &mut errors)
    } else {
        exec_query(store, &doc.fragments, &variables, &op.selections, &mut errors)
    };

    if errors.is_empty() {
        json!({ "data": data })
    } else {
        json!({ "data": Value::Null, "errors": errors })
    }
}

// -----------------------------------------------------------------------------
// Minimal Recursive-Descent GraphQL Parser
// -----------------------------------------------------------------------------

#[derive(Clone)]
enum GqlVal {
    Var(String),
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Null,
    Enum(String),
    List(Vec<GqlVal>),
    Obj(Vec<(String, GqlVal)>),
}

#[derive(Clone)]
struct Field {
    alias: Option<String>,
    name: String,
    args: Vec<(String, GqlVal)>,
    selections: Vec<Selection>,
}

impl Field {
    #[inline]
    fn key(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Clone)]
enum Selection {
    Field(Field),
    InlineFragment {
        type_cond: Option<String>,
        selections: Vec<Selection>,
    },
    FragmentSpread(String),
}

struct Operation {
    is_mutation: bool,
    name: Option<String>,
    selections: Vec<Selection>,
}

struct Document {
    operations: Vec<Operation>,
    fragments: FxHashMap<String, Vec<Selection>>,
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            b: s.as_bytes(),
            i: 0,
        }
    }

    fn skip(&mut self) {
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b',') {
                self.i += 1;
            } else if c == b'#' {
                while self.i < self.b.len() && self.b[self.i] != b'\n' {
                    self.i += 1;
                }
            } else {
                break;
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip();
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, ch: u8) -> bool {
        if self.peek() == Some(ch) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn parse_name(&mut self) -> Result<String, String> {
        self.skip();
        let start = self.i;
        if self.i < self.b.len() && (self.b[self.i].is_ascii_alphabetic() || self.b[self.i] == b'_')
        {
            self.i += 1;
            while self.i < self.b.len()
                && (self.b[self.i].is_ascii_alphanumeric() || self.b[self.i] == b'_')
            {
                self.i += 1;
            }
            Ok(String::from_utf8_lossy(&self.b[start..self.i]).into_owned())
        } else {
            Err("Expected GraphQL name".to_owned())
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.skip();
        if self.i >= self.b.len() || self.b[self.i] != b'"' {
            return Err("Expected string".to_owned());
        }
        if self.b[self.i..].starts_with(b"\"\"\"") {
            self.i += 3;
            let start = self.i;
            while self.i < self.b.len() {
                if self.b[self.i..].starts_with(b"\"\"\"") {
                    let s = String::from_utf8_lossy(&self.b[start..self.i]).into_owned();
                    self.i += 3;
                    return Ok(s);
                }
                self.i += 1;
            }
            return Err("Unterminated block string".to_owned());
        }
        self.i += 1;
        let mut out = Vec::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            if c == b'"' {
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            if c == b'\\' && self.i < self.b.len() {
                let esc = self.b[self.i];
                self.i += 1;
                match esc {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    _ => out.push(esc),
                }
            } else {
                out.push(c);
            }
        }
        Err("Unterminated string".to_owned())
    }

    fn parse_value(&mut self) -> Result<GqlVal, String> {
        let Some(c) = self.peek() else {
            return Err("Unexpected EOF in value".to_owned());
        };
        match c {
            b'$' => {
                self.i += 1;
                Ok(GqlVal::Var(self.parse_name()?))
            }
            b'"' => Ok(GqlVal::Str(self.parse_string()?)),
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                while self.peek() != Some(b']') {
                    items.push(self.parse_value()?);
                }
                self.i += 1;
                Ok(GqlVal::List(items))
            }
            b'{' => {
                self.i += 1;
                let mut pairs = Vec::new();
                while self.peek() != Some(b'}') {
                    let k = self.parse_name()?;
                    if !self.eat(b':') {
                        return Err("Expected ':' in input object".to_owned());
                    }
                    let v = self.parse_value()?;
                    pairs.push((k, v));
                }
                self.i += 1;
                Ok(GqlVal::Obj(pairs))
            }
            b'-' | b'0'..=b'9' => {
                let start = self.i;
                if c == b'-' {
                    self.i += 1;
                }
                let mut is_float = false;
                while self.i < self.b.len()
                    && (self.b[self.i].is_ascii_digit()
                        || self.b[self.i] == b'.'
                        || self.b[self.i] == b'e'
                        || self.b[self.i] == b'E'
                        || self.b[self.i] == b'+'
                        || self.b[self.i] == b'-')
                {
                    if matches!(self.b[self.i], b'.' | b'e' | b'E') {
                        is_float = true;
                    }
                    self.i += 1;
                }
                let s = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("0");
                if is_float {
                    Ok(GqlVal::Float(s.parse::<f64>().unwrap_or(0.0)))
                } else {
                    Ok(GqlVal::Int(s.parse::<i64>().unwrap_or(0)))
                }
            }
            _ => {
                let name = self.parse_name()?;
                match name.as_str() {
                    "true" => Ok(GqlVal::Bool(true)),
                    "false" => Ok(GqlVal::Bool(false)),
                    "null" => Ok(GqlVal::Null),
                    _ => Ok(GqlVal::Enum(name)),
                }
            }
        }
    }

    fn parse_args(&mut self) -> Result<Vec<(String, GqlVal)>, String> {
        if !self.eat(b'(') {
            return Ok(Vec::new());
        }
        let mut args = Vec::new();
        while self.peek() != Some(b')') {
            let name = self.parse_name()?;
            if !self.eat(b':') {
                return Err("Expected ':' in argument".to_owned());
            }
            let val = self.parse_value()?;
            args.push((name, val));
        }
        self.i += 1;
        Ok(args)
    }

    fn skip_var_defs(&mut self) -> Result<(), String> {
        if !self.eat(b'(') {
            return Ok(());
        }
        let mut depth = 1usize;
        while self.i < self.b.len() && depth > 0 {
            match self.b[self.i] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b'"' => {
                    let _ = self.parse_string()?;
                    continue;
                }
                _ => {}
            }
            self.i += 1;
        }
        Ok(())
    }

    fn parse_selection_set(&mut self) -> Result<Vec<Selection>, String> {
        if !self.eat(b'{') {
            return Err("Expected '{'".to_owned());
        }
        let mut sels = Vec::new();
        while self.peek() != Some(b'}') {
            if self.b[self.i..].starts_with(b"...") {
                self.i += 3;
                if self.peek() == Some(b'{') {
                    let sub = self.parse_selection_set()?;
                    sels.push(Selection::InlineFragment {
                        type_cond: None,
                        selections: sub,
                    });
                } else {
                    let kw = self.parse_name()?;
                    if kw == "on" {
                        let type_name = self.parse_name()?;
                        let sub = self.parse_selection_set()?;
                        sels.push(Selection::InlineFragment {
                            type_cond: Some(type_name),
                            selections: sub,
                        });
                    } else {
                        sels.push(Selection::FragmentSpread(kw));
                    }
                }
            } else {
                let first = self.parse_name()?;
                let (alias, name) = if self.eat(b':') {
                    (Some(first), self.parse_name()?)
                } else {
                    (None, first)
                };
                let args = self.parse_args()?;
                // Skip optional directives (@include/@skip)
                while self.eat(b'@') {
                    let _ = self.parse_name()?;
                    let _ = self.parse_args()?;
                }
                let selections = if self.peek() == Some(b'{') {
                    self.parse_selection_set()?
                } else {
                    Vec::new()
                };
                sels.push(Selection::Field(Field {
                    alias,
                    name,
                    args,
                    selections,
                }));
            }
        }
        self.i += 1;
        Ok(sels)
    }
}

fn parse_document(query: &str) -> Result<Document, String> {
    let mut p = Parser::new(query);
    let mut operations = Vec::new();
    let mut fragments = FxHashMap::default();
    while let Some(c) = p.peek() {
        if c == b'{' {
            let selections = p.parse_selection_set()?;
            operations.push(Operation {
                is_mutation: false,
                name: None,
                selections,
            });
        } else {
            let kw = p.parse_name()?;
            match kw.as_str() {
                "query" | "mutation" => {
                    let is_mutation = kw == "mutation";
                    let name = if matches!(p.peek(), Some(b'(' | b'{' | b'@')) {
                        None
                    } else {
                        Some(p.parse_name()?)
                    };
                    p.skip_var_defs()?;
                    while p.eat(b'@') {
                        let _ = p.parse_name()?;
                        let _ = p.parse_args()?;
                    }
                    let selections = p.parse_selection_set()?;
                    operations.push(Operation {
                        is_mutation,
                        name,
                        selections,
                    });
                }
                "fragment" => {
                    let fname = p.parse_name()?;
                    let _on = p.parse_name()?;
                    let _type_name = p.parse_name()?;
                    let selections = p.parse_selection_set()?;
                    fragments.insert(fname, selections);
                }
                _ => return Err(format!("Unexpected token '{}'", kw)),
            }
        }
    }
    Ok(Document {
        operations,
        fragments,
    })
}

fn resolve_val(v: &GqlVal, vars: &Map<String, Value>) -> Value {
    match v {
        GqlVal::Var(name) => vars.get(name).cloned().unwrap_or(Value::Null),
        GqlVal::Int(n) => Value::Number((*n).into()),
        GqlVal::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        GqlVal::Str(s) => Value::String(s.clone()),
        GqlVal::Bool(b) => Value::Bool(*b),
        GqlVal::Null => Value::Null,
        GqlVal::Enum(s) => Value::String(s.clone()),
        GqlVal::List(items) => Value::Array(items.iter().map(|x| resolve_val(x, vars)).collect()),
        GqlVal::Obj(pairs) => {
            let mut m = Map::new();
            for (k, val) in pairs {
                m.insert(k.clone(), resolve_val(val, vars));
            }
            Value::Object(m)
        }
    }
}

fn arg_val(field: &Field, name: &str, vars: &Map<String, Value>) -> Option<Value> {
    field
        .args
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| resolve_val(v, vars))
}

fn expand_selections<'a>(
    sels: &'a [Selection],
    type_name: &str,
    fragments: &'a FxHashMap<String, Vec<Selection>>,
) -> Vec<&'a Field> {
    let mut out = Vec::new();
    for s in sels {
        match s {
            Selection::Field(f) => out.push(f),
            Selection::InlineFragment {
                type_cond,
                selections,
            } => {
                if type_cond.as_deref().map(|t| t == type_name).unwrap_or(true) {
                    out.extend(expand_selections(selections, type_name, fragments));
                }
            }
            Selection::FragmentSpread(name) => {
                if let Some(f_sels) = fragments.get(name) {
                    out.extend(expand_selections(f_sels, type_name, fragments));
                }
            }
        }
    }
    out
}

fn unknown_field(errors: &mut Vec<Value>, field_name: &str, type_name: &str) {
    errors.push(json!({
        "message": format!("Field '{}' doesn't exist on type '{}'", field_name, type_name)
    }));
}

fn exec_query(
    store: &Store,
    fragments: &FxHashMap<String, Vec<Selection>>,
    vars: &Map<String, Value>,
    selections: &[Selection],
    errors: &mut Vec<Value>,
) -> Value {
    let mut out = Map::new();
    for f in expand_selections(selections, "Query", fragments) {
        let key = f.key().to_owned();
        match f.name.as_str() {
            "__typename" => {
                out.insert(key, Value::String("Query".to_owned()));
            }
            "viewer" => {
                let owner = store.inner.read().unwrap().owner_login.clone();
                let val = resolve_user(&owner, fragments, &f.selections, errors);
                out.insert(key, val);
            }
            "__type" => {
                let name = arg_val(f, "name", vars)
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                let val = resolve_introspection_type(&name, fragments, &f.selections, errors);
                out.insert(key, val);
            }
            "repository" => {
                let owner = arg_val(f, "owner", vars)
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                let name = arg_val(f, "name", vars)
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                if let Some((owner_login, repo_arc)) = store.get_repo(&owner, &name) {
                    let repo = repo_arc.read().unwrap();
                    let val = resolve_repository(
                        &owner_login,
                        &repo,
                        fragments,
                        vars,
                        &f.selections,
                        errors,
                    );
                    out.insert(key, val);
                } else {
                    out.insert(key, Value::Null);
                }
            }
            "node" => {
                let id = arg_val(f, "id", vars)
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                if let Some((owner_login, repo_arc)) = store.get_repo_by_gid(&id) {
                    let repo = repo_arc.read().unwrap();
                    let val = resolve_repository(
                        &owner_login,
                        &repo,
                        fragments,
                        vars,
                        &f.selections,
                        errors,
                    );
                    out.insert(key, val);
                } else if let Some((repo_arc, num)) = store.get_repo_for_issue_gid(&id) {
                    let repo = repo_arc.read().unwrap();
                    if let Some(issue) = num.checked_sub(1).and_then(|i| repo.issues.get(i as usize))
                    {
                        out.insert(
                            key,
                            resolve_issue(issue, fragments, &f.selections, errors),
                        );
                    } else {
                        out.insert(key, Value::Null);
                    }
                } else if let Some((_owner_login, repo_arc, num)) = store.get_repo_for_pr_gid(&id)
                {
                    let repo = repo_arc.read().unwrap();
                    if let Some(pr) = num.checked_sub(1).and_then(|i| repo.pulls.get(i as usize)) {
                        out.insert(
                            key,
                            resolve_pull(&repo, pr, fragments, vars, &f.selections, errors),
                        );
                    } else {
                        out.insert(key, Value::Null);
                    }
                } else {
                    out.insert(key, Value::Null);
                }
            }
            other => unknown_field(errors, other, "Query"),
        }
    }
    Value::Object(out)
}

fn resolve_user(
    login: &str,
    fragments: &FxHashMap<String, Vec<Selection>>,
    selections: &[Selection],
    errors: &mut Vec<Value>,
) -> Value {
    let mut out = Map::new();
    for f in expand_selections(selections, "User", fragments) {
        let key = f.key().to_owned();
        match f.name.as_str() {
            "__typename" => {
                out.insert(key, Value::String("User".to_owned()));
            }
            "login" => {
                out.insert(key, Value::String(login.to_owned()));
            }
            "id" => {
                out.insert(key, Value::String("U_3e8".to_owned()));
            }
            other => unknown_field(errors, other, "User"),
        }
    }
    Value::Object(out)
}

fn resolve_introspection_type(
    type_name: &str,
    fragments: &FxHashMap<String, Vec<Selection>>,
    selections: &[Selection],
    errors: &mut Vec<Value>,
) -> Value {
    let fields: Option<&[&str]> = match type_name {
        "Issue" => Some(&["id", "number", "title", "state", "body", "comments"]),
        "PullRequest" => Some(&[
            "id",
            "number",
            "headRefName",
            "baseRefName",
            "mergeable",
            "state",
            "merged",
            "files",
            "title",
            "body",
        ]),
        "Repository" => Some(&[
            "id",
            "databaseId",
            "name",
            "nameWithOwner",
            "owner",
            "defaultBranchRef",
            "viewerPermission",
            "hasIssuesEnabled",
            "issue",
            "issues",
            "pullRequests",
            "pullRequest",
        ]),
        "User" => Some(&["id", "login"]),
        _ => None,
    };
    let enums: Option<&[&str]> = match type_name {
        "SearchType" => Some(&["ISSUE", "REPOSITORY", "USER", "DISCUSSION"]),
        _ => None,
    };
    if fields.is_none() && enums.is_none() {
        return Value::Null;
    }

    let mut out = Map::new();
    for f in expand_selections(selections, "__Type", fragments) {
        let key = f.key().to_owned();
        match f.name.as_str() {
            "name" => {
                out.insert(key, Value::String(type_name.to_owned()));
            }
            "fields" => {
                if let Some(list) = fields {
                    let arr: Vec<Value> = list
                        .iter()
                        .map(|n| {
                            let mut item = Map::new();
                            for sf in expand_selections(&f.selections, "__Field", fragments) {
                                if sf.name == "name" {
                                    item.insert(
                                        sf.key().to_owned(),
                                        Value::String((*n).to_owned()),
                                    );
                                }
                            }
                            Value::Object(item)
                        })
                        .collect();
                    out.insert(key, Value::Array(arr));
                } else {
                    out.insert(key, Value::Null);
                }
            }
            "enumValues" => {
                if let Some(list) = enums {
                    let arr: Vec<Value> = list
                        .iter()
                        .map(|n| {
                            let mut item = Map::new();
                            for sf in expand_selections(&f.selections, "__EnumValue", fragments) {
                                if sf.name == "name" {
                                    item.insert(
                                        sf.key().to_owned(),
                                        Value::String((*n).to_owned()),
                                    );
                                }
                            }
                            Value::Object(item)
                        })
                        .collect();
                    out.insert(key, Value::Array(arr));
                } else {
                    out.insert(key, Value::Null);
                }
            }
            other => unknown_field(errors, other, "__Type"),
        }
    }
    Value::Object(out)
}

fn resolve_repository(
    owner: &str,
    repo: &crate::store::Repo,
    fragments: &FxHashMap<String, Vec<Selection>>,
    vars: &Map<String, Value>,
    selections: &[Selection],
    errors: &mut Vec<Value>,
) -> Value {
    let mut out = Map::new();
    for f in expand_selections(selections, "Repository", fragments) {
        let key = f.key().to_owned();
        match f.name.as_str() {
            "__typename" => {
                out.insert(key, Value::String("Repository".to_owned()));
            }
            "id" => {
                out.insert(key, Value::String(repo.global_id.clone()));
            }
            "databaseId" => {
                out.insert(key, json!(repo.id));
            }
            "name" => {
                out.insert(key, Value::String(repo.name.clone()));
            }
            "nameWithOwner" => {
                out.insert(key, Value::String(format!("{}/{}", owner, repo.name)));
            }
            "owner" => {
                out.insert(key, resolve_user(owner, fragments, &f.selections, errors));
            }
            "defaultBranchRef" => {
                let mut m = Map::new();
                for sf in expand_selections(&f.selections, "Ref", fragments) {
                    if sf.name == "name" {
                        m.insert(
                            sf.key().to_owned(),
                            Value::String(repo.default_branch.clone()),
                        );
                    }
                }
                out.insert(key, Value::Object(m));
            }
            "viewerPermission" => {
                out.insert(key, Value::String("ADMIN".to_owned()));
            }
            "hasIssuesEnabled" => {
                out.insert(key, Value::Bool(true));
            }
            "issue" => {
                let num = arg_val(f, "number", vars)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let val = match num.checked_sub(1).and_then(|i| repo.issues.get(i as usize)) {
                    Some(issue) => resolve_issue(issue, fragments, &f.selections, errors),
                    None => Value::Null,
                };
                out.insert(key, val);
            }
            "issues" => {
                let first = arg_val(f, "first", vars)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100) as usize;
                let after = arg_val(f, "after", vars)
                    .and_then(|v| v.as_str().map(str::to_owned));
                let states_filter: Option<Vec<String>> = arg_val(f, "states", vars).and_then(|v| {
                    v.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(str::to_owned))
                            .collect()
                    })
                });
                let desc = arg_val(f, "orderBy", vars)
                    .and_then(|v| {
                        v.get("direction")
                            .and_then(|d| d.as_str())
                            .map(|s| s == "DESC")
                    })
                    .unwrap_or(false);

                let mut list: Vec<&crate::store::Issue> = repo
                    .issues
                    .iter()
                    .filter(|i| match &states_filter {
                        Some(st) if !st.is_empty() => {
                            st.iter().any(|s| s == i.state.graphql_str())
                        }
                        _ => true,
                    })
                    .collect();

                if desc {
                    list.sort_by(|a, b| (b.seq, b.number).cmp(&(a.seq, a.number)));
                } else {
                    list.sort_by_key(|a| (a.seq, a.number));
                }

                let start_idx = after
                    .as_deref()
                    .and_then(|c| c.strip_prefix("c_"))
                    .and_then(|s| s.parse::<usize>().ok())
                    .map(|idx| idx + 1)
                    .unwrap_or(0);
                let end_idx = start_idx.saturating_add(first).min(list.len());
                let slice = if start_idx < list.len() {
                    &list[start_idx..end_idx]
                } else {
                    &[]
                };
                let has_next = end_idx < list.len();
                let end_cursor = if slice.is_empty() {
                    Value::Null
                } else {
                    Value::String(format!("c_{}", end_idx - 1))
                };

                let mut conn = Map::new();
                for sf in expand_selections(&f.selections, "IssueConnection", fragments) {
                    let skey = sf.key().to_owned();
                    match sf.name.as_str() {
                        "nodes" => {
                            let nodes = slice
                                .iter()
                                .map(|iss| resolve_issue(iss, fragments, &sf.selections, errors))
                                .collect();
                            conn.insert(skey, Value::Array(nodes));
                        }
                        "pageInfo" => {
                            let mut pi = Map::new();
                            for pf in expand_selections(&sf.selections, "PageInfo", fragments) {
                                match pf.name.as_str() {
                                    "hasNextPage" => {
                                        pi.insert(pf.key().to_owned(), Value::Bool(has_next));
                                    }
                                    "endCursor" => {
                                        pi.insert(pf.key().to_owned(), end_cursor.clone());
                                    }
                                    _ => {}
                                }
                            }
                            conn.insert(skey, Value::Object(pi));
                        }
                        "totalCount" => {
                            conn.insert(skey, json!(list.len()));
                        }
                        other => unknown_field(errors, other, "IssueConnection"),
                    }
                }
                out.insert(key, Value::Object(conn));
            }
            "pullRequests" => {
                let first = arg_val(f, "first", vars)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100) as usize;
                let slice: Vec<&PullRequest> = repo
                    .pulls
                    .iter()
                    .filter(|p| p.state == IssueState::Open)
                    .take(first)
                    .collect();
                let mut conn = Map::new();
                for sf in expand_selections(&f.selections, "PullRequestConnection", fragments) {
                    let skey = sf.key().to_owned();
                    match sf.name.as_str() {
                        "nodes" => {
                            let nodes = slice
                                .iter()
                                .map(|pr| {
                                    resolve_pull(repo, pr, fragments, vars, &sf.selections, errors)
                                })
                                .collect();
                            conn.insert(skey, Value::Array(nodes));
                        }
                        other => unknown_field(errors, other, "PullRequestConnection"),
                    }
                }
                out.insert(key, Value::Object(conn));
            }
            "pullRequest" => {
                let num = arg_val(f, "number", vars)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let val = match num.checked_sub(1).and_then(|i| repo.pulls.get(i as usize)) {
                    Some(pr) => resolve_pull(repo, pr, fragments, vars, &f.selections, errors),
                    None => Value::Null,
                };
                out.insert(key, val);
            }
            other => unknown_field(errors, other, "Repository"),
        }
    }
    Value::Object(out)
}

fn resolve_issue(
    issue: &crate::store::Issue,
    fragments: &FxHashMap<String, Vec<Selection>>,
    selections: &[Selection],
    errors: &mut Vec<Value>,
) -> Value {
    let mut out = Map::new();
    for f in expand_selections(selections, "Issue", fragments) {
        let key = f.key().to_owned();
        match f.name.as_str() {
            "__typename" => {
                out.insert(key, Value::String("Issue".to_owned()));
            }
            "id" => {
                out.insert(key, Value::String(issue.global_id.clone()));
            }
            "number" => {
                out.insert(key, json!(issue.number));
            }
            "title" => {
                out.insert(key, Value::String(issue.title.clone()));
            }
            "body" => {
                out.insert(key, Value::String(issue.body.clone()));
            }
            "state" => {
                out.insert(key, Value::String(issue.state.graphql_str().to_owned()));
            }
            other => unknown_field(errors, other, "Issue"),
        }
    }
    Value::Object(out)
}

fn resolve_pull(
    repo: &crate::store::Repo,
    pr: &PullRequest,
    fragments: &FxHashMap<String, Vec<Selection>>,
    vars: &Map<String, Value>,
    selections: &[Selection],
    errors: &mut Vec<Value>,
) -> Value {
    let mut out = Map::new();
    for f in expand_selections(selections, "PullRequest", fragments) {
        let key = f.key().to_owned();
        match f.name.as_str() {
            "__typename" => {
                out.insert(key, Value::String("PullRequest".to_owned()));
            }
            "id" => {
                out.insert(key, Value::String(pr.global_id.clone()));
            }
            "number" => {
                out.insert(key, json!(pr.number));
            }
            "title" => {
                out.insert(key, Value::String(pr.title.clone()));
            }
            "body" => {
                out.insert(key, Value::String(pr.body.clone()));
            }
            "headRefName" => {
                out.insert(key, Value::String(pr.head_ref.clone()));
            }
            "baseRefName" => {
                out.insert(key, Value::String(pr.base_ref.clone()));
            }
            "merged" => {
                out.insert(key, Value::Bool(pr.merged));
            }
            "state" => {
                let st = if pr.merged {
                    "MERGED"
                } else {
                    pr.state.graphql_str()
                };
                out.insert(key, Value::String(st.to_owned()));
            }
            "mergeable" => {
                let m = if repo.is_pr_conflicting(pr) {
                    "CONFLICTING"
                } else {
                    "MERGEABLE"
                };
                out.insert(key, Value::String(m.to_owned()));
            }
            "files" => {
                let first = arg_val(f, "first", vars)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100) as usize;
                let files = repo.diff_pr_files(pr);
                let mut conn = Map::new();
                for sf in expand_selections(&f.selections, "PullRequestChangedFileConnection", fragments)
                {
                    if sf.name == "nodes" {
                        let nodes: Vec<Value> = files
                            .iter()
                            .take(first)
                            .map(|cf| {
                                let mut fm = Map::new();
                                for ff in
                                    expand_selections(&sf.selections, "PullRequestChangedFile", fragments)
                                {
                                    match ff.name.as_str() {
                                        "path" => {
                                            fm.insert(
                                                ff.key().to_owned(),
                                                Value::String(cf.filename.clone()),
                                            );
                                        }
                                        "additions" => {
                                            fm.insert(ff.key().to_owned(), json!(cf.additions));
                                        }
                                        "deletions" => {
                                            fm.insert(ff.key().to_owned(), json!(cf.deletions));
                                        }
                                        _ => {}
                                    }
                                }
                                Value::Object(fm)
                            })
                            .collect();
                        conn.insert(sf.key().to_owned(), Value::Array(nodes));
                    }
                }
                out.insert(key, Value::Object(conn));
            }
            other => unknown_field(errors, other, "PullRequest"),
        }
    }
    Value::Object(out)
}

fn exec_mutation(
    store: &Store,
    fragments: &FxHashMap<String, Vec<Selection>>,
    vars: &Map<String, Value>,
    selections: &[Selection],
    errors: &mut Vec<Value>,
) -> Value {
    let mut out = Map::new();
    for f in expand_selections(selections, "Mutation", fragments) {
        let key = f.key().to_owned();
        let input = arg_val(f, "input", vars).unwrap_or(Value::Null);
        match f.name.as_str() {
            "createIssue" => {
                let repo_id = input
                    .get("repositoryId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let title = input
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let body = input
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let Some((_owner, repo_arc)) = store.get_repo_by_gid(repo_id) else {
                    errors.push(json!({ "message": "Repository not found" }));
                    return Value::Null;
                };
                let mut repo = repo_arc.write().unwrap();
                let id = store.next_issue_id.fetch_add(1, Ordering::Relaxed);
                let number = (repo.issues.len() + 1) as u32;
                let issue = crate::store::Issue {
                    id,
                    global_id: format!("I_{:x}_{:x}", repo.id, number),
                    number,
                    title,
                    body,
                    state: IssueState::Open,
                    labels: Vec::new(),
                    comments: Vec::new(),
                    seq: id,
                };
                let mut payload = Map::new();
                for sf in expand_selections(&f.selections, "CreateIssuePayload", fragments) {
                    if sf.name == "issue" {
                        payload.insert(
                            sf.key().to_owned(),
                            resolve_issue(&issue, fragments, &sf.selections, errors),
                        );
                    }
                }
                repo.issues.push(issue);
                repo.issue_http_cache.push(None);
                out.insert(key, Value::Object(payload));
            }
            "closeIssue" => {
                let issue_id = input
                    .get("issueId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let Some((repo_arc, num)) = store.get_repo_for_issue_gid(issue_id) else {
                    errors.push(json!({ "message": "Issue not found" }));
                    return Value::Null;
                };
                let mut repo = repo_arc.write().unwrap();
                let Some(idx) = num.checked_sub(1).map(|i| i as usize) else {
                    errors.push(json!({ "message": "Issue not found" }));
                    return Value::Null;
                };
                if idx >= repo.issues.len() {
                    errors.push(json!({ "message": "Issue not found" }));
                    return Value::Null;
                }
                repo.issues[idx].state = IssueState::Closed;
                let iss_val = {
                    let iss = &repo.issues[idx];
                    let mut payload = Map::new();
                    for sf in expand_selections(&f.selections, "CloseIssuePayload", fragments) {
                        if sf.name == "issue" {
                            payload.insert(
                                sf.key().to_owned(),
                                resolve_issue(iss, fragments, &sf.selections, errors),
                            );
                        }
                    }
                    Value::Object(payload)
                };
                repo.invalidate_issue_cache(num);
                out.insert(key, iss_val);
            }
            "createPullRequest" => {
                let repo_id = input
                    .get("repositoryId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let base_ref = input
                    .get("baseRefName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let head_ref = input
                    .get("headRefName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let title = input
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let body = input
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let Some((_owner, repo_arc)) = store.get_repo_by_gid(repo_id) else {
                    errors.push(json!({ "message": "Repository not found" }));
                    return Value::Null;
                };
                let mut repo = repo_arc.write().unwrap();
                let Some(head_sha) = repo.refs.get(&format!("refs/heads/{}", head_ref)).copied()
                else {
                    errors.push(json!({ "message": "Head branch not found" }));
                    return Value::Null;
                };
                let Some(base_sha) = repo.refs.get(&format!("refs/heads/{}", base_ref)).copied()
                else {
                    errors.push(json!({ "message": "Base branch not found" }));
                    return Value::Null;
                };
                let id = store.next_pr_id.fetch_add(1, Ordering::Relaxed);
                let number = (repo.pulls.len() + 1) as u32;
                let pr = PullRequest {
                    id,
                    global_id: format!("PR_{:x}_{:x}", repo.id, number),
                    number,
                    title,
                    body,
                    state: IssueState::Open,
                    head_ref,
                    head_sha,
                    base_ref,
                    base_sha,
                    merged: false,
                    merged_at: None,
                    merge_commit_sha: None,
                };
                let mut payload = Map::new();
                for sf in expand_selections(&f.selections, "CreatePullRequestPayload", fragments) {
                    if sf.name == "pullRequest" {
                        payload.insert(
                            sf.key().to_owned(),
                            resolve_pull(&repo, &pr, fragments, vars, &sf.selections, errors),
                        );
                    }
                }
                repo.pulls.push(pr);
                out.insert(key, Value::Object(payload));
            }
            "mergePullRequest" => {
                let pr_id = input
                    .get("pullRequestId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let Some((owner_login, repo_arc, num)) = store.get_repo_for_pr_gid(pr_id) else {
                    errors.push(json!({ "message": "PullRequest not found" }));
                    return Value::Null;
                };
                let mut repo = repo_arc.write().unwrap();
                match repo.squash_merge_pr(num, &store.commit_seq, None, &owner_login) {
                    Ok(_sha) => {
                        let pr = &repo.pulls[(num - 1) as usize];
                        let mut payload = Map::new();
                        for sf in
                            expand_selections(&f.selections, "MergePullRequestPayload", fragments)
                        {
                            if sf.name == "pullRequest" {
                                payload.insert(
                                    sf.key().to_owned(),
                                    resolve_pull(
                                        &repo,
                                        pr,
                                        fragments,
                                        vars,
                                        &sf.selections,
                                        errors,
                                    ),
                                );
                            }
                        }
                        out.insert(key, Value::Object(payload));
                    }
                    Err(MergeError::NotFound) => {
                        errors.push(json!({ "message": "PullRequest not found" }));
                        return Value::Null;
                    }
                    Err(MergeError::Conflict) => {
                        errors.push(json!({ "message": "Merge conflict" }));
                        return Value::Null;
                    }
                }
            }
            "addComment" => {
                let subject_id = input
                    .get("subjectId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let body = input
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let Some((repo_arc, num)) = store.get_repo_for_issue_gid(subject_id) else {
                    errors.push(json!({ "message": "Subject not found" }));
                    return Value::Null;
                };
                let mut repo = repo_arc.write().unwrap();
                let Some(issue) = num
                    .checked_sub(1)
                    .and_then(|i| repo.issues.get_mut(i as usize))
                else {
                    errors.push(json!({ "message": "Issue not found" }));
                    return Value::Null;
                };
                let cid = store.next_comment_id.fetch_add(1, Ordering::Relaxed);
                let gid = format!("C_{:x}", cid);
                issue.comments.push(Comment {
                    id: cid,
                    global_id: gid.clone(),
                    body: body.clone(),
                });
                let mut payload = Map::new();
                for sf in expand_selections(&f.selections, "AddCommentPayload", fragments) {
                    if sf.name == "commentEdge" {
                        let mut edge = Map::new();
                        for ef in expand_selections(&sf.selections, "IssueCommentEdge", fragments)
                        {
                            if ef.name == "node" {
                                let mut node = Map::new();
                                for nf in
                                    expand_selections(&ef.selections, "IssueComment", fragments)
                                {
                                    match nf.name.as_str() {
                                        "id" => {
                                            node.insert(
                                                nf.key().to_owned(),
                                                Value::String(gid.clone()),
                                            );
                                        }
                                        "body" => {
                                            node.insert(
                                                nf.key().to_owned(),
                                                Value::String(body.clone()),
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                                edge.insert(ef.key().to_owned(), Value::Object(node));
                            }
                        }
                        payload.insert(sf.key().to_owned(), Value::Object(edge));
                    }
                }
                out.insert(key, Value::Object(payload));
            }
            other => {
                unknown_field(errors, other, "Mutation");
                let _ = oid_hex_string;
            }
        }
    }
    Value::Object(out)
}
