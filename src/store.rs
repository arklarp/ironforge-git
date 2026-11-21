use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use rustc_hash::{FxHashMap, FxHashSet};
use sha1::{Digest, Sha1};

use crate::http::build_preframed_http;
use crate::util::{
    Oid, OidMap, OidSet, ZERO_OID, hex_to_oid, write_json_str, write_oid_hex,
    write_u32_ascii, write_u64_ascii,
};

pub const SCENARIO_EPOCH_SEC: u64 = 1_735_689_600;
pub const DEFAULT_BRANCH: &str = "main";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl ObjType {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
        }
    }

    #[inline]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct GitObj {
    pub kind: ObjType,
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct SmallParents {
    len: u8,
    inline: [Oid; 2],
    extra: Option<Box<[Oid]>>,
}

impl SmallParents {
    #[inline]
    pub fn new() -> Self {
        Self {
            len: 0,
            inline: [ZERO_OID; 2],
            extra: None,
        }
    }

    #[inline]
    pub fn push(&mut self, oid: Oid) {
        if self.len == 0 {
            self.inline[0] = oid;
            self.len = 1;
        } else if self.len == 1 {
            self.inline[1] = oid;
            self.len = 2;
        } else {
            let mut v = if let Some(ref ex) = self.extra {
                ex.to_vec()
            } else {
                vec![self.inline[0], self.inline[1]]
            };
            v.push(oid);
            self.len = 255;
            self.extra = Some(v.into_boxed_slice());
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[Oid] {
        match &self.extra {
            Some(ex) => ex,
            None => &self.inline[..(self.len as usize)],
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn contains(&self, target: &Oid) -> bool {
        self.as_slice().iter().any(|p| p == target)
    }
}

#[derive(Clone)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    pub oid: Oid,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IssueState {
    Open,
    Closed,
}

impl IssueState {
    #[inline]
    pub fn rest_str(self) -> &'static str {
        match self {
            IssueState::Open => "open",
            IssueState::Closed => "closed",
        }
    }

    #[inline]
    pub fn graphql_str(self) -> &'static str {
        match self {
            IssueState::Open => "OPEN",
            IssueState::Closed => "CLOSED",
        }
    }
}

#[derive(Clone)]
pub struct Comment {
    pub id: u64,
    pub global_id: String,
    pub body: String,
}

#[derive(Clone)]
pub struct Issue {
    pub id: u64,
    pub global_id: String,
    pub number: u32,
    pub title: String,
    pub body: String,
    pub state: IssueState,
    pub labels: Vec<String>,
    pub comments: Vec<Comment>,
    pub seq: u64,
}

#[derive(Clone)]
pub struct PullRequest {
    pub id: u64,
    pub global_id: String,
    pub number: u32,
    pub title: String,
    pub body: String,
    pub state: IssueState,
    pub head_ref: String,
    pub head_sha: Oid,
    pub base_ref: String,
    pub base_sha: Oid,
    pub merged: bool,
    pub merged_at: Option<&'static str>,
    pub merge_commit_sha: Option<Oid>,
}

pub struct ChangedFile {
    pub filename: String,
    pub status: &'static str,
    pub additions: usize,
    pub deletions: usize,
    pub changes: usize,
}

pub enum MergeError {
    NotFound,
    Conflict,
}

pub struct ReceiveRefsCache {
    pub bytes: Vec<u8>,
    pub single_ref_name: Option<String>,
    pub oid_offset: usize,
}

pub struct Repo {
    pub id: u64,
    pub global_id: String,
    pub name: String,
    pub private: bool,
    pub description: String,
    pub default_branch: String,
    pub objects: OidMap<GitObj>,
    pub commit_parents: OidMap<SmallParents>,
    pub commit_trees: OidMap<Oid>,
    pub refs: BTreeMap<String, Oid>,
    pub labels: FxHashMap<String, String>,
    pub issues: Vec<Issue>,
    pub issue_http_cache: Vec<Option<Arc<[u8]>>>,
    pub pulls: Vec<PullRequest>,
    pub cache_ls_refs_full: Option<Arc<[u8]>>,
    pub cache_fetch_depth1: Option<(Oid, Arc<[u8]>)>,
    pub cache_receive_refs: Option<ReceiveRefsCache>,
}

impl Repo {
    pub fn new(id: u64, name: String, private: bool, description: String) -> Self {
        Self {
            id,
            global_id: format!("R_{:x}", id),
            name,
            private,
            description,
            default_branch: DEFAULT_BRANCH.to_owned(),
            objects: OidMap::default(),
            commit_parents: OidMap::default(),
            commit_trees: OidMap::default(),
            refs: BTreeMap::new(),
            labels: FxHashMap::default(),
            issues: Vec::new(),
            issue_http_cache: Vec::new(),
            pulls: Vec::new(),
            cache_ls_refs_full: None,
            cache_fetch_depth1: None,
            cache_receive_refs: None,
        }
    }

    #[inline]
    pub fn invalidate_git_caches(&mut self) {
        self.cache_ls_refs_full = None;
        self.cache_fetch_depth1 = None;
        self.cache_receive_refs = None;
    }

    #[inline]
    pub fn put_object(&mut self, kind: ObjType, data: Vec<u8>) -> Oid {
        let oid = hash_object(kind, &data);
        if !self.objects.contains_key(&oid) {
            self.insert_known_object(oid, kind, data);
        }
        oid
    }

    #[inline]
    pub fn insert_known_object(&mut self, oid: Oid, kind: ObjType, data: Vec<u8>) {
        if kind == ObjType::Commit {
            let (tree, parents) = parse_commit_meta(&data);
            if let Some(t) = tree {
                self.commit_trees.insert(oid, t);
            }
            self.commit_parents.insert(oid, parents);
        }
        self.objects.insert(oid, GitObj { kind, data });
    }

    pub fn peel_oid(&self, mut oid: Oid) -> Option<Oid> {
        for _ in 0..16 {
            let obj = self.objects.get(&oid)?;
            if obj.kind == ObjType::Tag {
                oid = parse_tag_target(&obj.data)?;
            } else {
                return Some(oid);
            }
        }
        None
    }

    pub fn resolve_ref_oid(&self, spec: &str) -> Option<Oid> {
        if let Some(oid) = hex_to_oid(spec.as_bytes()) {
            if self.objects.contains_key(&oid) {
                return Some(oid);
            }
        }
        if let Some(&oid) = self.refs.get(spec) {
            return Some(oid);
        }
        let head_ref = format!("refs/heads/{}", spec);
        if let Some(&oid) = self.refs.get(&head_ref) {
            return Some(oid);
        }
        let tag_ref = format!("refs/tags/{}", spec);
        if let Some(&oid) = self.refs.get(&tag_ref) {
            return self.peel_oid(oid);
        }
        None
    }

    #[inline]
    pub fn is_ancestor(&self, ancestor: Oid, descendant: Oid) -> bool {
        if ancestor == descendant {
            return true;
        }
        if let Some(parents) = self.commit_parents.get(&descendant) {
            if parents.contains(&ancestor) {
                return true;
            }
        }
        let mut seen = OidSet::default();
        let mut queue = Vec::with_capacity(32);
        seen.insert(descendant);
        queue.push(descendant);
        let mut idx = 0;
        while idx < queue.len() {
            let cur = queue[idx];
            idx += 1;
            if let Some(parents) = self.commit_parents.get(&cur) {
                for &p in parents.as_slice() {
                    if p == ancestor {
                        return true;
                    }
                    if seen.insert(p) {
                        queue.push(p);
                    }
                }
            }
        }
        false
    }

    pub fn merge_base(&self, a: Oid, b: Oid) -> Option<Oid> {
        if a == b {
            return Some(a);
        }
        let mut anc_a = OidSet::default();
        let mut qa = vec![a];
        anc_a.insert(a);
        let mut ia = 0;
        while ia < qa.len() {
            let cur = qa[ia];
            ia += 1;
            if let Some(parents) = self.commit_parents.get(&cur) {
                for &p in parents.as_slice() {
                    if anc_a.insert(p) {
                        qa.push(p);
                    }
                }
            }
        }

        let mut seen_b = OidSet::default();
        let mut qb = vec![b];
        seen_b.insert(b);
        let mut ib = 0;
        while ib < qb.len() {
            let cur = qb[ib];
            ib += 1;
            if anc_a.contains(&cur) {
                return Some(cur);
            }
            if let Some(parents) = self.commit_parents.get(&cur) {
                for &p in parents.as_slice() {
                    if seen_b.insert(p) {
                        qb.push(p);
                    }
                }
            }
        }
        None
    }

    pub fn flatten_commit_tree(&self, commit_oid: Oid) -> BTreeMap<String, (String, Oid)> {
        let mut out = BTreeMap::new();
        if let Some(&tree_oid) = self.commit_trees.get(&commit_oid) {
            self.flatten_tree_rec(tree_oid, "", &mut out);
        }
        out
    }

    fn flatten_tree_rec(
        &self,
        tree_oid: Oid,
        prefix: &str,
        out: &mut BTreeMap<String, (String, Oid)>,
    ) {
        let Some(obj) = self.objects.get(&tree_oid) else {
            return;
        };
        if obj.kind != ObjType::Tree {
            return;
        }
        for entry in parse_tree(&obj.data) {
            let full = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", prefix, entry.name)
            };
            if entry.mode == "40000" {
                self.flatten_tree_rec(entry.oid, &full, out);
            } else {
                out.insert(full, (entry.mode, entry.oid));
            }
        }
    }

    pub fn build_tree_from_flat(&mut self, files: &BTreeMap<String, (String, Oid)>) -> Oid {
        struct DirNode {
            files: Vec<(String, String, Oid)>,
            dirs: BTreeMap<String, DirNode>,
        }
        impl DirNode {
            fn new() -> Self {
                Self {
                    files: Vec::new(),
                    dirs: BTreeMap::new(),
                }
            }
        }
        let mut root = DirNode::new();
        for (path, (mode, oid)) in files {
            let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                continue;
            }
            let mut node = &mut root;
            for &dir in &parts[..parts.len() - 1] {
                node = node.dirs.entry(dir.to_owned()).or_insert_with(DirNode::new);
            }
            node.files
                .push((parts[parts.len() - 1].to_owned(), mode.clone(), *oid));
        }

        fn build_node(repo: &mut Repo, node: DirNode) -> Oid {
            let mut entries = Vec::with_capacity(node.files.len() + node.dirs.len());
            for (name, mode, oid) in node.files {
                entries.push(TreeEntry { mode, name, oid });
            }
            for (name, child) in node.dirs {
                let child_oid = build_node(repo, child);
                entries.push(TreeEntry {
                    mode: "40000".to_owned(),
                    name,
                    oid: child_oid,
                });
            }
            let raw = build_tree(&mut entries);
            repo.put_object(ObjType::Tree, raw)
        }

        build_node(self, root)
    }

    pub fn find_tree_entry_at_path(&self, tree_oid: Oid, segments: &[&str]) -> Option<(String, Oid)> {
        if segments.is_empty() {
            return Some(("40000".to_owned(), tree_oid));
        }
        let obj = self.objects.get(&tree_oid)?;
        if obj.kind != ObjType::Tree {
            return None;
        }
        let entries = parse_tree(&obj.data);
        let target = segments[0];
        let found = entries.into_iter().find(|e| e.name == target)?;
        if segments.len() == 1 {
            Some((found.mode, found.oid))
        } else if found.mode == "40000" {
            self.find_tree_entry_at_path(found.oid, &segments[1..])
        } else {
            None
        }
    }

    pub fn diff_pr_files(&self, pr: &PullRequest) -> Vec<ChangedFile> {
        let head_tip = self
            .refs
            .get(&format!("refs/heads/{}", pr.head_ref))
            .copied()
            .unwrap_or(pr.head_sha);
        let base_tip = self
            .refs
            .get(&format!("refs/heads/{}", pr.base_ref))
            .copied()
            .unwrap_or(pr.base_sha);
        let compare_commit = self.merge_base(base_tip, head_tip).unwrap_or(pr.base_sha);

        let base_map = self.flatten_commit_tree(compare_commit);
        let head_map = self.flatten_commit_tree(head_tip);

        let mut all_paths: FxHashSet<&str> = FxHashSet::default();
        for k in base_map.keys() {
            all_paths.insert(k.as_str());
        }
        for k in head_map.keys() {
            all_paths.insert(k.as_str());
        }
        let mut sorted: Vec<&str> = all_paths.into_iter().collect();
        sorted.sort_unstable();

        let mut out = Vec::new();
        for path in sorted {
            let b = base_map.get(path);
            let h = head_map.get(path);
            match (b, h) {
                (None, Some((_, h_oid))) => {
                    let lines = self.blob_line_count(*h_oid).max(1);
                    out.push(ChangedFile {
                        filename: path.to_owned(),
                        status: "added",
                        additions: lines,
                        deletions: 0,
                        changes: lines,
                    });
                }
                (Some((_, b_oid)), None) => {
                    let lines = self.blob_line_count(*b_oid).max(1);
                    out.push(ChangedFile {
                        filename: path.to_owned(),
                        status: "removed",
                        additions: 0,
                        deletions: lines,
                        changes: lines,
                    });
                }
                (Some((_, b_oid)), Some((_, h_oid))) if b_oid != h_oid => {
                    let h_lines = self.blob_line_count(*h_oid).max(1);
                    let b_lines = self.blob_line_count(*b_oid).max(1);
                    out.push(ChangedFile {
                        filename: path.to_owned(),
                        status: "modified",
                        additions: h_lines,
                        deletions: b_lines,
                        changes: h_lines + b_lines,
                    });
                }
                _ => {}
            }
        }
        out
    }

    fn blob_line_count(&self, oid: Oid) -> usize {
        let Some(obj) = self.objects.get(&oid) else {
            return 0;
        };
        if obj.data.is_empty() {
            return 0;
        }
        let mut lines = obj.data.iter().filter(|&&b| b == b'\n').count();
        if !obj.data.ends_with(b"\n") {
            lines += 1;
        }
        lines
    }

    pub fn is_pr_conflicting(&self, pr: &PullRequest) -> bool {
        let base_ref = format!("refs/heads/{}", pr.base_ref);
        let head_ref = format!("refs/heads/{}", pr.head_ref);
        let base_tip = self.refs.get(&base_ref).copied().unwrap_or(pr.base_sha);
        let head_tip = self.refs.get(&head_ref).copied().unwrap_or(pr.head_sha);
        let base_map = self.flatten_commit_tree(base_tip);
        let head_map = self.flatten_commit_tree(head_tip);
        let lca_map = match self.merge_base(base_tip, head_tip) {
            Some(lca) => self.flatten_commit_tree(lca),
            None => BTreeMap::new(),
        };
        let mut keys: FxHashSet<&str> = FxHashSet::default();
        for k in base_map.keys() {
            keys.insert(k.as_str());
        }
        for k in head_map.keys() {
            keys.insert(k.as_str());
        }
        for k in keys {
            let o = lca_map.get(k);
            let b = base_map.get(k);
            let h = head_map.get(k);
            if b != h && b != o && h != o {
                return true;
            }
        }
        false
    }

    pub fn squash_merge_pr(
        &mut self,
        pr_number: u32,
        commit_seq: &AtomicU64,
        commit_title: Option<&str>,
        owner_login: &str,
    ) -> Result<Oid, MergeError> {
        let idx = match pr_number.checked_sub(1) {
            Some(i) if (i as usize) < self.pulls.len() => i as usize,
            _ => return Err(MergeError::NotFound),
        };
        if self.pulls[idx].merged || self.pulls[idx].state == IssueState::Closed {
            return Err(MergeError::Conflict);
        }
        let base_ref_name = self.pulls[idx].base_ref.clone();
        let head_ref_name = self.pulls[idx].head_ref.clone();
        let pr_title = self.pulls[idx].title.clone();
        let pr_base_sha = self.pulls[idx].base_sha;
        let pr_head_sha = self.pulls[idx].head_sha;

        let base_full_ref = format!("refs/heads/{}", base_ref_name);
        let head_full_ref = format!("refs/heads/{}", head_ref_name);
        let base_tip = self.refs.get(&base_full_ref).copied().unwrap_or(pr_base_sha);
        let head_tip = self.refs.get(&head_full_ref).copied().unwrap_or(pr_head_sha);

        let base_map = self.flatten_commit_tree(base_tip);
        let head_map = self.flatten_commit_tree(head_tip);
        let lca_map = match self.merge_base(base_tip, head_tip) {
            Some(lca) => self.flatten_commit_tree(lca),
            None => BTreeMap::new(),
        };

        let mut all_keys = BTreeMap::<String, ()>::new();
        for k in lca_map.keys() {
            all_keys.insert(k.clone(), ());
        }
        for k in base_map.keys() {
            all_keys.insert(k.clone(), ());
        }
        for k in head_map.keys() {
            all_keys.insert(k.clone(), ());
        }

        let mut merged_files = BTreeMap::new();
        for k in all_keys.keys() {
            let o = lca_map.get(k);
            let b = base_map.get(k);
            let h = head_map.get(k);
            if b == h {
                if let Some(val) = b {
                    merged_files.insert(k.clone(), val.clone());
                }
            } else if b == o {
                if let Some(val) = h {
                    merged_files.insert(k.clone(), val.clone());
                }
            } else if h == o {
                if let Some(val) = b {
                    merged_files.insert(k.clone(), val.clone());
                }
            } else {
                return Err(MergeError::Conflict);
            }
        }

        let merged_tree = self.build_tree_from_flat(&merged_files);
        let seq = commit_seq.fetch_add(1, Ordering::Relaxed);
        let msg = commit_title.unwrap_or(&pr_title);
        let parent_slice: &[Oid] = if base_tip == ZERO_OID { &[] } else { &[base_tip] };
        let commit_bytes = build_commit(
            merged_tree,
            parent_slice,
            owner_login,
            SCENARIO_EPOCH_SEC + seq,
            msg,
        );
        let squash_oid = self.put_object(ObjType::Commit, commit_bytes);
        self.refs.insert(base_full_ref, squash_oid);
        self.invalidate_git_caches();

        let pr = &mut self.pulls[idx];
        pr.state = IssueState::Closed;
        pr.merged = true;
        pr.merged_at = Some("2025-01-01T00:00:00Z");
        pr.merge_commit_sha = Some(squash_oid);
        Ok(squash_oid)
    }

    pub fn get_or_build_issue_http(&mut self, number: u32) -> Option<Arc<[u8]>> {
        let idx = number.checked_sub(1)? as usize;
        if idx >= self.issues.len() {
            return None;
        }
        if let Some(Some(cached)) = self.issue_http_cache.get(idx) {
            return Some(Arc::clone(cached));
        }
        let mut json = Vec::with_capacity(256);
        format_issue_json(&mut json, &self.issues[idx]);
        let frame = build_preframed_http(200, b"application/json", &json);
        if idx < self.issue_http_cache.len() {
            self.issue_http_cache[idx] = Some(Arc::clone(&frame));
        }
        Some(frame)
    }

    #[inline]
    pub fn invalidate_issue_cache(&mut self, number: u32) {
        if let Some(idx) = number.checked_sub(1) {
            if let Some(slot) = self.issue_http_cache.get_mut(idx as usize) {
                *slot = None;
            }
        }
    }
}

pub struct StoreInner {
    pub owner_login: String,
    pub repos: FxHashMap<String, Arc<RwLock<Repo>>>,
    pub repo_order: Vec<String>,
    pub repo_by_id: FxHashMap<u64, String>,
}

pub struct Store {
    pub token: String,
    pub inner: RwLock<StoreInner>,
    pub next_repo_id: AtomicU64,
    pub next_issue_id: AtomicU64,
    pub next_pr_id: AtomicU64,
    pub next_comment_id: AtomicU64,
    pub commit_seq: AtomicU64,
}

impl Store {
    pub fn new(token: String) -> Self {
        Self {
            token,
            inner: RwLock::new(StoreInner {
                owner_login: "adaiversen".to_owned(),
                repos: FxHashMap::default(),
                repo_order: Vec::new(),
                repo_by_id: FxHashMap::default(),
            }),
            next_repo_id: AtomicU64::new(1001),
            next_issue_id: AtomicU64::new(10001),
            next_pr_id: AtomicU64::new(20001),
            next_comment_id: AtomicU64::new(30001),
            commit_seq: AtomicU64::new(1),
        }
    }

    #[inline]
    pub fn check_auth(&self, auth: Option<&[u8]>) -> bool {
        let Some(hdr) = auth else {
            return self.token.is_empty();
        };
        if hdr.len() < 7 || !hdr[..6].eq_ignore_ascii_case(b"bearer") || hdr[6] != b' ' {
            return false;
        }
        let tok = &hdr[7..];
        if self.token.is_empty() {
            !tok.is_empty()
        } else {
            tok == self.token.as_bytes()
        }
    }

    #[inline]
    pub fn get_repo_arc(&self, owner: &str, name: &str) -> Option<Arc<RwLock<Repo>>> {
        let g = self.inner.read().unwrap();
        if owner != g.owner_login {
            return None;
        }
        g.repos.get(name).cloned()
    }

    pub fn get_repo(&self, owner: &str, name: &str) -> Option<(String, Arc<RwLock<Repo>>)> {
        let g = self.inner.read().unwrap();
        if owner != g.owner_login {
            return None;
        }
        let repo = g.repos.get(name)?.clone();
        Some((g.owner_login.clone(), repo))
    }

    pub fn create_repo(
        &self,
        name: String,
        private: bool,
        description: String,
    ) -> Result<(String, Arc<RwLock<Repo>>), ()> {
        let mut g = self.inner.write().unwrap();
        if g.repos.contains_key(&name) {
            return Err(());
        }
        let id = self.next_repo_id.fetch_add(1, Ordering::Relaxed);
        let owner = g.owner_login.clone();
        let repo = Arc::new(RwLock::new(Repo::new(id, name.clone(), private, description)));
        g.repos.insert(name.clone(), repo.clone());
        g.repo_order.push(name.clone());
        g.repo_by_id.insert(id, name);
        Ok((owner, repo))
    }

    pub fn delete_repo(&self, owner: &str, name: &str) -> bool {
        let mut g = self.inner.write().unwrap();
        if owner != g.owner_login {
            return false;
        }
        if let Some(repo) = g.repos.remove(name) {
            let id = repo.read().unwrap().id;
            g.repo_by_id.remove(&id);
            if let Some(pos) = g.repo_order.iter().position(|n| n == name) {
                g.repo_order.remove(pos);
            }
            true
        } else {
            false
        }
    }

    pub fn get_repo_by_gid(&self, gid: &str) -> Option<(String, Arc<RwLock<Repo>>)> {
        let id = decode_repo_gid(gid)?;
        let g = self.inner.read().unwrap();
        let name = g.repo_by_id.get(&id)?;
        let repo = g.repos.get(name)?.clone();
        Some((g.owner_login.clone(), repo))
    }

    pub fn get_repo_for_issue_gid(&self, gid: &str) -> Option<(Arc<RwLock<Repo>>, u32)> {
        let (repo_id, num) = decode_issue_gid(gid)?;
        let g = self.inner.read().unwrap();
        let name = g.repo_by_id.get(&repo_id)?;
        let repo = g.repos.get(name)?.clone();
        Some((repo, num))
    }

    pub fn get_repo_for_pr_gid(&self, gid: &str) -> Option<(String, Arc<RwLock<Repo>>, u32)> {
        let (repo_id, num) = decode_pr_gid(gid)?;
        let g = self.inner.read().unwrap();
        let name = g.repo_by_id.get(&repo_id)?;
        let repo = g.repos.get(name)?.clone();
        Some((g.owner_login.clone(), repo, num))
    }
}

#[inline]
pub fn decode_repo_gid(gid: &str) -> Option<u64> {
    let hex = gid.strip_prefix("R_")?;
    u64::from_str_radix(hex, 16).ok()
}

#[inline]
pub fn decode_issue_gid(gid: &str) -> Option<(u64, u32)> {
    let rest = gid.strip_prefix("I_")?;
    let (r, n) = rest.split_once('_')?;
    Some((u64::from_str_radix(r, 16).ok()?, u32::from_str_radix(n, 16).ok()?))
}

#[inline]
pub fn decode_pr_gid(gid: &str) -> Option<(u64, u32)> {
    let rest = gid.strip_prefix("PR_")?;
    let (r, n) = rest.split_once('_')?;
    Some((u64::from_str_radix(r, 16).ok()?, u32::from_str_radix(n, 16).ok()?))
}

#[inline]
pub fn hash_object(kind: ObjType, data: &[u8]) -> Oid {
    let mut hasher = Sha1::new();
    let header = format!("{} {}\0", kind.as_str(), data.len());
    hasher.update(header.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

pub fn parse_commit_meta(data: &[u8]) -> (Option<Oid>, SmallParents) {
    let mut tree = None;
    let mut parents = SmallParents::new();
    let header_end = data
        .windows(2)
        .position(|w| w == b"\n\n")
        .unwrap_or(data.len());
    let header = &data[..header_end];
    for line in header.split(|&b| b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"tree ") {
            if let Some(oid) = hex_to_oid(rest) {
                tree = Some(oid);
            }
        } else if let Some(rest) = line.strip_prefix(b"parent ") {
            if let Some(oid) = hex_to_oid(rest) {
                parents.push(oid);
            }
        }
    }
    (tree, parents)
}

pub fn parse_commit_message(data: &[u8]) -> String {
    let Some(blank) = data.windows(2).position(|w| w == b"\n\n") else {
        return String::new();
    };
    let mut msg = &data[blank + 2..];
    if msg.ends_with(b"\n") {
        msg = &msg[..msg.len() - 1];
    }
    String::from_utf8_lossy(msg).into_owned()
}

pub fn parse_tag_target(data: &[u8]) -> Option<Oid> {
    let header_end = data
        .windows(2)
        .position(|w| w == b"\n\n")
        .unwrap_or(data.len());
    for line in data[..header_end].split(|&b| b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"object ") {
            return hex_to_oid(rest);
        }
    }
    None
}

pub fn parse_tree(data: &[u8]) -> Vec<TreeEntry> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let Some(sp_rel) = data[i..].iter().position(|&b| b == b' ') else {
            break;
        };
        let sp = i + sp_rel;
        let Some(nul_rel) = data[sp + 1..].iter().position(|&b| b == 0) else {
            break;
        };
        let nul = sp + 1 + nul_rel;
        if nul + 21 > data.len() {
            break;
        }
        let mode = String::from_utf8_lossy(&data[i..sp]).into_owned();
        let name = String::from_utf8_lossy(&data[sp + 1..nul]).into_owned();
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[nul + 1..nul + 21]);
        out.push(TreeEntry { mode, name, oid });
        i = nul + 21;
    }
    out
}

pub fn build_tree(entries: &mut [TreeEntry]) -> Vec<u8> {
    entries.sort_by(|a, b| {
        let ab = a.name.as_bytes();
        let bb = b.name.as_bytes();
        let min_len = ab.len().min(bb.len());
        match ab[..min_len].cmp(&bb[..min_len]) {
            std::cmp::Ordering::Equal => {
                let ca = if ab.len() > min_len {
                    ab[min_len]
                } else if a.mode == "40000" {
                    b'/'
                } else {
                    0
                };
                let cb = if bb.len() > min_len {
                    bb[min_len]
                } else if b.mode == "40000" {
                    b'/'
                } else {
                    0
                };
                ca.cmp(&cb)
            }
            ord => ord,
        }
    });
    let mut out = Vec::with_capacity(entries.len() * 36);
    for e in entries {
        out.extend_from_slice(e.mode.as_bytes());
        out.push(b' ');
        out.extend_from_slice(e.name.as_bytes());
        out.push(0);
        out.extend_from_slice(&e.oid);
    }
    out
}

pub fn build_commit(
    tree: Oid,
    parents: &[Oid],
    author_login: &str,
    timestamp: u64,
    message: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + message.len());
    out.extend_from_slice(b"tree ");
    write_oid_hex(&tree, &mut out);
    out.push(b'\n');
    for p in parents {
        out.extend_from_slice(b"parent ");
        write_oid_hex(p, &mut out);
        out.push(b'\n');
    }
    let ident = format!(
        "{} <{}@example.invalid> {} +0000",
        author_login, author_login, timestamp
    );
    out.extend_from_slice(b"author ");
    out.extend_from_slice(ident.as_bytes());
    out.extend_from_slice(b"\ncommitter ");
    out.extend_from_slice(ident.as_bytes());
    out.extend_from_slice(b"\n\n");
    out.extend_from_slice(message.as_bytes());
    if !message.ends_with('\n') {
        out.push(b'\n');
    }
    out
}

#[inline]
pub fn format_issue_json(out: &mut Vec<u8>, issue: &Issue) {
    out.extend_from_slice(b"{\"id\":");
    write_u64_ascii(out, issue.id);
    out.extend_from_slice(b",\"node_id\":\"");
    out.extend_from_slice(issue.global_id.as_bytes());
    out.extend_from_slice(b"\",\"number\":");
    write_u32_ascii(out, issue.number);
    out.extend_from_slice(b",\"title\":");
    write_json_str(out, &issue.title);
    out.extend_from_slice(b",\"body\":");
    write_json_str(out, &issue.body);
    out.extend_from_slice(b",\"state\":\"");
    out.extend_from_slice(issue.state.rest_str().as_bytes());
    out.extend_from_slice(b"\",\"labels\":[");
    for (i, lbl) in issue.labels.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"name\":");
        write_json_str(out, lbl);
        out.push(b'}');
    }
    out.extend_from_slice(b"]}");
}

pub fn format_repo_json(out: &mut Vec<u8>, owner: &str, repo: &Repo) {
    out.extend_from_slice(b"{\"id\":");
    write_u64_ascii(out, repo.id);
    out.extend_from_slice(b",\"node_id\":\"");
    out.extend_from_slice(repo.global_id.as_bytes());
    out.extend_from_slice(b"\",\"name\":");
    write_json_str(out, &repo.name);
    out.extend_from_slice(b",\"full_name\":");
    write_json_str(out, &format!("{}/{}", owner, repo.name));
    out.extend_from_slice(b",\"private\":");
    out.extend_from_slice(if repo.private { b"true" } else { b"false" });
    out.extend_from_slice(b",\"description\":");
    write_json_str(out, &repo.description);
    out.extend_from_slice(b",\"default_branch\":");
    write_json_str(out, &repo.default_branch);
    out.extend_from_slice(b",\"owner\":{\"login\":");
    write_json_str(out, owner);
    out.extend_from_slice(b"}}");
}

pub fn format_pr_json(out: &mut Vec<u8>, pr: &PullRequest) {
    out.extend_from_slice(b"{\"id\":");
    write_u64_ascii(out, pr.id);
    out.extend_from_slice(b",\"node_id\":\"");
    out.extend_from_slice(pr.global_id.as_bytes());
    out.extend_from_slice(b"\",\"number\":");
    write_u32_ascii(out, pr.number);
    out.extend_from_slice(b",\"state\":\"");
    out.extend_from_slice(pr.state.rest_str().as_bytes());
    out.extend_from_slice(b"\",\"title\":");
    write_json_str(out, &pr.title);
    out.extend_from_slice(b",\"body\":");
    write_json_str(out, &pr.body);
    out.extend_from_slice(b",\"merged\":");
    out.extend_from_slice(if pr.merged { b"true" } else { b"false" });
    out.extend_from_slice(b",\"merged_at\":");
    match pr.merged_at {
        Some(ts) => {
            out.push(b'"');
            out.extend_from_slice(ts.as_bytes());
            out.push(b'"');
        }
        None => out.extend_from_slice(b"null"),
    }
    out.extend_from_slice(b",\"merge_commit_sha\":");
    match pr.merge_commit_sha {
        Some(sha) => {
            out.push(b'"');
            write_oid_hex(&sha, out);
            out.push(b'"');
        }
        None => out.extend_from_slice(b"null"),
    }
    out.extend_from_slice(b",\"head\":{\"ref\":");
    write_json_str(out, &pr.head_ref);
    out.extend_from_slice(b",\"sha\":\"");
    write_oid_hex(&pr.head_sha, out);
    out.extend_from_slice(b"\"},\"base\":{\"ref\":");
    write_json_str(out, &pr.base_ref);
    out.extend_from_slice(b",\"sha\":\"");
    write_oid_hex(&pr.base_sha, out);
    out.extend_from_slice(b"\"}}");
}
