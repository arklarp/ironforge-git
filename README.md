[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/arklarp/ironforge-git/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/arklarp/ironforge-git/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

# ironforge-git

Single-process deterministic GitHub-compatible git forge compiled to static musl Rust (`x86_64-unknown-linux-musl`) for the [github-core-clone-01](https://make.fun/bounty/github-core-clone-01) contest.

## Run

```sh
python3 -P -s main.py
```

`main.py` immediately replaces the Python process via `os.execv` with `bin/forge`, implementing the harness lifecycle (`MAKEFUN_ENV_URL` `/register` and `/done` polling, `MAKEFUN_SHOP_TOKEN` bearer auth) and all four surfaces in one in-memory store:

- **Git Smart HTTP (v2 & v0):** `/<owner>/<repo>.git/info/refs`, `git-upload-pack`, `git-receive-pack`
- **REST v3:** `/api/v3/...` (repositories, branches, git refs, commits, contents, issues, comments, labels, pull requests, merges)
- **GraphQL:** `/api/graphql`
- **MCP:** `/mcp` (`2026-07-28` + legacy JSON-RPC 2.0)

## Layout

- `main.py` — process launcher (`execv` into `bin/forge`)
- `bin/forge` — static `x86_64-unknown-linux-musl` release binary
- `src/` — Rust implementation (`main.rs`, `http.rs`, `git.rs`, `rest.rs`, `graphql.rs`, `mcp.rs`, `store.rs`, `util.rs`)
- `Cargo.toml`, `LICENSE`

Built for [make.fun](https://make.fun/?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01).
