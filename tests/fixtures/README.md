# Test fixtures

Every credential in these directories is fake: AWS's documented example key
(AKIAIOSFODNN7EXAMPLE), or a real token prefix followed by the filler "FAKE".
None of them work anywhere.

- `empty/`: a home with nothing in it.
- `full/`: a home (and filesystem root) with one of every file-based credential.
- `aws-sso/`: AWS profiles that use SSO and roles only, no static keys.
- `gh-keyring/`: a GitHub CLI login whose token lives in the OS keyring.
- `project/`: a working directory with `.env` files.
- `mcp/home/`: MCP client configs for every supported client (Claude Desktop
  on macOS and Linux, Claude Code, Cursor, VS Code, Windsurf, Zed, Codex,
  Gemini CLI), with tokens in env, args, URLs and headers.
- `mcp/project/`: a working directory with project-level MCP configs.
- `mcp/placeholders/`: MCP configs that only reference secrets
  (`${input:...}`, `${VAR}`, `<your-key-here>`); nothing should be reported.

- `workflows/gemini-dispatch/`: run-gemini-cli's dispatch and review
  workflows, where the agent job is gated through `needs:` on a job that
  checks the commenter's author association. Only secret names, no values.

- `dotenv-cases/`: a working directory with what real projects hold besides
  secrets: a `.env.example` of placeholders (plus one pasted real-looking
  token), public frontend keys (`NEXT_PUBLIC_*`, `VITE_*`) next to a secret
  exposed to the bundle, token formats several vendors share (`sk_test_`
  for WorkOS, `sk-` for DeepSeek), a local development database URL, and an
  empty and a commented MCP config. Tokens are numbered 06xx.

- `hostile/home/`, `hostile/project/`: untrusted text. Secrets inside names
  and URLs (a git credential section, a kubeconfig user name, an `.npmrc`
  key, a bare `.env` line, a `git fetch` in a workflow), and workflow job
  ids and `uses:` values with terminal escapes, workflow commands, bidi
  controls and Markdown/HTML. The control characters are written as YAML
  escapes, so the files themselves are plain text. Used by
  `tests/hostile.rs` and `tests/redaction.rs`.

- `leaky/home/` and `leaky/project/`: secrets pasted into the names the checks
  quote (section names, registry keys, kubeconfig user names, credential
  helper commands, netrc machine names, bare `.env` lines). Used by
  `tests/redaction_sources.rs`, which adds a `.git/config` with a token and
  an out-of-tree `.env` symlink in a temporary copy.

- `scrub/home/` and `scrub/project/`: secrets in shapes the report scrubber
  has to recognise: URL passwords with an unencoded `/` or an encoded colon,
  a host made to look like an image digest, `Authorization`/`Bearer`
  values, secret fragment and query parameters, and `--password`-style
  flags. `tests/redaction.rs` adds a `.git/config` in a temporary copy.

MCP fixture tokens are numbered 03xx, hostile fixture secrets 07xx, scrub
fixture secrets 09xx.

SSH private keys are not stored here (secret scanners flag even fake ones);
the tests write them to a temporary directory instead.

`project/.gitignore` ignores the project's own `.env` files (that is part of
what the `dotenv` check is tested against), so those fixture files are
committed with `git add -f`. Do the same when adding new ones.
