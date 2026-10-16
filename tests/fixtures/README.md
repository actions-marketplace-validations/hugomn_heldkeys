# Test fixtures

Every credential in these directories is fake: AWS's documented example key
(AKIAIOSFODNN7EXAMPLE), or a real token prefix followed by the filler "FAKE".
None of them work anywhere.

Fake credentials are committed as `{{fake:PREFIX|REST}}` markers, with the `|`
right after the token's public prefix if it has one, so secret scanners run on
this repository do not flag them. The tests never read these files directly:
`tests/common/fixtures.rs` copies this directory to the system temp directory
with every marker replaced by `PREFIXREST`, and `demo.tape` does the same.

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

- `logins/home/`: the files AI tools and developer platform CLIs keep
  after a login, in every format the `ai-logins` and `cli-logins` checks
  read (JSON, TOML, YAML, INI, a bare token, `.env`): Codex, Claude Code
  (`.credentials.json`, settings `env` and `apiKeyHelper`), Gemini CLI,
  GitHub Copilot, Hugging Face, Vault, Terraform, Vercel (macOS path),
  Netlify, Fly.io, Supabase, Wrangler, Stripe (live and test keys),
  Doppler, Railway, Kaggle. Also AWS session caches (`~/.aws/cli/cache`
  with one valid and one expired session, awsume), an aws-vault file
  keyring and a Granted config with a file keyring. Session expiries are
  in 2099 and 2020, so the tests do not depend on today's date.
- `logins/project/`: a project `.claude/settings.local.json`, and a `.env`
  with VS Code Local History copies under `.history/` (a copy of `.env`
  with the same value, an older one with a different value, a copy of
  `.env.local` and one of `.env.example`). Its `.env` and `.history`
  files are committed with `git add -f`.

Login fixture tokens are numbered 10xx.

MCP fixture tokens are numbered 03xx, hostile fixture secrets 07xx, scrub
fixture secrets 09xx.

SSH private keys are not stored here (secret scanners flag even fake ones);
the tests write them to a temporary directory instead.

`project/.gitignore` ignores the project's own `.env` files (that is part of
what the `dotenv` check is tested against), so those fixture files are
committed with `git add -f`. Do the same when adding new ones.

- `config/`: ignore rules and baselines. `repo/` is a repository with a
  `.heldkeys.toml` (one active ignore, one for `.env` files under
  `fixtures/`, one expired), two agent workflows and two `.env` files;
  `home/` holds a user config (`~/.config/heldkeys/config.toml`);
  `invalid/` holds configs that must be refused (unknown key, missing
  reason, a pattern that matches every rule, a bad date, a TOML syntax
  error); `hostile/config.toml` puts terminal escapes, workflow commands,
  Markdown and a URL password in a reason and a path. `job-named-fixtures/`
  is a workflow whose job id looks like a path (`fixtures-bot`), which a
  `path = "*fixtures*"` rule must not hide; `escalated/` is a workflow
  whose agent became High after a baseline (`base.json`) recorded it as
  Medium. Tokens are numbered 11xx.
