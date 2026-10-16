# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Rule ids (`HK-*`) are part of the
public interface: a released id never changes meaning.

## [Unreleased]

## [0.2.0] - 2026-10-16

### Added

- **Ignore rules.** A `.heldkeys.toml` in the scanned directory lists accepted risks as `[[ignore]]` tables with a `rule` (an id or a prefix such as `HK-WF-*`), an optional `path` glob matched against the file a finding is in (never its job id, `uses:` value or variable name), an optional exact `location` for findings in no file, a required `reason` and an optional `expires` date, after which the rule stops applying with a warning. Parsing is strict: unknown keys, a missing reason, a bad date and a pattern that matches every rule without a `location` or a `path` that names more than wildcards are errors (exit 2). Local scans also read `~/.config/heldkeys/config.toml`. `--config <file>` reads only that file, `--no-config` reads none.
- **Baselines.** `--baseline <file>` leaves out the findings already in a previous `--format json` report, matched on rule, location (relative to the scanned directory, without line numbers) and fingerprint, so CI fails only on new findings. A finding that got worse since (higher severity, wider access or a longer lifetime) is reported again, with "was medium in the baseline" in its detail. `--write-baseline <file>` writes every finding of the run as a baseline. JSON reports gain `origin`, the scanned directory as shown.
- **Ignored findings stay visible.** The summary line counts them ("(4 ignored by .heldkeys.toml, 2 in the baseline)"), text and Markdown reports have an "Ignored" section with every ignore rule that matched, its reason and file (`--details` lists the findings themselves), JSON has a `suppressed` list and `ignored` and `in_baseline` counts in `summary`, SARIF emits them as results with `suppressions` (kind `external`, the reason as justification), and the `preflight` verdict line says how many were left out. `--no-ignore` reports everything.
- In the CI run of a pull request (GitHub Actions on `pull_request` or an untrusted trigger) or a GitLab merge request, `heldkeys ci` warns when ignore rules or the baseline were read from the change's own checkout: on stderr, in the text and Markdown reports, as JSON `notices` and as SARIF tool notifications, and the summary line says "ignored by a file the pull request can change".
- Action inputs `config` and `baseline`, and docs on protecting both files with CODEOWNERS or reading them from the default branch.
- `ai-logins` check (new "AI tool logins" category): logins AI coding tools keep on disk. Codex `auth.json`, API key or ChatGPT login, honouring `CODEX_HOME` (HK-AI-001); Claude Code `.credentials.json` on Linux, honouring `CLAUDE_CONFIG_DIR`; the macOS keychain is never read (HK-AI-002); credentials in the `env` block of Claude Code settings, user and project, and `apiKeyHelper` (HK-AI-003); Gemini CLI `oauth_creds.json` and `~/.gemini/.env` (HK-AI-004); GitHub Copilot `apps.json` and `hosts.json` (HK-AI-005); Hugging Face `token` and `stored_tokens`, honouring `HF_HOME` (HK-AI-006).
- `cli-logins` check (new "Developer platform CLIs" category): logins developer platform CLIs keep on disk, on macOS and Linux paths. Vault `~/.vault-token` (HK-CLI-001), Terraform `credentials.tfrc.json` (HK-CLI-002), Vercel `auth.json` (HK-CLI-003), Netlify `config.json` (HK-CLI-004), Fly.io `config.yml` (HK-CLI-005), Supabase `access-token` (HK-CLI-006), Cloudflare Wrangler `default.toml` (HK-CLI-007), Stripe CLI `config.toml`, with test-mode keys rated Low (HK-CLI-008), Doppler `.doppler.yaml` (HK-CLI-009), Railway `config.json` (HK-CLI-010) and Kaggle `kaggle.json` (HK-CLI-011).
- `aws` check: awsume's session cache (HK-AWS-008), aws-vault's file keyring, High when `AWS_VAULT_FILE_PASSPHRASE` is set (HK-AWS-009), and Granted's file keyring setting (HK-AWS-010).
- `aws` check: cached sessions in `~/.aws/cli/cache` and the awsume cache are read for their expiry. A session that has not expired is reported as "Cached AWS session usable without MFA" with the time it expires; a cache holding only expired sessions is no longer reported.
- `dotenv` check: copies of `.env` files that VS Code's Local History extension keeps in `.history/` (`.env_20260507230125`), reported as "Editor history copy of a .env file" with the severity of the value inside (HK-DOTENV-003). A copy holding the same value as the `.env` file counts as the same secret, so many copies stay one line in the summary.
- "Next steps" in the summary has actions for AI tool logins, developer platform CLIs, cached AWS sessions and editor history copies.

## [0.1.1] - 2026-10-16

The first public release.

### Added

#### Local

- `heldkeys scan` (the default command): an inventory of the credentials reachable from the current shell, sandbox or container, with severity, lifetime and access for each, and the fixes that shrink the list.
- Local checks `env`, `aws`, `gcloud`, `azure`, `kube`, `docker`, `netrc`, `git-credentials`, `git-helper`, `npmrc`, `pypirc`, `cargo-credentials`, `dotenv`, `ssh-agent`, `docker-socket`, `k8s-service-account` and `cloud-metadata`.
- `git-config` check: tokens in `url.<base>.insteadOf` rewrites (HK-GITCFG-001), `http.extraheader` (HK-GITCFG-002) and remote URLs (HK-GITCFG-003), in `~/.gitconfig`, `~/.config/git/config` and the project's `.git/config`. `heldkeys ci` runs it on the repository's `.git/config` only, and inside GitHub Actions leaves the checkout's `Authorization` header to HK-CI-005.
- The `dotenv` check walks gitignored directories too (depth 4, skipping dependency directories such as `node_modules`) and follows symlinks that stay inside the working directory.
- HK-READ-001 (`read-errors`): a file a check looks at that exists but could not be read or parsed is reported as an Info finding in every mode, instead of being skipped silently.
- `--strict` on `scan`, `preflight` and `ci`: also exit 1 when something could not be analysed (an HK-READ-001 or HK-WF-007 finding), for gates that must fail closed.
- `heldkeys checks`: every check and rule, as text or JSON.
- Output formats `text` and `json` (`"schema": "heldkeys/v1"`), `--output`, `--quiet`, `--no-color` and `NO_COLOR`, `--home` and `--path`.
- `--fail-on none|high|medium|low|long-lived-write` and exit codes 0, 1 and 2.
- Redacted fingerprints only, guarded by a test that runs every fixture through every output format.
- `HELDKEYS_NO_NET=1` to skip the metadata reachability probe.

#### MCP

- `mcp` check: tokens in the env, args, URLs and headers of MCP server configs for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Codex and Gemini CLI, in the home directory and the project (HK-MCP-001, HK-MCP-002), plus project-level configs whose servers start when an agent opens the directory (HK-MCP-003).

#### Sandbox

- `heldkeys preflight`: a one-line PASS or FAIL verdict for container entrypoints and sandbox start hooks, exiting 1 when a finding reaches `--fail-on` (default `high`); `--format json` puts the report on stdout and the verdict on stderr.
- `heldkeys scan --docker <container>` and `heldkeys scan --kube <pod> [-n <namespace>] [-c <container>]`: copy a Linux heldkeys into a running container or pod, run it there, read the JSON back and remove the copy. `--binary` names the Linux build to copy.
- Recipes for Docker, devcontainers, Kubernetes, E2B, Daytona, Modal, Vercel Sandbox, Cloudflare Sandbox and coding agents (`docs/sandboxes.md`), static musl build instructions (`docs/building.md`), and an agent skill (`skill/heldkeys/SKILL.md`).
- `examples/Dockerfile.preflight`: preflight as an entrypoint gate.

#### CI

- `heldkeys ci`: a runtime inventory of the GitHub Actions or GitLab CI job (`ci-runtime`, HK-CI-001 to HK-CI-007) plus static analysis of the AI agent steps in `.github/workflows` (`workflows`, HK-WF-001 to HK-WF-006). Fails on High by default.
- The workflow analysis follows local reusable workflows (`jobs.<id>.uses: ./.github/workflows/x.yml`) into the workflow they call, with the caller's triggers, permissions and secrets, up to 3 calls deep.
- HK-WF-007: a workflow file that could not be analysed (invalid YAML, over the YAML budget, too large, or a reusable-workflow call that cannot be followed) is reported as an Info finding, so a pass never hides an unchecked agent step.
- `heldkeys ci --repo-secrets`: tokens of known formats in tracked files on the current branch (`repo-secrets`, HK-REPO-001).
- Output formats `markdown` (PR comments and job summaries, kept under GitHub's size limits) and `sarif` (SARIF 2.1.0 for code scanning, with workflow file and line locations).
- A summary line for `ci` that counts AI agent workflow risks apart from the credentials reachable in the job.
- The `hugomn/heldkeys` composite GitHub Action: verifies the release binary's checksum, runs `heldkeys ci`, writes the job summary and, with `sarif: true`, uploads SARIF to code scanning.
- `examples/vulnerable-agent-workflow.yml` and `examples/hardened-agent-workflow.yml`.

#### Docs

- A page for each of the 70 rules in `docs/rules/`, with an index generated from `heldkeys checks --format json` and tests that fail when a rule has no page or is missing from the README.
- `docs/threat-model.md`: what heldkeys treats as untrusted, what it defends against, what it cannot see, and which guarantees are tested.

### Changed

- **Text output leads with a summary.** On a machine with many checkouts a scan can hold hundreds of findings, most of them a few secrets copied into many `.env` files. The default view is now a header naming the scanned directory, the 10 distinct credentials to fix first (machine-wide logins before project files, at most 3 from one place while others have some), counts by place (shell environment, cloud CLIs, git, package registries, SSH, MCP configs, sandbox and host, project `.env` files with their file and repository count), secrets found in several places collapsed into one line each, at most 6 generic next steps, and a pointer to `--details`. The summary line stays last.
- **`--details` (`-v`)** lists every finding, grouped by place and then by file: each path once, relative to the scanned directory, with title, place in the file and fingerprint under it, and lifetime, access and detail after them or on dimmed lines below. Lines fit `COLUMNS` (default 100); long paths are cut in the middle, fingerprints never.
- **Duplicates are recognised without keeping the value.** Checks that read a value (`env`, `dotenv`, `mcp`) keep a per-process keyed hash of it in memory only, so copies of one secret are grouped; it is never printed or serialized. JSON findings gain `category` and, when the same secret is found elsewhere, `duplicates` (how many other findings hold it).
- **Markdown** puts the same summary before the full per-severity tables; **preflight** ranks its reasons the same way and lists at most 10 (`+N more`, all with `--details`).
- **Fewer false positives in `.env` files.** Placeholders in template files (`.env.example`, `.sample`, `.template`, `.dist`, also as in `.env.local.example`) are not reported, a real-looking token in one is titled "... in a template file" one severity lower; public frontend variables (`VITE_`, `NEXT_PUBLIC_`, `PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`) that are public by design (site keys, publishable and anonymous keys, client ids, analytics keys) are skipped, while one whose name says `SECRET`, `PRIVATE` or `SERVICE_ROLE` is High, "Secret exposed to the frontend bundle"; connection strings to `localhost` with a trivial password are not reported.
- **Severity and titles.** A value of unknown shape flagged only by a cloud or source-control name ("Possible cloud or SCM credential") is Medium, not High. Token formats several vendors share are titled after the vendor the variable names (`WORKOS_API_KEY=sk_test_...` is a "WorkOS test-mode API key", `DEEPSEEK_API_KEY=sk-...` a "DeepSeek API key"), else "Test-mode secret key (sk_test_)", "Live secret key (sk_live_)" or "OpenAI-style API key".
- **Configs.** An empty JSON config (an editor's fresh `mcp.json`) is skipped instead of reported as not valid JSON, and a leading byte order mark is accepted. The note for a `.env` walk that hit its entry limit says to run heldkeys from a single project or pass `--path`.

### Security hardening

heldkeys treats everything it scans as untrusted: a pull request controls its workflows, a cloned repository its project files, a container what it sends back.

- **Output sanitising.** Every string field of every finding, and every string read back from a `--docker` or `--kube` target, is made inert before rendering: control characters, escape sequences, carriage returns, line breaks, bidi controls and Unicode line separators become `?`, and text that would start a GitHub Actions workflow command is defused. The Markdown renderer escapes links, images, emphasis, HTML and @mentions, writes URLs from scanned files as code spans so GitHub does not autolink them, and keeps fixes copy-pastable.
- **Scrubbing.** Secrets that a check quoted in a location or detail are masked before rendering: URL passwords (including unencoded `/` or `@` in the password and percent-encoded separators), `Authorization` and `Bearer` values, secret URL query and fragment parameters (`?api_key=`, `#access_token=`, OAuth `?code=`), `--password`, `--token`, `--api-key` and `--secret` style flags, and known tokens. A fingerprint that is not in the `abcd…xyz` shape is dropped. Fingerprints leave at least 12 characters of a token hidden after its public prefix. Checks show hosts and program names instead of whole URLs, helper command lines or bare `.env` lines.
- **Confined reads.** Files are opened first and the open handle is checked, so only regular files are read and a FIFO cannot block the scan; reads are bounded (1 MiB for most files); `/proc` and `/sys` are refused; a symlink in the project, the repository or a workflow directory that leads outside it is not followed and is reported instead. HK-CI-005 does not follow git config includes outside the repository or the runner's temp directory, and a `.git` file's `gitdir:` outside the working directory is followed only when git's back-pointer names it.
- **YAML budget.** Workflows and kubeconfigs with more than 100 aliases, more than 50,000 nodes once aliases are expanded, or more than 64 levels of nesting are refused before the tree is built.
- **No code from the repository.** `ci --repo-secrets` runs `git ls-files` with a cleared environment, `core.hooksPath=/dev/null`, `core.fsmonitor=false`, `protocol.allow=never` and `GIT_OPTIONAL_LOCKS=0`, and does not read tracked symlinks that lead out of the repository.
- **Bounded workflow analysis.** The number of local reusable-workflow calls followed from one repository is capped, so a fan-out of calls cannot multiply the work, and YAML documents are also refused when their expanded size goes over budget.
- **Fail closed everywhere.** `--strict` covers every credential file the checks look at and every workflow that could not be analysed (HK-WF-007), and `heldkeys ci` also reports tokens in the remote URLs of the repository's `.git/config`.
- **Bounded remote scans.** Every `docker` and `kubectl` command is killed after 120 seconds, and its output is capped.
- **Fewer places to hide.** Only the exact `HELDKEYS_*` variables heldkeys reads are skipped by the `env` check. Of an SSH private key file only the first 256 bytes are read.
- **CPU-bounded scrubbing and parsing.** Scrubbing finds URL user information in linear time, even on a `uses:` value followed by hundreds of thousands of slashes; heredoc detection counts arithmetic parentheses once per line; actor-gate conditions are parsed in linear time and not read as gates past 32 levels of nesting, so a crafted workflow cannot stall the scan or overflow the stack.
- **Clipped repository-controlled names.** Job ids, `uses:` values, file names, secret names, permission scopes and CI environment names are cut to 200 characters before they go into a finding, so one absurd name cannot flood the report.
- **Actor gates through `needs:`.** An actor or `author_association` gate on any job in a job's transitive `needs:` also gates it (unless `always()`, `failure()` or `cancelled()` breaks the chain), and same-repository pull request checks count as a gate, so gated dispatch workflows such as run-gemini-cli's are Medium rather than High for HK-WF-001.
- **Scrubbing false positives.** `mailto:`, `xmpp:` and `sip:` addresses are no longer masked as passwords, a query parameter is masked only when its name is or ends in a secret word (`token_count`, `max_tokens` and `zipcode` stay), and percent-encoding in displayed text is kept as written.
- **Workflow rules.** Agent CLIs are matched only in shell code and argument positions, not in prompts or heredocs; only positive actor checks count as a gate for HK-WF-001; interpreters and build runners in an allow list count as unrestricted shell for HK-WF-006; the cloud keys Claude Code needs on Bedrock or Vertex are Medium, not High, for HK-WF-004.

## [0.1.0] - 2026-10-15

Published to crates.io early to reserve the name, and yanked. Use 0.1.1.

[Unreleased]: https://github.com/hugomn/heldkeys/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hugomn/heldkeys/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/hugomn/heldkeys/releases/tag/v0.1.1
[0.1.0]: https://crates.io/crates/heldkeys/0.1.0
