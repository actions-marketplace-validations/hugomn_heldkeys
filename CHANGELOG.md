# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Rule ids (`HK-*`) are part of the
public interface: a released id never changes meaning.

## [Unreleased]

### Added

- Every release archive comes with its GitHub build provenance as `<archive>.sigstore.json`, so `gh attestation verify <archive> --bundle <archive>.sigstore.json --owner hugomn` works without asking GitHub. The bundles of the earlier releases, 0.1.1 to 0.2.3, were attached from the same attestations.
- Fuzz targets (`fuzz/`, cargo-fuzz) for the YAML, TOML, JSON-with-comments and INI readers, the ignore-rule, baseline and report parsers, and the token rules, redaction and output sanitising. CI runs each for a short while on every push.

### Changed

- CI runs HOL's plugin scanner (`hashgraph-online/ai-plugin-scanner-action`, pinned to a commit) on every push and pull request, with read access only, no secrets and no network probing, and fails below a score of 100.
- CI runs OpenSSF Scorecard on every push to `main` and weekly, uploads the findings to code scanning and publishes the score.
- CI runs CodeQL on the Rust sources and on the workflows, on every push to `main`, every pull request and weekly.

## [0.2.3] - 2026-10-16

### Changed

- Fake test credentials are no longer committed as complete tokens: fixtures in `tests/fixtures` use `{{fake:...}}` markers that the tests resolve when they copy them, and Rust tests split each token after its prefix, so secret scanners such as gitleaks report nothing on the repository.
- CI runs gitleaks on the tracked files.

## [0.2.2] - 2026-10-16

### Changed

- The GitHub Action installs the heldkeys binary of its own release by default instead of the newest one, so pinning the action to a commit pins the binary too. `version: latest` keeps the old behaviour.
- The release workflow runs with read-only permissions except where it publishes, installs cargo-dist from a checksummed archive and pins `actions/checkout` v7.0.1. The Homebrew formula gains a `test` block.
- CI runs heldkeys and zizmor on this repository.
- Docs: the dependency list now includes `toml`, and the install script notes say what the installer changes. `SPEC.md` is gone; the README and `docs/` cover the design.

## [0.2.1] - 2026-10-16

### Changed

- The GitHub Action adds `heldkeys` to the job's PATH, so later steps can run it directly (for example to write a baseline).
- Workflow examples and CI pin `actions/checkout` v7.0.1, which runs on Node 24.

### Fixed

- `scan --docker` and `scan --kube` no longer leave the copied binary in the target when they are interrupted. The copy now deletes its own file as soon as it starts (a hidden `--remove-self` flag), so once it runs, killing heldkeys cannot leave it behind. After a failed `docker cp` or `kubectl cp`, which may have written part of the file, heldkeys now runs `rm -f` on the path too. In Docker that `rm -f` runs as root (`docker exec -u 0`, on the exact path only), because `docker cp` creates the file owned by root in a sticky `/tmp`: before, a container running as a non-root user always kept the copy. Ctrl-C and SIGTERM during the copy or the scan stop that step and still run the `rm -f`. A cleanup that fails after a failed scan is now part of the error message instead of being dropped. What can still leave the file behind is listed in docs/sandboxes.md. `--binary` must now point at heldkeys 0.2.1 or later.

## [0.2.0] - 2026-10-16

### Added

- Ignore rules: a `.heldkeys.toml` in the scanned directory lists accepted risks as `[[ignore]]` tables with a `rule` (an id or a prefix such as `HK-WF-*`), an optional `path` glob matched against the file a finding is in (never its job id, `uses:` value or variable name), an optional exact `location` for findings in no file, a required `reason` and an optional `expires` date, after which the rule stops applying with a warning. Parsing is strict: unknown keys, a missing reason, a bad date and a pattern that matches every rule without a `location` or a `path` that names more than wildcards are errors (exit 2). Local scans also read `~/.config/heldkeys/config.toml`. `--config <file>` reads only that file, `--no-config` reads none.
- Baselines: `--baseline <file>` leaves out the findings already in a previous `--format json` report, matched on rule, location (relative to the scanned directory, without line numbers) and fingerprint, so CI fails only on new findings. A finding that got worse since (higher severity, wider access or a longer lifetime) is reported again, with "was medium in the baseline" in its detail. `--write-baseline <file>` writes every finding of the run as a baseline. JSON reports gain `origin`, the scanned directory as shown.
- Ignored findings stay visible. The summary line counts them ("(4 ignored by .heldkeys.toml, 2 in the baseline)"), text and Markdown reports have an "Ignored" section with every ignore rule that matched, its reason and file (`--details` lists the findings themselves), JSON has a `suppressed` list and `ignored` and `in_baseline` counts in `summary`, SARIF emits them as results with `suppressions` (kind `external`, the reason as justification), and the `preflight` verdict line says how many were left out. `--no-ignore` reports everything.
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

#### Output

- The text report leads with a summary: the scanned directory, the 10 distinct credentials to fix first (machine-wide logins before project files), counts by place, secrets found in several places collapsed into one line each, a few next steps, and a pointer to `--details`. The summary line comes last.
- `--details` (`-v`) lists every finding, grouped by place and then by file, with paths relative to the scanned directory. Lines fit `COLUMNS` (default 100); long paths are cut in the middle, fingerprints never.
- Copies of one secret are grouped through a per-process keyed hash that is kept in memory only and never printed or serialized. JSON findings have `category` and, when the same secret is found elsewhere, `duplicates`.
- Markdown puts the same summary before the full per-severity tables, and preflight ranks its reasons the same way, listing at most 10 unless `--details` is given.
- Placeholders in `.env` template files (`.env.example`, `.sample`, `.template`, `.dist`) are not reported, and a real-looking token in one is one severity lower. Public frontend variables (`VITE_`, `NEXT_PUBLIC_`, `PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`) that hold public values are skipped, while one named `SECRET`, `PRIVATE` or `SERVICE_ROLE` is High. Connection strings to `localhost` with a trivial password are not reported.
- A value of unknown shape flagged only by a cloud or source-control name is Medium. Token formats several vendors share are titled after the vendor the variable names (`WORKOS_API_KEY=sk_test_...` is a "WorkOS test-mode API key").

#### Security

heldkeys treats everything it scans as untrusted: a pull request controls its workflows, a cloned repository its project files, a container what it sends back.

- Every string from a scanned file or a `--docker` or `--kube` target is made inert before rendering: control characters, escape sequences, line breaks and bidi controls become `?`, and text that would start a GitHub Actions workflow command is defused. The Markdown renderer escapes links, images, emphasis, HTML and @mentions.
- Secrets that a check quotes in a location or detail are masked: URL passwords, `Authorization` and `Bearer` values, secret query and fragment parameters, `--password` and `--token` style flags, and known tokens. A fingerprint not in the `abcd…xyz` shape is dropped.
- Only regular files are read, through the open handle, and most reads stop at 1 MiB. `/proc` and `/sys` are refused, and a symlink that leads out of the project, repository or workflow directory is reported instead of followed.
- YAML with more than 100 aliases, 50,000 expanded nodes or 64 levels of nesting is refused before the tree is built, and the number of reusable-workflow calls followed from one repository is capped.
- `ci --repo-secrets` runs `git ls-files` with a cleared environment and hooks, fsmonitor and protocols disabled.
- `docker` and `kubectl` commands are killed after 120 seconds, and their output is capped.
- Scrubbing and parsing run in linear time, and repository-controlled names are cut to 200 characters, so a crafted workflow cannot stall the scan, overflow the stack or flood the report.
- An actor or `author_association` gate on a job in a job's transitive `needs:` also gates it, and same-repository pull request checks count as a gate for HK-WF-001. Agent CLIs are matched only in shell code, not in prompts or heredocs.

## [0.1.0] - 2026-10-15


Published to crates.io early to reserve the name, and yanked. Use 0.1.1.

[Unreleased]: https://github.com/hugomn/heldkeys/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/hugomn/heldkeys/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/hugomn/heldkeys/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/hugomn/heldkeys/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/hugomn/heldkeys/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/hugomn/heldkeys/releases/tag/v0.1.1
[0.1.0]: https://crates.io/crates/heldkeys/0.1.0
