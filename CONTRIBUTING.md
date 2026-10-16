# Contributing to heldkeys

Thanks for helping. The most useful contributions are new checks for places where agents find credentials, fixes for false positives and negatives, and clearer fixes in the output. Please open an issue first for anything large, so we can agree on the shape before you write it.

## Ground rules

These are the promises in the README, and every change has to keep them:

- **Never print a secret.** A value reaches a `Finding` only through `redact::fingerprint` (or `redact::shorten` for values that are not secret, such as a public key hash). Never put a value in `title`, `location`, `detail` or `fix`.
- **Read-only.** Checks read files and `ctx.env`. They do not write, and they do not run commands, except where a check documents it (`ssh-add -l`, and `git ls-files` for `ci --repo-secrets`). Only `scan --docker` and `scan --kube` run `docker` or `kubectl`, and only against the target the user named.
- **No network.** Nothing new talks to the network. A check that needs to ask an issuer about a token must be gated behind `--deep` and talk only to that issuer.
- **Plain Rust.** No async, no macros of our own, no clever generics. Small files, one check per file, comments that explain why. A security engineer who does not write Rust every day should be able to review it.
- **Never run the binary against your real home or environment in tests.** Use `--home`, `--root` and `--path` pointing at fixtures, an empty environment (`env -i`), and `HELDKEYS_NO_NET=1`. The helpers in `tests/common` do this for you.

## Setup

You need a stable Rust toolchain (1.88 or later).

```sh
git clone https://github.com/hugomn/heldkeys
cd heldkeys
cargo test
```

Before you push, run the same checks as CI:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

To try the binary safely, on a copy of the fixtures with their fake credentials resolved (see step 5 below):

```sh
F="$(mktemp -d)" && cp -R tests/fixtures/. "$F" && \
  find "$F" -type f -exec perl -pi -e 's/\{\{fake:([^}|]*)\|?([^}]*)\}\}/$1$2/g' {} +
env -i HELDKEYS_NO_NET=1 PATH="$PATH" cargo run -q -- \
  --home "$F/full" --root "$F/full" --path "$F/project"
```

## Adding a check

A check is one file in `src/checks/`, plus a fixture, tests and a docs page. `src/checks/netrc.rs` is a good small example to copy.

1. **Write the file.** Create `src/checks/<name>.rs` with a unit struct that implements `Check` (`id`, `describe`, `rules`, `run`). Resolve every path through `ctx.home_path`, `ctx.config_dir`, `ctx.root_path` or `ctx.cwd`, never through the real process environment, so fixtures work. Missing files are not errors: return no findings.
2. **Declare the rules.** Each kind of finding gets a `Rule` const with a stable id `HK-<AREA>-<NNN>` and a one-line summary, listed in `rules()`. Pass the matching const to `Finding::new`. A released id never changes meaning; if the meaning changes, add a new id.
3. **Pick severity, lifetime and access** with the rule of thumb in `src/finding.rs`, and write a one-line `fix` that a person can act on.
4. **Register it.** Add `pub mod <name>;` and the check to `local_checks()` or `ci_checks()` in `src/checks/mod.rs`. The registry tests then verify that its rule ids are unique and well formed, and that every finding uses a declared rule.
5. **Add a fixture.** Put fake credentials under `tests/fixtures/<case>/`. Use AWS's documented example key (`AKIAIOSFODNN7EXAMPLE`) or a real token prefix followed by obvious filler such as `FAKE`. Never commit anything that works. Write each fake credential as `{{fake:PREFIX|REST}}`, for example `{{fake:sk-|proj-FAKEFAKEFAKEFAKEFAKEFAKE0042}}`, with the `|` right after the token's public prefix if it has one. The tests read a copy of `tests/fixtures` in which every marker is replaced by `PREFIXREST`, so secret scanners run on this repository do not flag test data. In Rust code, split fake tokens the same way with `concat!("sk-", "proj-FAKE...")`. `.env` files in `tests/fixtures/project` are ignored on purpose, so add them with `git add -f`. Do not commit private keys, even fake ones: write them to a temporary directory in the test, as `tests/common` does.
6. **Test it.** Unit tests go at the bottom of the check's file (see `checks::testutil`). If you added new fake secrets, list them in `FIXTURE_SECRETS` in `tests/common/mod.rs` so the redaction test looks for them in every output format.
7. **Document it.** Add `docs/rules/<ID>.md` for each new rule, following the template in [docs/rules/README.md](docs/rules/README.md), and add a row to the rule tables in `docs/rules/README.md` and the README.

## Token formats

Token patterns live in `src/rules.rs`. Take formats from the issuer's public documentation and link it in a comment. Patterns adapted from gitleaks or betterleaks (MIT) are fine with their copyright notice added to `NOTICE`. Do not copy from trufflehog (AGPL) or secrets-patterns-db (CC-BY-SA).

## Recording the demo

The README GIF is generated from `demo.tape` with [VHS](https://github.com/charmbracelet/vhs):

```sh
vhs demo.tape
```

Run it from the repository root. It builds a release binary, scans a temporary copy of the fake fixtures in a clean environment, and writes `docs/assets/demo.gif`. Commit the GIF together with any change to the text output, so the README stays truthful.

## Commits and pull requests

- Small, focused commits with [Conventional Commits](https://www.conventionalcommits.org/) messages: `feat(checks): add terraform credentials`, `fix(report): ...`, `docs: ...`.
- One logical change per pull request, with tests.
- Do not paste real credentials, real output from your own machine, or fingerprints of your own tokens into issues or pull requests. Reproduce with fixtures.

## Releasing

Maintainers only. A `vX.Y.Z` tag starts `.github/workflows/release.yml` (generated by cargo-dist), which builds the binaries, creates the GitHub release, updates the formula in hugomn/homebrew-tap and publishes the crate to crates.io through `.github/workflows/publish-crates.yml`.

One-time setup:

- **crates.io Trusted Publishing.** On crates.io, open the `heldkeys` crate, then Settings, Trusted Publishing, and add a GitHub publisher: owner `hugomn`, repository `heldkeys`, workflow filename `release.yml`, no environment. It has to be `release.yml` and not `publish-crates.yml`: crates.io checks the `workflow_ref` claim of the OIDC token, which names the workflow the tag started, not the reusable workflow it calls. With that in place no crates.io token is stored anywhere; the job gets one that lasts about 30 minutes.
- **Homebrew.** The `HOMEBREW_TAP_TOKEN` repository secret, a fine-grained token that can write to hugomn/homebrew-tap.
- **Tools.** `cargo`, `dist` 0.33 and `gh`, logged in.

To release, put the changes under `## [Unreleased]` in CHANGELOG.md, then from a branch based on `origin/main`:

```sh
scripts/release.sh X.Y.Z --dry-run   # bump, checks, and what it would push
scripts/release.sh X.Y.Z
```

The script bumps the version in Cargo.toml, Cargo.lock, CHANGELOG.md and the docs, runs fmt, clippy, the tests and `dist plan`, squashes the branch into one commit named `heldkeys X.Y.Z`, and asks before it pushes main, the `vX.Y.Z` tag and the moved `v0` tag. It then waits for the Release workflow and prints the release URL. `--yes` skips the question, and `--brew` upgrades the Homebrew install at the end to check the formula.

## Reporting security issues

Please do not open a public issue. See [SECURITY.md](SECURITY.md).
