# demo.tape: records docs/assets/demo.gif with VHS (https://github.com/charmbracelet/vhs).
#
#   vhs demo.tape
#
# Run it from the repository root. Everything it scans is a temporary copy of
# the fake fixtures in tests/fixtures. The hidden setup wraps heldkeys in
# `env -i`, so the recording never sees your real environment, and passes
# --home and --root so every path resolves inside the copy, never on your
# machine. The README samples come from the same setup.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set LineHeight 1.05
# About 104 columns and 43 rows: heldkeys gets no COLUMNS through `env -i`,
# so it lays out for 100 columns, and the summary (about 40 lines) fits on
# one screen without wrapping or scrolling.
Set Width 1080
Set Height 1020
Set Padding 20
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set CursorBlink false

# --- Setup (not recorded) ---------------------------------------------------
Hide
Type `cargo build --release --quiet && REPO="$PWD"` Enter
Type `DEMO="$(mktemp -d)" && cp -R tests/fixtures/full/. "$DEMO" && cd "$DEMO"` Enter
# Keep a tidy subset of the full fixture so the summary fits on one screen.
Type `rm -rf .aws/config .aws/sso .azure .cargo .config/gcloud/credentials.db .config/gcloud/legacy_credentials .git-credentials .gitconfig .kube .netrc .pypirc var` Enter
Type `printf '{"auths":{"https://index.docker.io/v1/":{"auth":"ZmFrZXVzZXI6RkFLRWRvY2tlclBBU1MwMDA3"}}}' > .docker/config.json` Enter
Type `mkdir -p code/app .ssh && cp "$REPO"/tests/fixtures/project/.env "$REPO"/tests/fixtures/project/.env.local code/app/` Enter
# A fake unencrypted OpenSSH key. The header is assembled at runtime so that
# secret scanners do not flag this file.
Type `printf -- '-----BEGIN %s PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABFAKEsshKEYbody0201\n-----END %s PRIVATE KEY-----\n' OPENSSH OPENSSH > .ssh/id_ed25519` Enter
# Every call goes through this function: a cleared environment with two fake
# tokens, as if exported in a shell profile (GITHUB_TOKEN is the same fake
# token as the one in the fixture's Cursor MCP config), and --home, --root
# and --path pointing into the copy.
Type `heldkeys() { env -i PATH=/usr/bin:/bin HELDKEYS_NO_NET=1 GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000021 ANTHROPIC_API_KEY=sk-ant-api03-FAKEFAKEFAKEFAKEFAKE-FAKE "$REPO/target/release/heldkeys" --home "$DEMO" --root "$DEMO" --path "$DEMO/code/app" "$@"; }` Enter
Type `export PS1='$ ' && clear` Enter
Show

# --- Scene 1: what can an agent in this shell reach? ------------------------
Sleep 800ms
Type "heldkeys"
Sleep 600ms
Enter
Sleep 9s

# --- Scene 2: every finding, by place and file -------------------------------
Type "clear" Enter
Type "heldkeys --details | head -n 22"
Sleep 600ms
Enter
Sleep 5s

# --- Scene 3: preflight as a gate in a sandbox entrypoint --------------------
Type "clear" Enter
Type `heldkeys preflight --fail-on long-lived-write; echo "exit $?"`
Sleep 600ms
Enter
Sleep 5s

# --- Scene 4: an AI agent step in a GitHub workflow -------------------------
Hide
Type `mkdir -p code/app/.github/workflows && cp "$REPO/docs/assets/demo-workflow.yml" code/app/.github/workflows/triage.yml && clear` Enter
Show
Type "heldkeys ci"
Sleep 600ms
Enter
Sleep 8s

# --- Cleanup (not recorded) -------------------------------------------------
Hide
Type `cd "$REPO" && rm -rf "$DEMO"` Enter
