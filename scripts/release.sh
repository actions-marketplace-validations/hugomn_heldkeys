#!/usr/bin/env bash
#
# Cut a heldkeys release from the current branch.
#
#   scripts/release.sh X.Y.Z [--dry-run] [--yes] [--brew]
#
# 1. Refuses unless the working tree is clean, X.Y.Z is newer than Cargo.toml
#    and origin/main is an ancestor of HEAD.
# 2. Bumps Cargo.toml and Cargo.lock, dates the Unreleased section of
#    CHANGELOG.md and updates the version examples in the docs.
# 3. Runs fmt, clippy, the tests and `dist plan`, then $HELDKEYS_RELEASE_HOOK
#    with the version if it is set, for any extra checks of your own.
# 4. Squashes everything since origin/main into one commit, "heldkeys X.Y.Z",
#    and asks before going further.
# 5. Pushes main and tags vX.Y.Z.
# 6. Waits for the Release workflow, then moves the vMAJOR tag. The action
#    installs the binary of its own release, so vMAJOR only moves once that
#    release has its binaries.
#
# --dry-run does steps 1 to 3, prints what steps 4 to 6 would do, and then puts
# the files back as they were. --yes skips the confirmation. --brew upgrades
# hugomn/tap/heldkeys at the end and checks the installed version.
#
# The tag starts .github/workflows/release.yml, which builds the binaries,
# creates the GitHub release, updates the Homebrew formula and publishes to
# crates.io with Trusted Publishing. Nothing here needs a token beyond your
# usual git and gh logins.

set -euo pipefail

REPO="hugomn/heldkeys"
REPO_URL="https://github.com/${REPO}"

# Files the version bump touches. They are restored if the script stops before
# the release commit, so a failed run leaves the tree as it found it.
BUMP_FILES=(Cargo.toml Cargo.lock CHANGELOG.md README.md action.yml docs/github-action.md docs/sandboxes.md)

usage() {
  sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

die() {
  echo "release: $*" >&2
  exit 1
}

step() {
  echo
  echo "==> $*"
}

# --- arguments ---------------------------------------------------------------

VERSION=""
DRY_RUN=0
YES=0
BREW=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --yes) YES=1 ;;
    --brew) BREW=1 ;;
    -h | --help) usage 0 ;;
    -*) die "unknown option: $arg" ;;
    *)
      [[ -z "$VERSION" ]] || die "only one version, please"
      VERSION="$arg"
      ;;
  esac
done
[[ -n "$VERSION" ]] || usage
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like 1.2.3, got: $VERSION"

TAG="v${VERSION}"
MAJOR_TAG="v${VERSION%%.*}"
TODAY="$(date +%Y-%m-%d)"

# Work from the repository root wherever the script is called from.
cd "$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"

for tool in git cargo dist; do
  command -v "$tool" > /dev/null || die "$tool is not installed"
done
if [[ "$DRY_RUN" -eq 0 ]]; then
  command -v gh > /dev/null || die "gh is not installed (needed to watch the release)"
fi

# Succeeds when version $1 is newer than version $2. Plain X.Y.Z only.
version_newer() {
  local a1 a2 a3 b1 b2 b3
  IFS=. read -r a1 a2 a3 <<< "$1"
  IFS=. read -r b1 b2 b3 <<< "$2"
  if ((a1 != b1)); then
    ((a1 > b1))
  elif ((a2 != b2)); then
    ((a2 > b2))
  else
    ((a3 > b3))
  fi
}

# Escapes the dots of a version for use in a regular expression.
re() {
  printf '%s' "${1//./\\.}"
}

# Rewrites a file in place with a filter command (sed or awk, given the file
# as its last argument), the same way on macOS and Linux. Fails if the file did
# not change, so a reworded doc is noticed instead of silently skipped.
#   edit FILE sed -E -e 's/a/b/'
edit() {
  local file="$1"
  shift
  local tmp
  tmp="$(mktemp)"
  "$@" "$file" > "$tmp"
  if cmp -s "$file" "$tmp"; then
    rm -f "$tmp"
    die "$file: expected a version to update and found none"
  fi
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

# --- 1. preconditions --------------------------------------------------------

step "Checking the working tree"

[[ -z "$(git status --porcelain)" ]] || die "the working tree is not clean; commit or stash first"

CURRENT="$(sed -n -E 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' Cargo.toml | head -n 1)"
[[ -n "$CURRENT" ]] || die "could not read the package version from Cargo.toml"
version_newer "$VERSION" "$CURRENT" || die "$VERSION is not newer than Cargo.toml's $CURRENT"
echo "Cargo.toml is at $CURRENT, releasing $VERSION"

# The release notes come from CHANGELOG.md, so the Unreleased section must say
# something, and its compare link must start at the current version.
unreleased_lines="$(awk '
  /^## \[Unreleased\]/ { inside = 1; next }
  inside && /^## \[/ { exit }
  inside && NF { n++ }
  END { print n + 0 }
' CHANGELOG.md)"
[[ "$unreleased_lines" -gt 0 ]] || die "the [Unreleased] section of CHANGELOG.md is empty; describe the release first"
grep -q "^\[Unreleased\]: ${REPO_URL}/compare/v$(re "$CURRENT")\.\.\.HEAD$" CHANGELOG.md \
  || die "CHANGELOG.md: expected the link [Unreleased]: ${REPO_URL}/compare/v${CURRENT}...HEAD"

git fetch --quiet --tags origin
git merge-base --is-ancestor origin/main HEAD || die "origin/main is not an ancestor of HEAD; rebase on origin/main first"
if git rev-parse -q --verify "refs/tags/${TAG}" > /dev/null; then
  die "tag $TAG already exists"
fi

BEFORE="$(git rev-parse HEAD)"
echo "HEAD is $(git log -1 --format='%h %s'), $(git rev-list --count origin/main..HEAD) commit(s) ahead of origin/main"

# From here until the release commit, put the files back on any exit.
RESTORE=1
restore() {
  if [[ "$RESTORE" -eq 1 ]]; then
    git checkout --quiet HEAD -- "${BUMP_FILES[@]}"
  fi
}
trap restore EXIT

# --- 2. bump -----------------------------------------------------------------

step "Bumping $CURRENT to $VERSION"

# The package version is the only line in Cargo.toml that starts with
# `version =`; dependency versions sit inside braces.
edit Cargo.toml sed -E -e "s/^version = \"$(re "$CURRENT")\"$/version = \"${VERSION}\"/"
cargo update --offline --quiet -p heldkeys
grep -q -A1 '^name = "heldkeys"$' Cargo.lock || die "heldkeys is missing from Cargo.lock"
grep -A1 '^name = "heldkeys"$' Cargo.lock | grep -q "^version = \"${VERSION}\"$" \
  || die "Cargo.lock still has the old heldkeys version"

# CHANGELOG.md: date the Unreleased section and fix the compare links.
# shellcheck disable=SC2016 # the $0 in the awk program is awk's, not the shell's
edit CHANGELOG.md awk -v version="$VERSION" -v today="$TODAY" -v current="$CURRENT" -v url="$REPO_URL" '
  $0 == "## [Unreleased]" {
    print
    print ""
    print "## [" version "] - " today
    next
  }
  $0 == "[Unreleased]: " url "/compare/v" current "...HEAD" {
    print "[Unreleased]: " url "/compare/v" version "...HEAD"
    print "[" version "]: " url "/compare/v" current "...v" version
    next
  }
  { print }
'

# Version examples in the docs: the SHA pin comment, "such as A.B.C" and the
# container image tag.
old="$(re "$CURRENT")"
edit README.md sed -E -e "s/(hugomn\/heldkeys@[^ ]+ # v)${old}([^0-9]|$)/\1${VERSION}\2/g"
edit action.yml sed -E \
  -e "s/(such as \`?)${old}([^0-9]|$)/\1${VERSION}\2/g" \
  -e "s/^(    default: \")${old}\"$/\1${VERSION}\"/"
edit docs/github-action.md sed -E \
  -e "s/(hugomn\/heldkeys@[^ ]+ # v)${old}([^0-9]|$)/\1${VERSION}\2/g" \
  -e "s/(such as \`?)${old}([^0-9]|$)/\1${VERSION}\2/g"
edit docs/sandboxes.md sed -E -e "s/(heldkeys:)${old}([^0-9]|$)/\1${VERSION}\2/g"

leftover="$(grep -n -F "$CURRENT" README.md action.yml docs/github-action.md docs/sandboxes.md || true)"
if [[ -n "$leftover" ]]; then
  echo "Note: these lines still mention $CURRENT; check whether they should:"
  echo "$leftover"
fi

git --no-pager diff --stat

# --- 3. checks ---------------------------------------------------------------

step "cargo fmt --check"
cargo fmt --all --check

step "cargo clippy"
cargo clippy --all-targets --locked -- -D warnings

step "cargo test"
HELDKEYS_NO_NET=1 cargo test --locked

step "dist plan"
dist plan

if [[ -n "${HELDKEYS_RELEASE_HOOK:-}" ]]; then
  [[ -x "$HELDKEYS_RELEASE_HOOK" ]] || die "HELDKEYS_RELEASE_HOOK is set but $HELDKEYS_RELEASE_HOOK is not executable"
  step "Release hook"
  "$HELDKEYS_RELEASE_HOOK" "$VERSION" || die "the release hook failed"
fi

# --- dry run stops here ------------------------------------------------------

if [[ "$DRY_RUN" -eq 1 ]]; then
  step "Dry run: everything above passed. A real run would now:"
  cat << EOF
  git add ${BUMP_FILES[*]}
  git reset --soft origin/main
  git commit -m "heldkeys ${VERSION}"     # $(git rev-list --count origin/main..HEAD) commit(s) plus the bump, squashed
  git show --stat HEAD                    # then ask y/N$([[ "$YES" -eq 1 ]] && echo " (skipped: --yes)")
  git push origin HEAD:main
  git tag -a ${TAG} -m "heldkeys ${VERSION}"
  git push origin refs/tags/${TAG}
  gh run watch <Release run for ${TAG}> --exit-status
  git tag -f ${MAJOR_TAG}
  git push --force origin refs/tags/${MAJOR_TAG}
  gh release view ${TAG} --json url$([[ "$BREW" -eq 1 ]] && printf '\n  brew update && brew upgrade hugomn/tap/heldkeys')
EOF
  echo
  echo "The bumped files are being restored; nothing was committed, tagged or pushed."
  exit 0
fi

# --- 4. squash and confirm ---------------------------------------------------

step "Squashing into one commit: heldkeys $VERSION"

git add "${BUMP_FILES[@]}"
RESTORE=0
git reset --quiet --soft origin/main
if ! git commit --quiet -m "heldkeys ${VERSION}"; then
  git reset --quiet --soft "$BEFORE"
  die "git commit failed; the branch is back at $BEFORE with the bump staged"
fi
git --no-pager show --stat HEAD

if [[ "$YES" -ne 1 ]]; then
  echo
  answer=""
  read -r -p "Push main and ${TAG} (and move ${MAJOR_TAG} once it is released)? [y/N] " answer || true
  if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
    echo "Stopped. Nothing was pushed. The squashed commit is local only."
    echo "To go back to the commits you had: git reset --hard $BEFORE"
    exit 1
  fi
fi

# --- 5. push and tag ---------------------------------------------------------

step "Pushing main and ${TAG}"
git push origin HEAD:main
git tag -a "$TAG" -m "heldkeys ${VERSION}"
git push origin "refs/tags/${TAG}"

# --- 6. watch the release ----------------------------------------------------

step "Waiting for the Release workflow"
run_id=""
for _ in $(seq 1 30); do
  run_id="$(gh run list --repo "$REPO" --workflow release.yml --branch "$TAG" --event push \
    --limit 1 --json databaseId --jq '.[0].databaseId // empty' || true)"
  [[ -n "$run_id" ]] && break
  sleep 5
done
[[ -n "$run_id" ]] || die "no Release run for $TAG after 150 seconds; see ${REPO_URL}/actions"

gh run watch "$run_id" --repo "$REPO" --exit-status \
  || die "the Release workflow failed: ${REPO_URL}/actions/runs/${run_id}; ${MAJOR_TAG} was not moved"

step "Moving ${MAJOR_TAG} to ${TAG}"
# A lightweight tag, like the existing v0.
git tag -f "$MAJOR_TAG"
git push --force origin "refs/tags/${MAJOR_TAG}"

release_url="$(gh release view "$TAG" --repo "$REPO" --json url --jq .url)"
echo
echo "Released heldkeys ${VERSION}: ${release_url}"
echo "crates.io: https://crates.io/crates/heldkeys/${VERSION}"

if [[ "$BREW" -eq 1 ]]; then
  step "Checking Homebrew"
  brew update --quiet
  if brew list --versions heldkeys > /dev/null 2>&1; then
    brew upgrade hugomn/tap/heldkeys || true
  else
    brew install hugomn/tap/heldkeys
  fi
  installed="$("$(brew --prefix)/bin/heldkeys" --version)"
  echo "$installed"
  [[ "$installed" == *"$VERSION"* ]] || die "Homebrew installed '$installed', expected $VERSION"
fi
