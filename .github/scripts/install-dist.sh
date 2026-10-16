#!/usr/bin/env bash
# Installs cargo-dist for the release workflow from its release archive,
# checked against a SHA-256 pinned here, instead of piping its installer
# script into sh. Bump DIST_VERSION and the hashes together with
# cargo-dist-version in dist-workspace.toml.
set -euo pipefail

DIST_VERSION=0.33.0

case "${RUNNER_OS}/${RUNNER_ARCH}" in
  Linux/X64)
    target=x86_64-unknown-linux-gnu
    sha=4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293 ;;
  Linux/ARM64)
    target=aarch64-unknown-linux-gnu
    sha=9c554ab21a58ad46eb9b6710f89633ccb26bc2577cf4b0c2d18a5b826a31913e ;;
  macOS/X64)
    target=x86_64-apple-darwin
    sha=6a49bfb61bd86770d79c27f3d2b40c6b2e71cde940d3d31a6ccaaffc124d7a29 ;;
  macOS/ARM64)
    target=aarch64-apple-darwin
    sha=7b3cbe25511de01d74c0f5fcb7909edabd379bea9cfa284d93af5a3cdfa3247c ;;
  *)
    echo "::error::no pinned cargo-dist for ${RUNNER_OS}/${RUNNER_ARCH}"
    exit 1 ;;
esac

asset="cargo-dist-${target}.tar.xz"
dir="${RUNNER_TEMP}/cargo-dist"
rm -rf "$dir"
mkdir -p "$dir"
curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$dir/$asset" \
  "https://github.com/axodotdev/cargo-dist/releases/download/v${DIST_VERSION}/${asset}"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$dir/$asset" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$dir/$asset" | awk '{print $1}')"
fi
if [ "$actual" != "$sha" ]; then
  echo "::error::checksum mismatch for $asset (expected $sha, got $actual)"
  exit 1
fi

tar -xJf "$dir/$asset" -C "$dir"
mkdir -p "$HOME/.cargo/bin"
install -m 755 "$dir/cargo-dist-${target}/dist" "$HOME/.cargo/bin/dist"
echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
"$HOME/.cargo/bin/dist" --version
