# Building heldkeys

heldkeys is meant to be dropped into places that have nothing installed: a container image, a hosted sandbox, a CI job. For Linux that means a **static musl binary**: one file, no libc, no runtime, no `HOME` needed, and it works on a read-only filesystem. This page explains how to build one yourself. The release binaries are built by `.github/workflows/release.yml`.

## The usual build

```sh
cargo build --release
# target/release/heldkeys
```

That gives you a binary for the machine you are on. On macOS it is a Mach-O binary, which is fine for scanning your laptop but cannot run inside a Linux container. `heldkeys scan --docker` and `--kube` detect this and ask for `--binary <path>` to a Linux build.

## Static Linux builds

Two targets cover nearly every container and sandbox:

| Target | For |
|---|---|
| `x86_64-unknown-linux-musl` | Intel/AMD Linux: most cloud VMs, E2B, Daytona, Modal, Vercel Sandbox, Cloudflare Sandbox, GitHub-hosted runners |
| `aarch64-unknown-linux-musl` | ARM Linux: Graviton and Ampere VMs, Docker on Apple silicon (containers there are arm64 unless you ask for amd64) |

The dependencies are all pure Rust (clap, owo-colors, regex, serde, serde_json, toml, yaml-rust2): no OpenSSL, no C libraries. Rust's musl targets ship their own musl C runtime, so the only thing a build needs is a linker for the target.

### On a Linux machine of the same architecture

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# target/x86_64-unknown-linux-musl/release/heldkeys
```

The system `cc` usually works as the linker. If the link step fails, install your distribution's musl tools (`musl-tools` on Debian and Ubuntu) and try again.

### Cross-compiling (from macOS, or for the other architecture)

Pick one of these. Either works.

**cargo-zigbuild**, which uses Zig as a cross linker:

```sh
# one-time setup
brew install zig            # or your platform's zig package
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# builds
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

**cross**, which builds inside a Docker container with the right toolchain:

```sh
cargo install cross
cross build --release --target x86_64-unknown-linux-musl
cross build --release --target aarch64-unknown-linux-musl
```

The binaries land in `target/<target>/release/heldkeys`.

### Checking the result

```sh
file target/x86_64-unknown-linux-musl/release/heldkeys
# ... ELF 64-bit LSB pie executable, x86-64, ... static-pie linked, stripped
```

Look for `statically linked` or `static-pie linked`. A `dynamically linked ... interpreter /lib/ld-linux...` binary is a glibc build: it runs on most full distributions but not in Alpine, distroless or scratch images. `heldkeys scan --docker/--kube` reads the ELF header of the binary it is about to copy and refuses one built for the wrong CPU, and warns about one that is dynamically linked.

A quick smoke test in an empty image:

```sh
docker run --rm -v "$PWD/target/x86_64-unknown-linux-musl/release/heldkeys:/heldkeys:ro" \
  --read-only gcr.io/distroless/static /heldkeys preflight
```

## What the code assumes about the system

So that one static binary runs anywhere, the code avoids anything glibc-specific:

- **No C dependencies, no dynamic loading, no `getaddrinfo`.** The single network probe (`cloud-metadata`) connects to a literal IP address with a 300 ms timeout and sends nothing.
- **No home directory required.** Without `--home`, heldkeys uses `$HOME`, then the passwd entry, then `/` (what Docker does for users without one). A home directory that does not exist is scanned as empty rather than being an error.
- **Read-only.** It never writes, except the `--output` file you ask for, so a read-only root filesystem is fine.
- **Optional helper programs.** `ssh-add -l` is run if it is on `PATH` (for the `ssh-agent` check); without it, keys loaded in a running agent are not listed, but passphrase-less key files in `~/.ssh` still are. `git` is run only by `ci --repo-secrets`, for `git ls-files`. `docker` and `kubectl` are used only by `scan --docker/--kube`, on the machine you run that from, never inside the target. All four are found through `PATH`, so whoever controls `PATH` decides which program runs (see the [threat model](threat-model.md)).
- **Unix APIs only from `std`.** `std::os::unix` (Unix sockets for the Docker socket check) works the same on musl.

## Release profile

`Cargo.toml` already sets `lto = true`, `codegen-units = 1` and `strip = true` for release builds, to keep the binary small enough to upload to a sandbox in one call.
