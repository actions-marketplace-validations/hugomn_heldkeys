# HK-CARGO-001: Cargo registry token in credentials.toml

| Check | Runs in | Default severity |
|---|---|---|
| `cargo-credentials` | `heldkeys scan` | High |

## What it detects

A `token` in `~/.cargo/credentials.toml` or the older `~/.cargo/credentials` (or under `CARGO_HOME`), for crates.io or another registry.

## Why it matters for agents

`cargo login` stores the token in plaintext unless a credential provider is configured. It can publish new versions of every crate the account owns.

## How to fix

- Run `cargo logout`.
- Configure a credential provider (`cargo:macos-keychain`, `cargo:libsecret`) and a token scoped to specific crates and endpoints.
- Publish from CI with trusted publishing where the registry supports it.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cargo-credentials",
  "rule": "HK-CARGO-001",
  "title": "Cargo registry token",
  "location": "~/.cargo/credentials.toml [registry]",
  "fingerprint": "cioF…E12",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Run cargo logout, or configure a credential provider (cargo:macos-keychain, cargo:libsecret) and a scoped token.",
  "category": "package-registry"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Cargo: registry authentication](https://doc.rust-lang.org/cargo/reference/registry-authentication.html)
- [cargo logout](https://doc.rust-lang.org/cargo/commands/cargo-logout.html)
