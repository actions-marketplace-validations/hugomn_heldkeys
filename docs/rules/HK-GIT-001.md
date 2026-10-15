# HK-GIT-001: Git credential helper that stores logins in plaintext

| Check | Runs in | Default severity |
|---|---|---|
| `git-helper` | `heldkeys scan` | Medium |

## What it detects

`helper = store` in a `[credential]` or `[credential "<url>"]` section of `~/.gitconfig` or `~/.config/git/config`.

## Why it matters for agents

A credential helper answers `git credential fill` for any process running as you. Whatever it stores, usually a token that can push, is reachable even when no file holds it in plaintext. With `store`, the logins also sit in plaintext in `~/.git-credentials` (see [HK-GITCRED-001](HK-GITCRED-001.md)).

## How to fix

- Switch to a keychain-backed helper (`osxkeychain`, `libsecret`, `manager`) and delete `~/.git-credentials`.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-helper",
  "rule": "HK-GIT-001",
  "title": "Git credential helper stores plaintext",
  "location": "~/.gitconfig [credential https://git.example.com]",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "helper store for https://git.example.com; any process can ask it via git credential fill",
  "fix": "Switch to a keychain-backed helper (osxkeychain, libsecret, manager) and delete ~/.git-credentials.",
  "category": "git"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [git-credential-store](https://git-scm.com/docs/git-credential-store)
- [gitcredentials: providing usernames and passwords to Git](https://git-scm.com/docs/gitcredentials)
