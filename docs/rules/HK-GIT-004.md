# HK-GIT-004: Git credential helper backed by a keychain or other store

| Check | Runs in | Default severity |
|---|---|---|
| `git-helper` | `heldkeys scan` | Medium |

## What it detects

Any other credential helper, such as `osxkeychain`, `libsecret`, `manager` or a custom program.

## Why it matters for agents

A credential helper answers `git credential fill` for any process running as you. Whatever it stores, usually a token that can push, is reachable even when no file holds it in plaintext. Keychain helpers protect logins at rest, not from processes running as you: they answer without a prompt once the keychain is unlocked.

## How to fix

- Run agents under a user or sandbox without your git logins.
- Or use fine-grained, read-only tokens for what the agent needs.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-helper",
  "rule": "HK-GIT-004",
  "title": "Git credential helper",
  "location": "~/.gitconfig [credential]",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "helper osxkeychain for all hosts; any process can ask it via git credential fill",
  "fix": "Run agents under a user or sandbox without your git logins, or use fine-grained, read-only tokens.",
  "category": "git"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [gitcredentials: providing usernames and passwords to Git](https://git-scm.com/docs/gitcredentials)
