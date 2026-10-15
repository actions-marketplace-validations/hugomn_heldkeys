# HK-GIT-002: Git credential helper that caches logins in memory

| Check | Runs in | Default severity |
|---|---|---|
| `git-helper` | `heldkeys scan` | Medium |

## What it detects

`helper = cache` in a git config file.

## Why it matters for agents

A credential helper answers `git credential fill` for any process running as you. Whatever it stores, usually a token that can push, is reachable even when no file holds it in plaintext. The cache daemon holds logins in memory until its timeout, 15 minutes by default, often raised to hours.

## How to fix

- Lower the cache timeout, or run `git credential-cache exit` before handing the shell to an agent.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-helper",
  "rule": "HK-GIT-002",
  "title": "Git credential helper caches logins",
  "location": "~/.gitconfig [credential]",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "helper cache for all hosts; any process can ask it via git credential fill",
  "fix": "Lower the cache timeout, or run git credential-cache exit before handing the shell to an agent.",
  "category": "git"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [git-credential-cache](https://git-scm.com/docs/git-credential-cache)
- [gitcredentials: providing usernames and passwords to Git](https://git-scm.com/docs/gitcredentials)
