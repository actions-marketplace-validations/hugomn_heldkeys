# HK-GITCRED-001: Plaintext git login in a credential-store file

| Check | Runs in | Default severity |
|---|---|---|
| `git-credentials` | `heldkeys scan` | High |

## What it detects

A `https://user:secret@host` line in `~/.git-credentials` or `~/.config/git/credentials`, written by `credential.helper = store`. The title names the token format when it is recognised.

## Why it matters for agents

Each line is a working login, in plaintext, that can usually push code. A hijacked agent can read the file, or simply push to any repository on that host.

## How to fix

- Switch to a keychain-backed helper (`osxkeychain`, `libsecret`, `manager`) or `gh auth`.
- Delete the file and rotate every token that was in it.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-credentials",
  "rule": "HK-GITCRED-001",
  "title": "Plaintext git password",
  "location": "~/.git-credentials (git.example.com)",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Switch to a keychain-backed helper (osxkeychain, libsecret, manager) or gh auth, then delete the file and rotate the token.",
  "category": "git"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [git-credential-store](https://git-scm.com/docs/git-credential-store)
- [gitcredentials: providing usernames and passwords to Git](https://git-scm.com/docs/gitcredentials)
