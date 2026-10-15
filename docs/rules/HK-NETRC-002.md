# HK-NETRC-002: Plaintext password in ~/.netrc

| Check | Runs in | Default severity |
|---|---|---|
| `netrc` | `heldkeys scan` | High on cloud and source-control hosts, Medium elsewhere. |

## What it detects

A `password` in `~/.netrc` that does not match a known token format. No fingerprint is shown.

## Why it matters for agents

curl, git, pip and others read `.netrc` automatically, so the password is usable by any command the agent runs. Passwords do not expire on their own.

## How to fix

- Remove the entry from `.netrc`.
- Use a credential helper or a short-lived token for that host.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "netrc",
  "rule": "HK-NETRC-002",
  "title": "Plaintext password in .netrc",
  "location": "~/.netrc (machine ftp.example.com)",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Remove the entry from .netrc; use a credential helper or a short-lived token for that host.",
  "category": "git"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Everything curl: .netrc](https://everything.curl.dev/usingcurl/netrc.html)
