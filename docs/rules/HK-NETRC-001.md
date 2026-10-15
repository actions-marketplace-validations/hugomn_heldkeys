# HK-NETRC-001: Token of a known format in ~/.netrc

| Check | Runs in | Default severity |
|---|---|---|
| `netrc` | `heldkeys scan` | Depends on the token format; usually High. |

## What it detects

A `password` in `~/.netrc` (or `$NETRC`) whose value matches a known token format, such as a GitHub token for `api.github.com`.

## Why it matters for agents

curl, git, pip, Heroku and many other tools read `.netrc` automatically. A token here is used by any command the agent runs against that host, with no prompt and no sign in the command line.

## How to fix

- Remove the entry from `.netrc`.
- Use a credential helper or a short-lived token for that host.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "netrc",
  "rule": "HK-NETRC-001",
  "title": "GitHub personal access token (classic)",
  "location": "~/.netrc (machine api.github.com)",
  "fingerprint": "ghp_…008",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Remove the entry from .netrc; use a credential helper or a short-lived token for that host.",
  "category": "git"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Everything curl: .netrc](https://everything.curl.dev/usingcurl/netrc.html)
