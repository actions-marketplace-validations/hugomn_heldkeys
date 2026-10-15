# HK-GITCFG-002: Authorization header in git http.extraheader

| Check | Runs in | Default severity |
|---|---|---|
| `git-config` | `heldkeys scan`, `heldkeys preflight`, `heldkeys ci` (repository config only) | High |

## What it detects

An `extraheader` entry in an `[http]` or `[http "<url>"]` section that carries a credential: an `Authorization` (or `Proxy-Authorization`) header with a `basic`, `bearer` or `token` value, or any header holding a token of a known format. Read from `~/.gitconfig`, `$XDG_CONFIG_HOME/git/config` and `./.git/config`; `heldkeys ci` reads only `./.git/config`, and inside GitHub Actions it skips `Authorization` headers there, which [HK-CI-005](HK-CI-005.md) reports. For `basic`, the base64 value is decoded in memory only to recognise the token format.

## Why it matters for agents

`actions/checkout` writes this header (with `GITHUB_TOKEN`) and many scripts copy the pattern. git sends the header to that host on every fetch and push, and any process that can read the file can copy it. In CI, heldkeys reports the checkout case as [HK-CI-005](HK-CI-005.md); this rule covers the same header anywhere else.

## How to fix

- Remove it: `git config --unset-all http.<url>.extraheader` (or `--global` for `~/.gitconfig`).
- Rotate the token.
- Use a credential helper instead. In GitHub Actions, use `persist-credentials: false` on `actions/checkout`.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-config",
  "rule": "HK-GITCFG-002",
  "title": "Auth header in git http.extraheader",
  "location": "~/.gitconfig [http https://github.com]",
  "fingerprint": "ghp_…992",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "git sends this header to https://github.com on every fetch and push",
  "fix": "Remove it (git config --unset-all http.<url>.extraheader), rotate the token, and use a credential helper instead.",
  "category": "git"
}
```

## References

- [git-config: http.extraHeader](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpextraHeader)
- [actions/checkout: persist-credentials](https://github.com/actions/checkout#usage)
