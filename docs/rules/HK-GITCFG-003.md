# HK-GITCFG-003: Credential embedded in a git remote URL

| Check | Runs in | Default severity |
|---|---|---|
| `git-config` | `heldkeys scan`, `heldkeys preflight`, `heldkeys ci` (repository config only) | High |

## What it detects

A `url` or `pushurl` of a `[remote "<name>"]` section with credentials in it: `https://user:TOKEN@host/...`, or `https://TOKEN@host/...` when the token has a known format. Read from the working directory's `.git/config` and the global git config; `heldkeys ci` reads only the working directory's `.git/config`. When `.git` is a file (`gitdir: <dir>`), a directory outside the working directory is followed only if git's own back-pointer there names this working directory (a linked worktree or a submodule); otherwise the file is reported as not read ([HK-READ-001](HK-READ-001.md)).

## Why it matters for agents

The agent works inside the repository, so `.git/config` is one `cat` away, and every `git push` it runs uses the token. Tokens in remote URLs also leak through `git remote -v`, logs and error messages.

## How to fix

- `git remote set-url <name> <the URL without credentials>`.
- Rotate the token.
- Use a credential helper (`gh auth setup-git`, `osxkeychain`, `libsecret`).

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-config",
  "rule": "HK-GITCFG-003",
  "title": "Token in a git remote URL",
  "location": "./.git/config [remote origin]",
  "fingerprint": "ghp_…993",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "url points to https://github.com with credentials in the URL",
  "fix": "Run git remote set-url with the URL minus its credentials, rotate the token, and use a credential helper instead.",
  "category": "git"
}
```

## References

- [git-remote: set-url](https://git-scm.com/docs/git-remote#Documentation/git-remote.txt-emset-urlem)
