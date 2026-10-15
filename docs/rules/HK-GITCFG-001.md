# HK-GITCFG-001: Credential embedded in a git url.<base>.insteadOf rewrite

| Check | Runs in | Default severity |
|---|---|---|
| `git-config` | `heldkeys scan`, `heldkeys preflight`, `heldkeys ci` (repository config only) | High |

## What it detects

A `[url "https://user:TOKEN@host/"]` section with `insteadOf` (or `pushInsteadOf`) in `~/.gitconfig`, `$XDG_CONFIG_HOME/git/config` or the working directory's `.git/config`; `heldkeys ci` reads only the working directory's `.git/config`. A bare `https://TOKEN@host/` counts when the token has a known format; a plain user name such as `git@` does not.

## Why it matters for agents

This is a popular trick in CI scripts and Dockerfiles to make every `git clone` authenticate. The token sits in plaintext in a file any process running as the user can read, and git sends it on every fetch and push, so a hijacked agent can both copy it and push with it.

## How to fix

- Remove the credentials from the `[url]` section and delete the section if only the token made it useful.
- Rotate the token.
- Use a credential helper (`gh auth setup-git`, `osxkeychain`, `libsecret`) or, in CI, a short-lived token passed only to the step that needs it.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-config",
  "rule": "HK-GITCFG-001",
  "title": "Token in a git URL rewrite",
  "location": "~/.gitconfig [url https://github.com]",
  "fingerprint": "ghp_…991",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Remove the credentials from the [url] section, rotate the token, and use a credential helper or gh auth instead.",
  "category": "git"
}
```

Only the scheme and host of the URL are shown. The fingerprint appears only for tokens of a known format.

## References

- [git-config: url.<base>.insteadOf](https://git-scm.com/docs/git-config#Documentation/git-config.txt-urlltbasegtinsteadOf)
