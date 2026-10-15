# HK-GIT-003: Git configured to use the GitHub CLI token

| Check | Runs in | Default severity |
|---|---|---|
| `git-helper` | `heldkeys scan` | Medium |

## What it detects

A credential helper that runs `gh auth git-credential`, as set up by `gh auth setup-git`.

## Why it matters for agents

A credential helper answers `git credential fill` for any process running as you. Whatever it stores, usually a token that can push, is reachable even when no file holds it in plaintext. Here the helper hands out your `gh` login, which by default has the `repo` scope on every repository you can access.

## How to fix

- Run the agent with a separate, fine-grained token instead of your `gh` login.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-helper",
  "rule": "HK-GIT-003",
  "title": "Git uses the GitHub CLI token",
  "location": "~/.gitconfig [credential https://github.com]",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "helper gh for https://github.com; any process can ask it via git credential fill",
  "fix": "Run the agent with a separate, fine-grained token instead of your gh login.",
  "category": "git"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [gh auth login](https://cli.github.com/manual/gh_auth_login)
- [GitHub: managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [gitcredentials: providing usernames and passwords to Git](https://git-scm.com/docs/gitcredentials)
