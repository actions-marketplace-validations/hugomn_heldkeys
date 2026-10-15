# HK-GIT-006: GitHub CLI login with its token in the OS keyring

| Check | Runs in | Default severity |
|---|---|---|
| `git-helper` | `heldkeys scan` | High |

## What it detects

A host in `~/.config/gh/hosts.yml` without an inline token: gh keeps it in the OS keyring.

## Why it matters for agents

The keyring protects the token at rest, not from processes running as you: `gh auth token` prints it, and every `gh` command uses it. The access is the same as a plaintext token.

## How to fix

- Use a fine-grained token with only the repositories and permissions the agent needs.
- Or run `gh auth logout` before handing the shell to an agent.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-helper",
  "rule": "HK-GIT-006",
  "title": "GitHub CLI login (token in OS keyring)",
  "location": "~/.config/gh/hosts.yml (github.com)",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "gh auth token prints it to any process running as this user",
  "fix": "Use a fine-grained token with only the repositories and permissions the agent needs, or gh auth logout.",
  "category": "git"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [gh auth token](https://cli.github.com/manual/gh_auth_token)
- [gh auth login](https://cli.github.com/manual/gh_auth_login)
- [GitHub: managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
