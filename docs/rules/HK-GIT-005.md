# HK-GIT-005: GitHub CLI token stored in plaintext hosts.yml

| Check | Runs in | Default severity |
|---|---|---|
| `git-helper` | `heldkeys scan` | High |

## What it detects

An `oauth_token` in `~/.config/gh/hosts.yml` (or `GH_CONFIG_DIR`). gh writes it there when no OS keyring is available, or with `gh auth login --insecure-storage`.

## Why it matters for agents

gh's default scopes include `repo`, which can push to every repository you can access, plus `read:org` and `gist`. The token is long-lived and plaintext.

## How to fix

- Use a fine-grained token with only the repositories and permissions the agent needs.
- Or run `gh auth logout` before handing the shell to an agent.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "git-helper",
  "rule": "HK-GIT-005",
  "title": "GitHub OAuth token",
  "location": "~/.config/gh/hosts.yml (github.com)",
  "fingerprint": "gho_…013",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "GitHub CLI token stored in plaintext",
  "fix": "Use a fine-grained token with only the repositories and permissions the agent needs, or gh auth logout.",
  "category": "git"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [gh auth login](https://cli.github.com/manual/gh_auth_login)
- [GitHub: managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
