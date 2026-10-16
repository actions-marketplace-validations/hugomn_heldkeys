# HK-AI-005: GitHub Copilot OAuth token in apps.json or hosts.json

| Check | Runs in | Default severity |
|---|---|---|
| `ai-logins` | `heldkeys scan`, `heldkeys preflight` | Medium |

## What it detects

`oauth_token` entries in `~/.config/github-copilot/apps.json` and `~/.config/github-copilot/hosts.json` (under `$XDG_CONFIG_HOME` when it is set), written when an editor plugin (Vim, Neovim, JetBrains, Xcode, the Copilot language server) signs in to Copilot. One finding per host or app entry.

## Why it matters for agents

The token is a GitHub user token for the Copilot app. It does not expire, and anyone who copies it can use your Copilot seat and read your GitHub profile. It is narrower than a personal access token, which is why it is Medium.

## How to fix

- Sign out of Copilot in the editor where agents run.
- Revoke the GitHub Copilot app's authorization in your GitHub settings if the token may have been copied.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "ai-logins",
  "rule": "HK-AI-005",
  "title": "GitHub Copilot OAuth token",
  "location": "~/.config/github-copilot/hosts.json [github.com]",
  "fingerprint": "gho_…015",
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "read",
  "detail": "GitHub Copilot: *.oauth_token",
  "fix": "Sign out of Copilot where agents run, or revoke the GitHub Copilot app in your GitHub settings.",
  "category": "ai-tools"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [GitHub: reviewing and revoking authorization of GitHub Apps](https://docs.github.com/en/apps/using-github-apps/reviewing-and-revoking-authorization-of-github-apps)
