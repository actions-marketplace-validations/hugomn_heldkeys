# HK-CLI-004: Netlify CLI login token in config.json

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`users.<id>.auth.token` in the Netlify CLI's `config.json`: `~/.netlify/config.json`, `~/Library/Preferences/netlify/config.json` (macOS) or `~/.config/netlify/config.json` (Linux). One finding per user.

## Why it matters for agents

The token can deploy and configure every site of every team the account belongs to, including environment variables.

## How to fix

- Run `netlify logout` where agents run.
- Use a personal access token with an expiry for automation.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-004",
  "title": "Netlify CLI login token",
  "location": "~/.netlify/config.json [0000fakeuser]",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Netlify CLI: users.*.auth.token",
  "fix": "Run netlify logout where agents run; use a personal access token with an expiry for automation.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Netlify CLI](https://docs.netlify.com/cli/get-started/)
