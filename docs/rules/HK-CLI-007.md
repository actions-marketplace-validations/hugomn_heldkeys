# HK-CLI-007: Cloudflare Wrangler OAuth or API token in its config

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`oauth_token`, `refresh_token` and `api_token` in Wrangler's `default.toml`: `~/Library/Preferences/.wrangler/config/default.toml` (macOS), `~/.config/.wrangler/config/default.toml` (Linux, or under `$XDG_CONFIG_HOME`) and the older `~/.wrangler/config/default.toml`.

## Why it matters for agents

The access token expires within hours, but the refresh token does not, and `wrangler login` asks for broad scopes: Workers, Pages, KV, R2, D1 and DNS on every account you can reach.

## How to fix

- Run `wrangler logout` where agents run.
- Use an API token scoped to one account and the permissions needed, passed through `CLOUDFLARE_API_TOKEN` only where it is used.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-007",
  "title": "Cloudflare Wrangler login tokens",
  "location": "~/.config/.wrangler/config/default.toml",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Wrangler: refresh_token, oauth_token",
  "fix": "Run wrangler logout where agents run; use an API token scoped to one account and the permissions needed.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Wrangler commands: login](https://developers.cloudflare.com/workers/wrangler/commands/#login)
