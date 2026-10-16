# HK-AI-004: Gemini CLI OAuth login or API key on disk

| Check | Runs in | Default severity |
|---|---|---|
| `ai-logins` | `heldkeys scan`, `heldkeys preflight` | High, or by format for ~/.gemini/.env |

## What it detects

`~/.gemini/oauth_creds.json`, where Gemini CLI keeps a Google sign-in (`refresh_token`, `access_token`), and `~/.gemini/.env`, which Gemini CLI loads for `GEMINI_API_KEY`, `GOOGLE_API_KEY` and similar. Entries in the `.env` file are judged like environment variables.

## Why it matters for agents

The OAuth login is a Google refresh token. Gemini CLI asks for the `cloud-platform` scope, so a copied token can reach Google Cloud as you, not only Gemini. An API key in `~/.gemini/.env` spends from the project it belongs to.

## How to fix

- Delete `~/.gemini/oauth_creds.json` (or switch the sign-in method with `/auth`) where other agents run.
- Use an API key restricted to the Gemini API, with a quota, and keep it out of plain files.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "ai-logins",
  "rule": "HK-AI-004",
  "title": "Gemini CLI Google OAuth tokens",
  "location": "~/.gemini/oauth_creds.json",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "Gemini CLI: refresh_token, access_token",
  "fix": "Delete ~/.gemini/oauth_creds.json where other agents run, or use an API key with narrow quotas; the login can reach Google Cloud.",
  "category": "ai-tools"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Gemini CLI](https://github.com/google-gemini/gemini-cli)
