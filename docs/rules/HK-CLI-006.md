# HK-CLI-006: Supabase CLI access token on disk

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`~/.supabase/access-token`, where the Supabase CLI stores its personal access token when no OS keychain is available (containers, most Linux servers).

## Why it matters for agents

A personal access token can manage every project of every organization you belong to: read database passwords and API keys, run migrations, change settings.

## How to fix

- Run `supabase logout` where agents run.
- On desktops, let the CLI keep the token in the OS keychain.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-006",
  "title": "Supabase CLI access token",
  "location": "~/.supabase/access-token",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Supabase CLI",
  "fix": "Run supabase logout where agents run, or let the CLI keep the token in the OS keychain.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Supabase CLI: login](https://supabase.com/docs/reference/cli/supabase-login)
