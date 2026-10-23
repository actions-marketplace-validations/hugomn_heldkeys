# HK-BREACH-003: OpenCode data on disk: provider keys linked in OpenCode Console may be exposed (17 Oct 2026)

| Check | Runs in | Default severity |
|---|---|---|
| `platform-breaches` | `heldkeys incident black-october` | Low |

## What it detects

`auth.json` or `opencode.db` in OpenCode's data directory (`$XDG_DATA_HOME/opencode` or `~/.local/share/opencode`) or `~/.config/opencode`. The files are not read. heldkeys cannot tell from them whether the user also linked providers in OpenCode Console, hence Low.

## Why it matters for agents

OpenCode reported a breach of a legacy console system around 17 October 2026 affecting 1.4% of console users who had linked external providers; provider keys stored in those console workspaces may have been exposed, and users reported unexpected charges. Keys the CLI and desktop app keep locally were not affected.

## How to fix

- If you linked OpenAI, Anthropic or Google keys in OpenCode Console, revoke them at the provider, issue new ones and check the provider's usage for anything unexpected.
- Nothing to do for keys that only ever lived in the local `auth.json`.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "platform-breaches",
  "rule": "HK-BREACH-003",
  "title": "Provider keys linked in OpenCode Console",
  "location": "~/.local/share/opencode/auth.json",
  "fingerprint": null,
  "severity": "low",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "OpenCode uses this machine; the console breach of 17 Oct 2026 exposed linked provider keys for 1.4% of console users",
  "fix": "Keys kept locally were not affected; if you linked OpenAI, Anthropic or Google keys in OpenCode Console, revoke and reissue them at the provider and check its usage.",
  "category": "breaches"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [TechCrunch: hackers hit AI coding tool OpenCode, running up charges on users' AI accounts](https://techcrunch.com/2026/10/19/hackers-hit-ai-coding-tool-opencode-running-up-charges-on-users-ai-accounts/)
