# HK-MCP-002: Credential-named value with a secret-looking value in an MCP server config

| Check | Runs in | Default severity |
|---|---|---|
| `mcp` | `heldkeys scan`, `heldkeys preflight` | Medium. A name that points at a cloud or source-control credential (`GITHUB_*`, `AWS_*`, ...) is titled "Possible cloud or SCM credential". |

## What it detects

The same places as [HK-MCP-001](HK-MCP-001.md), but for values that do not match a known token format. heldkeys reports them when the *name* says credential and the *value* looks real:

- `env` entries such as `MY_SERVICE_API_KEY`,
- arguments such as `--api-key=...`, `--token ...` or `--password ...`,
- URL query parameters such as `?api_key=...` or `?token=...`,
- headers such as `Authorization: Bearer ...` or `X-Api-Key: ...`,
- fields such as Codex's `bearer_token`.

Names are matched with the same rules as the `env` and `dotenv` checks (`*_TOKEN`, `*_SECRET`, `*_API_KEY`, `*_PASSWORD`, ...). Flag, field and header names are first turned into environment-variable style, so `--api-key`, `apiKey` and `X-Api-Key` all read as `API_KEY`.

Placeholders are skipped: empty values, `${VAR}`, `${input:id}`, `${env:VAR}`, `$VAR`, `<your-key>`, `changeme`, file paths, and values shorter than 8 characters.

## Why it matters for agents

Same as HK-MCP-001: the file is readable by any agent running as you, and the server acts with the credential. heldkeys cannot tell the provider, so it shows no fingerprint (the ends of an unknown secret are part of the secret) and marks lifetime and access as unknown.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "mcp",
  "rule": "HK-MCP-002",
  "title": "Possible credential",
  "location": "~/.codeium/windsurf/mcp_config.json mcpServers.search serverUrl ?api_key",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "Windsurf user config",
  "fix": "Rotate it and remove it from the MCP config: use the client's secret prompt (for example ${input:...} in VS Code) or a credential helper, and give the server its own narrowly scoped token.",
  "category": "mcp"
}
```

## How to fix

As for [HK-MCP-001](HK-MCP-001.md): rotate the value, keep it out of the file (client secret prompt, OAuth, or a wrapper that reads a secret store), and scope it narrowly.

## False positives

If the value is not a secret (for example a public project id in a field named `*_KEY`), rename the field if you control the server, or ignore the finding. heldkeys never prints the value, so a false positive costs nothing but a line in the report.
