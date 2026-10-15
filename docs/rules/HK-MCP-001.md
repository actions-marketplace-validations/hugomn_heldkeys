# HK-MCP-001: Token of a known format in an MCP server config (env, args, URL or headers)

| Check | Runs in | Default severity |
|---|---|---|
| `mcp` | `heldkeys scan`, `heldkeys preflight` | Taken from the token format: High for GitHub, GitLab, npm, PyPI, Slack, cloud and AI-provider keys; lower for test-mode or short-lived tokens. |

## What it detects

A value in an MCP server definition that matches a known token format (`ghp_`, `github_pat_`, `glpat-`, `npm_`, `xoxb-`, `sk-ant-`, `AKIA`, a URL with an embedded password, and the rest of the table in `src/rules.rs`). heldkeys looks in:

- the server's `env` block,
- each item of `args`, including `--flag=value`, `--flag value`, `NAME=value` and `--header "Authorization: Bearer ..."`,
- `url`, `serverUrl` and `httpUrl`, as a whole (for `user:password@host`) and per query parameter,
- `headers` and Codex's `http_headers`, with the `Bearer`/`Basic`/`Token` scheme removed,
- Zed extension `settings`, and any other string field named like a credential (`bearer_token`, `apiKey`).

Files read, relative to your home directory unless marked `./` (the working directory):

| Client | Files |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`, `~/.config/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude.json` (top-level and per-project `mcpServers`; honours `CLAUDE_CONFIG_DIR`), `./.mcp.json` |
| Cursor | `~/.cursor/mcp.json`, `./.cursor/mcp.json` |
| VS Code | `settings.json` (`mcp.servers`) and `mcp.json` under `~/Library/Application Support/Code/User/` and `~/.config/Code/User/` (also `Code - Insiders`), `./.vscode/mcp.json`, `./.vscode/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Zed | `~/.config/zed/settings.json` (`context_servers`), `./.zed/settings.json` |
| Codex | `~/.codex/config.toml` (`[mcp_servers.*]`; honours `CODEX_HOME`) |
| Gemini CLI | `~/.gemini/settings.json`, `./.gemini/settings.json` |

## Why it matters for agents

The token sits in a plain file in your home directory. An agent running as you can `cat` it, and a prompt injection only needs one shell command to send it somewhere. The agent can also call the MCP server's tools, which act with the token's full permissions. MCP config tokens tend to be broad, long-lived personal tokens, because they are pasted in once and forgotten.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "mcp",
  "rule": "HK-MCP-001",
  "title": "Slack token",
  "location": "~/.cursor/mcp.json mcpServers.slack env SLACK_BOT_TOKEN",
  "fingerprint": "xoxb…305",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Cursor user config",
  "fix": "Rotate it and remove it from the MCP config: use the client's secret prompt (for example ${input:...} in VS Code) or a credential helper, and give the server its own narrowly scoped token.",
  "category": "mcp"
}
```

The location is the file, the path to the server inside it, and where in the server the value was found. Only a fingerprint (at most 4 leading and 3 trailing characters) is ever shown.

## How to fix

1. Rotate the token. Assume it has been read.
2. Stop writing it into the config file. Most clients can prompt for it or read it from a secret store:
   - VS Code: declare an `inputs` entry with `"password": true` and reference it as `${input:id}`; VS Code keeps the value in the OS keychain.
   - Remote servers that support OAuth (GitHub's, Linear's, and others): use the client's OAuth flow instead of a static header.
   - Otherwise, start the server through a small wrapper that fetches the token from your OS keychain or a secret manager at launch.
3. Give the server its own token with the narrowest scopes it needs (a fine-grained GitHub token limited to one repository, a read-only database user), not your personal admin token.

Moving the token into an environment variable of your shell is not a fix: the `env` check will report it there, because the agent inherits that environment.
