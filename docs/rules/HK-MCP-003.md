# HK-MCP-003: Project-level MCP config whose servers start when an agent opens the directory (context)

| Check | Runs in | Default severity |
|---|---|---|
| `mcp` | `heldkeys scan`, `heldkeys preflight` | Info |

## What it detects

An MCP config in the working directory that defines at least one server:

- `./.mcp.json` (Claude Code)
- `./.cursor/mcp.json` (Cursor)
- `./.vscode/mcp.json` and `./.vscode/settings.json` (VS Code)
- `./.gemini/settings.json` (Gemini CLI)
- `./.zed/settings.json` (Zed)

The finding lists the server names and the programs they start (file name only; arguments can hold secrets), for example `Claude Code: 2 server(s) (db, docs); runs npx, uvx`.

When the working directory is your home directory, these files are reported as user configs instead.

## Why it matters for agents

A project-level MCP config is code that runs on your machine. When an agent opens the directory, the client starts every listed server, which means running its `command` with its `args`, usually through `npx` or `uvx`, which download and run the latest version of a package. Anyone who can change the repository (a pull request author, a compromised dependency, a malicious clone) can add a server here. Some clients ask before starting project servers and some do not, and approvals are easy to click through. In CI, an agent that checks out an untrusted pull request and loads its `.mcp.json` is the scenario behind the `HK-WF-002` workflow rule.

It is reported as Info, not as a credential: it does not expose anything by itself. It tells you that this directory decides what runs next to your agent.

## How to fix

- Read the config before letting an agent open a repository you did not write.
- Pin server packages to exact versions (`npx -y package@1.2.3`), not `latest`.
- Keep the client's approval prompt for project servers turned on (for example, do not set `enableAllProjectMcpServers` in Claude Code).
- Never put credentials in a project-level config: it is usually committed to git. heldkeys reports those separately as HK-MCP-001 or HK-MCP-002.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "mcp",
  "rule": "HK-MCP-003",
  "title": "Project-level MCP config",
  "location": "./.mcp.json",
  "fingerprint": null,
  "severity": "info",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "Claude Code: 2 server(s) (db, docs); runs npx, uvx",
  "fix": "Review these servers before an agent opens this directory; a cloned repo can add servers that run commands when the agent starts.",
  "category": "mcp"
}
```
