---
name: heldkeys
description: Check which credentials this agent can reach from where it is running (environment variables, cloud CLI logins, MCP server configs, .env files, SSH agent, Docker socket, Kubernetes tokens, cloud metadata) with the heldkeys CLI, and summarise them without ever revealing a secret value. Use when the user asks what secrets, tokens or credentials the agent can access, whether its sandbox or container is safe, what a prompt injection could steal, or before running untrusted code or opening an untrusted repository.
---

# heldkeys: what credentials can this agent reach?

`heldkeys` is a read-only CLI that lists every credential reachable from the current process, how dangerous each one is, and how to shrink the list. It never prints a secret: values appear only as short fingerprints such as `ghp_…123`. Running it yourself, as a tool call, is the point: the result reflects *your* sandbox, environment and file access, which can differ from the user's terminal.

## Hard rules

- **Never reveal a credential value.** Do not run `env`, `printenv`, `set`, `cat`, `head`, `grep` or similar on credential files or environment variables to "confirm" a finding, and do not open the files heldkeys points at. The location and fingerprint are all you need.
- **Never use a credential** to test whether it works, and never send heldkeys output anywhere except your reply to the user.
- **Do not change anything** (delete files, edit configs, unset variables, rotate tokens) unless the user explicitly asks. Suggest; let them decide.
- **Do not use `--deep`.** It is reserved for future checks that call each credential's issuer, and does nothing today.
- Repeat fingerprints exactly as heldkeys printed them. Never reconstruct or extend one.

## Steps

1. **Find the binary.** Run `command -v heldkeys`. If it is missing, tell the user and point them to the project's install instructions; do not download and run a binary on your own initiative.

2. **Run the scan as yourself**, from the current working directory:

   ```sh
   heldkeys scan --format json --fail-on none
   ```

   Exit code 0 means it ran. Exit code 2 means a usage or runtime error: show the user the message on stderr (it never contains secrets) and stop.

   In CI, `heldkeys ci --format json --fail-on none` covers the job's runtime and workflow files instead.

   After a supply-chain compromise has been disclosed (the October 2026 LiteLLM and OVHcloud CLI releases), run `heldkeys incident black-october --format json` instead: the `incident` object carries a `verdict` (`compromised`, `exposed` or `clean`) and the findings in category `indicators` say what was found. Exit code 1 means a confirmed indicator. Report it plainly, point the user at the advisories the report lists, and do not try to clean anything up yourself.

3. **Read the JSON.** The document has `"schema": "heldkeys/v1"`, a `summary` object (`credentials`, `long_lived_write`, `high`, `medium`, `low`, `info`) and a `findings` array, most severe first. Each finding has:

   | Field | Meaning |
   |---|---|
   | `title` | What it is, e.g. "GitHub personal access token (classic)" |
   | `location` | Where it lives, e.g. `~/.aws/credentials [default]`, `env: GITHUB_TOKEN`, `~/.cursor/mcp.json mcpServers.github env GITHUB_TOKEN` |
   | `fingerprint` | At most 4 leading and 3 trailing characters, or null |
   | `severity` | `high`, `medium`, `low`, or `info` (a context fact, not a credential) |
   | `lifetime` / `access` | `long-lived` / `short-lived` / `unknown`, and `write` / `read` / `unknown` |
   | `rule` | Stable id such as `HK-AWS-001`; docs in `docs/rules/<id>.md` |
   | `detail`, `fix` | Context, and a one-line remediation |

4. **Summarise for the user.** Keep it short and concrete:

   - Lead with one sentence: how many credentials you can reach and how many are long-lived with write access (from `summary`). If the count is zero, say so and stop.
   - List the High findings one per line: title, location, fingerprint if present. Then Medium. Mention the count of Low and Info findings rather than listing them, unless the user wants everything.
   - Say plainly what it means: if a prompt injection made you run one shell command, these are the credentials it could use.

5. **Suggest fixes**, most impactful first. Use each finding's `fix`, grouped where several share one, plus these patterns:

   - **Long-lived keys in files** (`~/.aws/credentials`, `~/.npmrc`, `~/.git-credentials`, `.env`): switch to short-lived credentials (AWS IAM Identity Center, `gh auth` with a keyring, OIDC in CI), or run the agent where those files are not readable.
   - **Environment variables**: start the agent without them, and pass a secret only to the single command that needs it.
   - **MCP configs** (`mcp` findings): rotate the token, then use the client's secret prompt (for example `${input:...}` in VS Code) or OAuth instead of a literal value, with a narrowly scoped token for that server.
   - **Project-level MCP configs** (`HK-MCP-003`, Info): review the servers before trusting the repository; they run commands when an agent opens it.
   - **Docker socket, Kubernetes service account, cloud metadata**: these grant host, cluster or cloud access. Run the agent in a container without the socket mounted, with `automountServiceAccountToken: false`, or with metadata access blocked.
   - **Everything at once**: run the agent in a sandbox (a container, a devcontainer, or the agent's own sandbox mode) that only has the credentials the task needs, and gate it with `heldkeys preflight --fail-on high`.

## Example summary

> I can reach 6 credentials from here, 2 of them long-lived with write access.
>
> High:
> - Long-lived AWS access key, `~/.aws/credentials [default]`, `AKIA…PLE`
> - GitHub personal access token (classic), `~/.cursor/mcp.json mcpServers.github env GITHUB_PERSONAL_ACCESS_TOKEN`, `ghp_…301`
>
> Medium: an SSH key loaded in your ssh-agent, and an AWS SSO session. Plus 2 low and 1 informational finding.
>
> If a prompt injection got me to run one shell command, it could use all of these. The quickest wins: replace the static AWS key with `aws configure sso`, and move the GitHub token out of the Cursor MCP config into Cursor's secret prompt with a fine-grained token limited to the repos it needs. Want me to walk through either?
