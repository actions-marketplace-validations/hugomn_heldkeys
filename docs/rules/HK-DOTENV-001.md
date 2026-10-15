# HK-DOTENV-001: Token of a known format in a .env file

| Check | Runs in | Default severity |
|---|---|---|
| `dotenv` | `heldkeys scan` | Depends on the token format. |

## What it detects

heldkeys walks the working directory (or `--path`) to a depth of 4, skipping only dependency directories (`.git`, `node_modules`, `bower_components`, `target`, `vendor`, virtualenvs, `__pycache__`, `.tox`) and stopping after 20,000 entries. Gitignored directories are walked too: `.vercel/.env.production.local` is exactly the kind of file an agent finds. Symlinked `.env` files are followed when they stay inside the working directory; one that points outside it is not read and is reported as [HK-READ-001](HK-READ-001.md). It reports `KEY=value` lines in `.env` and `.env.*` files whose value matches a known token format. Template files (`.env.example`, `.sample`, `.template`, `.dist`, `.defaults`, also as in `.env.local.example`) are included for known formats, because real keys end up in them more often than anyone would like, but placeholders (`sk-ant-xxxx...`, `your_key_here`, `<token>`, a local database with password `postgres`) are skipped, and a real-looking token is titled "... in a template file" and reported one severity level lower. When the variable name names the vendor of a shared format, the title says so: `WORKOS_API_KEY=sk_test_...` is a "WorkOS test-mode API key", `DEEPSEEK_API_KEY=sk-...` a "DeepSeek API key"; without one it is "Test-mode secret key (sk_test_)" or "OpenAI-style API key". A line that is not `KEY=value` (a pasted URL, a bare token) is reported by its line number only, for example `./.env:3`, because the line itself may be the secret.

## Why it matters for agents

Coding agents read project files freely, and `.env` files are where projects keep their secrets. `.gitignore` keeps them out of git, not away from the agent, so heldkeys reports them even when they are ignored. A single `cat .env` or a broad file search is enough.

## How to fix

- Move the value out of the file into a secret manager, and load it only in the process that needs it.
- Or run the agent where the file is not readable (a sandbox without the project's `.env`).
- If a real key is in a template file that is committed, rotate it.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "dotenv",
  "rule": "HK-DOTENV-001",
  "title": "Slack token in a template file",
  "location": "./.env.example: SLACK_BOT_TOKEN",
  "fingerprint": "xoxb…017",
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Move SLACK_BOT_TOKEN out of .env.example into a secret manager, or run the agent where this file is not readable.",
  "category": "project-env"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [OWASP: Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
