# HK-DOTENV-002: Credential-named entry with a secret-looking value in a .env file

| Check | Runs in | Default severity |
|---|---|---|
| `dotenv` | `heldkeys scan` | Medium (a name alone is weak evidence; cloud and source-control names are titled "Possible cloud or SCM credential"). |

## What it detects

heldkeys walks the working directory (or `--path`) to a depth of 4, skipping only dependency directories (`.git`, `node_modules`, `bower_components`, `target`, `vendor`, virtualenvs, `__pycache__`, `.tox`) and stopping after 20,000 entries. Gitignored directories are walked too: `.vercel/.env.production.local` is exactly the kind of file an agent finds. Symlinked `.env` files are followed when they stay inside the working directory; one that points outside it is not read and is reported as [HK-READ-001](HK-READ-001.md). It reports entries whose name usually holds a secret (`*_TOKEN`, `*_PASSWORD`, ...) and whose value looks real. Template files are skipped for this rule, because their name-matched entries are placeholders by design. Names with a public frontend prefix (`VITE_`, `NEXT_PUBLIC_`, `PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`) end up in the browser bundle: site keys, publishable and anonymous keys, client ids and analytics keys are skipped as public by design, and a name that says `SECRET`, `PRIVATE` or `SERVICE_ROLE` is reported as High, "Secret exposed to the frontend bundle". Connection strings to `localhost` with a trivial password (`postgres`, `password`, `secret`, ...) are not reported.

## Why it matters for agents

Coding agents read project files freely, and `.env` files are where projects keep their secrets. An agent can read gitignored files, so heldkeys reports them even when they are ignored. A single `cat .env` or a broad file search is enough.

## How to fix

- Move the value out of the file into a secret manager.
- Or run the agent where the file is not readable.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "dotenv",
  "rule": "HK-DOTENV-002",
  "title": "Possible credential",
  "location": "./.env: INTERNAL_API_TOKEN",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": null,
  "fix": "Move INTERNAL_API_TOKEN out of .env into a secret manager, or run the agent where this file is not readable.",
  "category": "project-env"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [OWASP: Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
