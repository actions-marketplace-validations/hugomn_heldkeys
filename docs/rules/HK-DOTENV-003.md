# HK-DOTENV-003: Credential in an editor history copy of a .env file

| Check | Runs in | Default severity |
|---|---|---|
| `dotenv` | `heldkeys scan`, `heldkeys preflight` | Same as the value: by format, or High or Medium |

## What it detects

Copies of `.env` files that the VS Code Local History extension keeps under `.history/`, named with a timestamp: `.env_20260507230125`, or `.env_20260507230125.local` for a copy of `.env.local`. They are read with the same rules as `.env` files (HK-DOTENV-001 and HK-DOTENV-002, including the template rules for copies of `.env.example`), and reported with the title "Editor history copy of a .env file"; the detail names the credential and the file it was copied from. A copy that holds the same value as the `.env` file is the same secret in the report, so many copies of one file stay one line in the summary.

## Why it matters for agents

Every save of `.env` leaves another copy, including the keys you have since rotated out of the real file and the ones you never meant to keep. Agents search project directories freely, and `.history` is rarely gitignored or cleaned.

## How to fix

- Delete the `.history` folder.
- Add `**/.env*` to the extension's `local-history.exclude` setting so it stops copying them.
- Rotate any key that only lives in a history copy and is still valid.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "dotenv",
  "rule": "HK-DOTENV-003",
  "title": "Editor history copy of a .env file",
  "location": "./.history/.env_20260507230125: OPENAI_API_KEY",
  "fingerprint": "sk-p…025",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "OpenAI project API key, in a copy of .env",
  "fix": "Delete the .history folder and add .env* to the Local History extension's local-history.exclude setting.",
  "category": "project-env"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Local History extension for VS Code](https://marketplace.visualstudio.com/items?itemName=xyz.local-history)
