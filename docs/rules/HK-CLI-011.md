# HK-CLI-011: Kaggle API key in kaggle.json

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | Medium |

## What it detects

The `key` in `~/.kaggle/kaggle.json` (or `$KAGGLE_CONFIG_DIR/kaggle.json`, or `~/.config/kaggle/kaggle.json`).

## Why it matters for agents

The key acts as your Kaggle account: it can download competition data you agreed to keep private and publish datasets, models and notebooks under your name.

## How to fix

- Delete `kaggle.json` where agents run.
- Expire the key in your Kaggle account settings if it may have been copied.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-011",
  "title": "Kaggle API key",
  "location": "~/.kaggle/kaggle.json",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "Kaggle CLI: key",
  "fix": "Delete kaggle.json where agents run, or expire the key in your Kaggle account settings.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Kaggle API](https://github.com/Kaggle/kaggle-api)
