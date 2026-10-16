# HK-AI-006: Hugging Face access token on disk

| Check | Runs in | Default severity |
|---|---|---|
| `ai-logins` | `heldkeys scan`, `heldkeys preflight` | Medium |

## What it detects

`~/.cache/huggingface/token` and `~/.cache/huggingface/stored_tokens` (under `$HF_HOME`, or `$XDG_CACHE_HOME/huggingface`, when set), written by `hf auth login` (formerly `huggingface-cli login`). The same token in both files is one secret in the report.

## Why it matters for agents

A Hugging Face token can be a write token: it can push models and datasets, and change private repositories, under your account. Model hubs are a supply-chain target, and a token in a cache directory is easy to miss.

## How to fix

- Run `hf auth logout` where agents run.
- Give agents a fine-grained, read-only token for the repositories they need.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "ai-logins",
  "rule": "HK-AI-006",
  "title": "Hugging Face token",
  "location": "~/.cache/huggingface/token",
  "fingerprint": "hf_F…006",
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "Hugging Face",
  "fix": "Run hf auth logout where agents run, and give agents a fine-grained, read-only token.",
  "category": "ai-tools"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Hugging Face: user access tokens](https://huggingface.co/docs/hub/en/security-tokens)
- [Hugging Face CLI](https://huggingface.co/docs/huggingface_hub/en/guides/cli)
