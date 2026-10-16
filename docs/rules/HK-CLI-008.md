# HK-CLI-008: Stripe CLI API key in config.toml

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High (live mode) or Low (test mode) |

## What it detects

`live_mode_api_key` and `test_mode_api_key` in the profiles of `~/.config/stripe/config.toml` (or under `$XDG_CONFIG_HOME`), written by `stripe login`. Live-mode keys are High ("Stripe CLI live-mode key"), test-mode keys Low ("Stripe CLI test-mode key").

## Why it matters for agents

The CLI's keys are restricted keys that last 90 days. A live-mode key acts on real customers and money: refunds, payouts, customer data.

## How to fix

- Run `stripe logout` (or `stripe logout --all`) where agents run.
- Give agents test-mode access only.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-008",
  "title": "Stripe CLI live-mode key",
  "location": "~/.config/stripe/config.toml [default]",
  "fingerprint": "rk_l…008",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Stripe CLI live mode: *.live_mode_api_key",
  "fix": "Run stripe logout where agents run; the CLI key acts on your live Stripe account until it expires.",
  "category": "dev-platform"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Stripe CLI](https://docs.stripe.com/stripe-cli)
