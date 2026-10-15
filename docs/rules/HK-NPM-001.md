# HK-NPM-001: npm registry credential in .npmrc

| Check | Runs in | Default severity |
|---|---|---|
| `npmrc` | `heldkeys scan` | High |

## What it detects

An `_authToken`, `_auth` or `_password` in `~/.npmrc` (or `NPM_CONFIG_USERCONFIG`) or in the project's `.npmrc`. Values that reference an environment variable (`${NPM_TOKEN}`) are not secrets and are skipped.

## Why it matters for agents

An npm token in `.npmrc` usually has publish rights. A hijacked agent could push a malicious version of every package the account maintains, which is how several npm supply-chain worms spread.

## How to fix

- Use a granular access token that is read-only, or scoped to the packages the agent needs.
- In CI, reference the token as `${NPM_TOKEN}` and set it only in the publish step; prefer trusted publishing.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "npmrc",
  "rule": "HK-NPM-001",
  "title": "npm access token",
  "location": "~/.npmrc (//registry.npmjs.org/)",
  "fingerprint": "npm_…010",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Use a granular, read-only or automation token scoped to the needed packages, or reference it as ${NPM_TOKEN} only in CI.",
  "category": "package-registry"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [npm: about access tokens](https://docs.npmjs.com/about-access-tokens)
- [npm: npmrc](https://docs.npmjs.com/cli/configuring-npm/npmrc)
