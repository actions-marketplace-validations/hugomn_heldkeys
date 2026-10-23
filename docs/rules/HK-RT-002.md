# HK-RT-002: Node.js without the October 2026 security release (26.12.1, 24.22.1, 22.23.4), or end of life

| Check | Runs in | Default severity |
|---|---|---|
| `runtime-versions` | `heldkeys incident black-october` | Low |

## What it detects

The version printed by `node --version` on `PATH`, the versions installed by nvm, Volta, fnm, asdf, n and Homebrew (from their directory names), and the versions the project pins in `FROM node:` lines of Dockerfiles, `image: node:` lines of compose files, `.nvmrc`, `.node-version` and `.tool-versions`. Lines 22, 24 and 26 below the fixed release, and the end-of-life lines (20 and older, 21, 23, 25), are reported. A major alone (`node:22-slim`) is only reported when that whole line is end of life.

## Why it matters for agents

CVE-2026-111497 is an out-of-bounds write in the Brotli decoder that Node.js says permits remote code execution; the release also fixes three High-severity TLS hostname and DNS bugs. Not a credential: listed so the patch list and the rotation list come from one run.

## How to fix

- Update to 26.12.1, 24.22.1 or 22.23.4, or later.
- Move projects pinned to an end-of-life line to 22, 24 or 26.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "runtime-versions",
  "rule": "HK-RT-002",
  "title": "Node.js 22.23.3 without the Oct 2026 fix",
  "location": "~/.nvm/versions/node/v22.23.3",
  "fingerprint": null,
  "severity": "low",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "CVE-2026-111497 (Brotli decoder out-of-bounds write, remote code execution) and nine more",
  "fix": "Update to Node.js 22.23.4 or later.",
  "category": "runtimes"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [Node.js: October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [Node.js release schedule](https://github.com/nodejs/release#release-schedule)
