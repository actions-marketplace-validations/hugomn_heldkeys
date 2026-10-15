# HK-PYPI-001: Package index password or token in ~/.pypirc

| Check | Runs in | Default severity |
|---|---|---|
| `pypirc` | `heldkeys scan` | High |

## What it detects

A `password` in any section of `~/.pypirc`, usually a `pypi-` upload token.

## Why it matters for agents

twine reads this file automatically. A token here lets the agent upload new releases of the account's packages; an account-wide token covers all of them.

## How to fix

- Use a project-scoped API token instead of an account-wide one.
- Publish from CI with trusted publishing, and keep no upload token on laptops.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "pypirc",
  "rule": "HK-PYPI-001",
  "title": "PyPI upload token",
  "location": "~/.pypirc [pypi]",
  "fingerprint": "pypi…011",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Use a project-scoped API token, or trusted publishing from CI, instead of an account-wide one.",
  "category": "package-registry"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [PyPI: API tokens](https://pypi.org/help/#apitoken)
- [PyPI: trusted publishers](https://docs.pypi.org/trusted-publishers/)
- [Python Packaging: the .pypirc file](https://packaging.python.org/en/latest/specifications/pypirc/)
