# HK-READ-001: A file a check looks at exists but could not be read or parsed (context)

| Check | Runs in | Default severity |
|---|---|---|
| `read-errors` | `heldkeys scan`, `heldkeys preflight`, `heldkeys ci` | Info |

## What it detects

A file that one of the checks looks at exists but was not checked:

- it is larger than the size limit (1 MiB for most files, 32 MiB for `~/.claude.json`);
- it is not a regular file (a directory, FIFO, socket or device where a config file should be);
- it is a symlink that leads out of the working directory (project files such as `.env`, `.mcp.json`, `.npmrc`, and tracked files for `--repo-secrets`), or into `/proc` or `/sys`;
- it could not be opened (permissions, I/O error);
- it is the repository config behind a `.git` file whose `gitdir:` leads outside the working directory without git's back-pointer to it;
- it is not valid JSON or YAML, or a YAML file is over the expansion budget (more than 100 aliases, 50,000 nodes or 8 MiB of text once aliases are expanded, or 64 levels of nesting).

The `dotenv` walk also reports the working directory here when it stops after 20,000 entries.

## Why it matters for agents

A file heldkeys skipped is a file it says nothing about. Whatever credential it holds is missing from the report, and a `preflight` gate would pass over it. The agent itself may well be able to read it.

## How to fix

- Look at the file by hand.
- For a gate that must fail closed, add `--strict`: `heldkeys preflight --strict` (and `scan --strict`, `ci --strict`) exits 1 when any of these findings is present. In `ci`, `--strict` also fails on [HK-WF-007](HK-WF-007.md), a workflow file that could not be analysed.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "read-errors",
  "rule": "HK-READ-001",
  "title": "File could not be read",
  "location": "~/.kube/config",
  "fingerprint": null,
  "severity": "info",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "could not read ~/.kube/config: not valid YAML: while parsing a node, did not find expected node content at byte 9 line 2 column 1",
  "fix": "Check this file by hand: anything it holds is missing from this report. --strict fails the run on these.",
  "category": "not-analysed"
}
```

## References

- [Running heldkeys in sandboxes: failing closed](../sandboxes.md#failing-closed-with---strict)
