# HK-WF-007: Workflow file that could not be analysed (context)

| Check | Runs in | Default severity |
|---|---|---|
| `workflows` | `heldkeys ci` | Info |

## What it detects

A file in `.github/workflows` that heldkeys could not analyse, so any agent step in it went unchecked. The detail always reads `could not analyse <file>: <reason>`, where the reason is one of:

- not valid YAML, or over the YAML budget (more than 100 aliases, more than 50,000 nodes or 8 MiB of text once aliases are expanded, or nested more than 64 levels deep; the budget covers every document in the file and merge keys `<<` too): a YAML "alias bomb" is refused rather than expanded;
- larger than the size limit for a workflow file (1 MiB);
- a symlink that leads outside the working tree, or into `/proc` or `/sys` (a repository controls its own files, not the runner's);
- the operating system refused to read it;
- not a YAML mapping, so not a workflow;
- reached through a local reusable-workflow call that heldkeys does not follow: a call cycle, more than 3 nested calls, a `uses: ./.github/workflows/...` that names a file that does not exist, a local path outside `.github/workflows` (`./.github/workflows/../../x.yml`, `./ci/x.yml`, an absolute path; the detail then reads `local reusable workflow outside .github/workflows not followed`), or calls that reach more than 2,000 jobs in all (each called job counts once per distinct caller context; past that budget no further calls are followed, and one finding says where it stopped). These are reported at the calling job.

Empty files and files holding only comments are skipped silently: there is nothing in them to check.

It is Info, so it never counts as a workflow risk and never trips `--fail-on`. `heldkeys ci --strict` fails on it, as on HK-READ-001, for gates that must fail closed. Files elsewhere that heldkeys cannot read (`.git/config`, home-level configs) are reported as [HK-READ-001](HK-READ-001.md) instead.

## Why it matters for agents

A linter that silently skips what it cannot read reports "no risks" for exactly the files an attacker would want it to skip. GitHub itself refuses to run a workflow it cannot parse, so most of these are harmless typos, but the finding makes sure a pass from `heldkeys ci` never hides an unchecked agent step.

## How to fix

Fix the file (GitHub shows the same parse error on the Actions tab), or review its agent steps by hand. For reusable workflows, keep call chains short and point `uses:` at a file that exists.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "workflows",
  "rule": "HK-WF-007",
  "title": "Workflow file not analysed",
  "location": ".github/workflows/agent.yml",
  "fingerprint": null,
  "severity": "info",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "could not analyse .github/workflows/agent.yml: not valid YAML: while parsing a node, did not find expected node content at byte 6 line 2 column 1",
  "fix": "Check this workflow by hand, or fix what kept heldkeys from reading it: its agent steps were not checked.",
  "category": "workflow"
}
```

## References

- [GitHub: reusing workflows](https://docs.github.com/en/actions/sharing-automations/reusing-workflows)
- [GitHub: workflow syntax](https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions)
