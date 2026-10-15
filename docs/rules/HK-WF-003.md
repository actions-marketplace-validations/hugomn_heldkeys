# HK-WF-003: AI agent step in a job with write-all or unrestricted default permissions

| Check | Runs in | Default severity |
|---|---|---|
| `workflows` | `heldkeys ci` | High for `permissions: write-all`. Medium when no `permissions:` block is set on the job or the workflow (or, for a called workflow, on its callers). |

## What it detects

An agent step whose job runs with `permissions: write-all`, or with no `permissions:` block at all (neither on the job nor on the workflow). Job-level permissions win over workflow-level ones, so a job that narrows a workflow's `write-all` is not reported. A local reusable workflow gets at most what its calling job allows and inherits it when it sets nothing, so a called workflow is judged by its effective permissions through each caller.

When no block is set, the token gets the repository's default. That default is read-only for repositories created since February 2023, but older repositories and organisations that never changed the setting still hand out a write-all token. heldkeys cannot see that setting from the YAML, so it asks you to make the permissions explicit.

## Why it matters for agents

Every agent reads text it did not write: the repository, issue and PR content, web pages it fetches, tool output. Any of it can carry a prompt injection, so the token in the agent's job is the token an attacker gets. With `write-all` that token can push to branches, create releases, edit issues and PRs, approve and merge where branch rules allow it, and trigger other workflows.

A scheduled "fix flaky tests" agent with `write-all` reads a test log that includes a crafted error message. The message tells it the fix is to update `package.json` to point a dependency at a fork. The agent commits that to `main`, and every developer and deployment picks it up.

## Vulnerable

```yaml
on:
  schedule:
    - cron: "0 3 * * 1"

jobs:
  gemini:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@<sha> # v0
        with:
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
```

## Fixed

```yaml
on:
  schedule:
    - cron: "0 3 * * 1"

permissions: {}

jobs:
  gemini:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # only if it opens PRs; never contents: write
    steps:
      - uses: google-github-actions/run-gemini-cli@<sha> # v0
        with:
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
```

Having the agent open a pull request instead of pushing keeps a human review between its output and your default branch.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "workflows",
  "rule": "HK-WF-003",
  "title": "AI agent job with broad token permissions",
  "location": ".github/workflows/gemini.yml:9 jobs.gemini.steps[0] (uses: google-github-actions/run-gemini-cli@0123456)",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "no permissions: block on jobs.gemini or the workflow; the token depends on the repository default (write-all on older repos and orgs). Set permissions explicitly",
  "fix": "Add a job-level permissions: block with only what the agent needs (for example contents: read).",
  "category": "workflow"
}
```

## References

- [GitHub: controlling permissions for GITHUB_TOKEN](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token)
- [GitHub changelog: default GITHUB_TOKEN permissions changed to read-only (February 2023)](https://github.blog/changelog/2023-02-02-github-actions-updating-the-default-github_token-permissions-to-read-only/)
- [zizmor: excessive-permissions audit](https://docs.zizmor.sh/audits/#excessive-permissions)
