# HK-CI-006: CI job context: platform, workflow, trigger and runner (context)

| Check | Runs in | Default severity |
|---|---|---|
| `ci-runtime` | `heldkeys ci` | Info |

## What it detects

Nothing to fix. This finding records the facts that frame the other `ci-runtime` findings, from the CI's own environment variables:

- On GitHub Actions: the workflow file (`GITHUB_WORKFLOW_REF`), the job (`GITHUB_JOB`), the event (`GITHUB_EVENT_NAME`, flagged when an outsider can write its text, such as `issue_comment` or `pull_request_target`) and the runner type (`RUNNER_ENVIRONMENT`).
- On GitLab CI: the project, the job and the pipeline source.

It is Info, so it never counts as a credential and never trips `--fail-on`.

## Why it matters for agents

The same token is a different risk on a different runner. On a self-hosted runner, files, caches and processes can outlive the job, so the next job (possibly from another repository or a fork) can find what this one left behind. heldkeys rates every runtime finding one level higher there, and this finding says why.

The trigger matters too: a job started by `issue_comment` runs with text an outsider wrote, which is exactly what a prompt injection needs. The `workflows` check reports that combination as [HK-WF-001](HK-WF-001.md).

## How to fix

No action needed. If the runner is self-hosted, prefer ephemeral runners (one job per runner) for any job that runs an agent.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "ci-runtime",
  "rule": "HK-CI-006",
  "title": "GitHub Actions job",
  "location": ".github/workflows/review.yml",
  "fingerprint": null,
  "severity": "info",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "job review; triggered by issue_comment, whose text an outsider can write; GitHub-hosted runner (a fresh VM per job); this scan sees the heldkeys step's environment; agent steps also get their own with: and env:",
  "fix": "No action needed; context for the findings above.",
  "category": "ci-job"
}
```

## References

- [GitHub: default environment variables](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/store-information-in-variables#default-environment-variables)
- [GitHub: hardening for self-hosted runners](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners)
