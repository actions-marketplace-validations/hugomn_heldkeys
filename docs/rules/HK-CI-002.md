# HK-CI-002: GitHub token in the CI job's environment

| Check | Runs in | Default severity |
|---|---|---|
| `ci-runtime` | `heldkeys ci` | By format: Medium for the job's own installation token (`ghs_`, short-lived), High for a personal access token (`ghp_`, `github_pat_`). One level higher on a self-hosted runner. |

## What it detects

`GITHUB_TOKEN` or `GH_TOKEN` in the environment of the heldkeys step, inside GitHub Actions. GitHub does not put the job token in a step's environment by itself: a workflow does it with `env: GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}` (or `github.token`), usually at job or workflow level so that `gh` works in every step. A personal access token stored as a secret and exported under one of these names is reported here too, with its own, higher severity.

## Why it matters for agents

With the token in the environment, a hijacked agent does not need to find it: `gh` and `git` pick it up on their own. What the token can do is set by the workflow's `permissions:` block, which the `workflows` check reads ([HK-WF-003](HK-WF-003.md)). With `contents: write` the agent can push; with `pull-requests: write` or `issues: write` it can post whatever it read to a public thread. A personal access token is worse: it is not limited to this repository or this job, and it keeps working after the run.

## How to fix

- Pass the token only to the step that needs it, as step-level `env:`, and not to the agent step unless the agent must call the API.
- Set a job-level `permissions:` block with only the scopes that job needs, for example `contents: read`.
- Replace personal access tokens with the job token or a GitHub App installation token scoped to the repository.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "ci-runtime",
  "rule": "HK-CI-002",
  "title": "GitHub token in the job environment",
  "location": ".github/workflows/review.yml env: GITHUB_TOKEN",
  "fingerprint": "ghs_…301",
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "GitHub App installation token; what it can do is set by the workflow's permissions: block (see the workflows findings)",
  "fix": "Pass the token only to the step that needs it, with a job-level permissions: block that is as narrow as possible.",
  "category": "ci-job"
}
```

## References

- [GitHub: automatic token authentication](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication)
- [GitHub: controlling permissions for GITHUB_TOKEN](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token)
