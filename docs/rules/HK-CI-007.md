# HK-CI-007: GitLab CI job token in the job's environment

| Check | Runs in | Default severity |
|---|---|---|
| `ci-runtime` | `heldkeys ci` | Medium. High on a self-hosted runner. |

## What it detects

`CI_JOB_TOKEN` in the environment, inside GitLab CI (`GITLAB_CI=true`). GitLab sets it in every job. `CI_REGISTRY_PASSWORD` and `CI_DEPENDENCY_PROXY_PASSWORD` are the same token under other names, so they are not reported again.

## Why it matters for agents

The job token acts as the user who started the pipeline, until the job ends. It can call parts of the GitLab API, pull and push to the container registry and the package registries, and clone other projects that allow it in their job token allowlist. A hijacked agent in the job can use all of that.

## How to fix

- Limit which projects accept this project's job token (Settings, CI/CD, Job token permissions).
- Keep agents out of jobs that deploy or publish packages and images.
- Run agent jobs on GitLab-hosted or ephemeral runners rather than long-lived shared ones.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "ci-runtime",
  "rule": "HK-CI-007",
  "title": "GitLab CI job token",
  "location": ".gitlab-ci.yml env: CI_JOB_TOKEN",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "API, registry and package access as the user who started the pipeline, until the job ends",
  "fix": "Limit the job token's project allowlist (CI/CD job token settings) and keep agents out of jobs that deploy.",
  "category": "ci-job"
}
```

## References

- [GitLab: CI/CD job token](https://docs.gitlab.com/ci/jobs/ci_job_token/)
- [GitLab: predefined CI/CD variables](https://docs.gitlab.com/ci/variables/predefined_variables/)
