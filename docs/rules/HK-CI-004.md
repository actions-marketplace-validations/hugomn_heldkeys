# HK-CI-004: Actions runtime token with write access to the cache and artifacts

| Check | Runs in | Default severity |
|---|---|---|
| `ci-runtime` | `heldkeys ci` | Medium. High on a self-hosted runner. |

## What it detects

`ACTIONS_RUNTIME_TOKEN` in the environment of the heldkeys step, inside GitHub Actions. The runner gives this token to JavaScript and container actions so they can use the Actions cache and upload artifacts. A plain `run:` step does not normally see it, so this finding means a step exported it or heldkeys runs inside an action that has it.

## Why it matters for agents

The token can write cache entries and artifacts. Later jobs restore caches by key, including jobs on the default branch and release builds, so whoever holds the token can plant files those jobs will trust. An agent that can read this variable can do that with a few HTTP requests.

The absence of this finding does not prove a job is safe from cache poisoning: code running in a job has other ways to reach the cache. Treat any agent step in a job that also saves caches or builds release artifacts as able to poison them.

## How to fix

- Keep agent steps out of jobs that save caches or build release artifacts.
- Do not export `ACTIONS_RUNTIME_TOKEN` to the environment of other steps.
- Do not restore caches written by jobs that run agents in release and deploy jobs.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "ci-runtime",
  "rule": "HK-CI-004",
  "title": "Actions runtime token (cache and artifacts)",
  "location": ".github/workflows/review.yml env: ACTIONS_RUNTIME_TOKEN",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "write",
  "detail": "can write the Actions cache and artifacts, which later jobs (including release builds) restore",
  "fix": "Keep agent steps out of jobs that save caches or build release artifacts.",
  "category": "ci-job"
}
```

## References

- [GitHub: caching dependencies to speed up workflows](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/caching-dependencies-to-speed-up-workflows)
- [GitHub: security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
