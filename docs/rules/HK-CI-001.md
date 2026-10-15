# HK-CI-001: Credential in the CI job's environment

| Check | Runs in | Default severity |
|---|---|---|
| `ci-runtime` | `heldkeys ci` | By format, as for [HK-ENV-001](HK-ENV-001.md) and [HK-ENV-002](HK-ENV-002.md): High for long-lived cloud, source-control and AI provider keys, Medium for short-lived ones and for credential-named variables of unknown shape, Low for test-mode keys. One level higher on a self-hosted runner. |

## What it detects

Inside GitHub Actions (`GITHUB_ACTIONS=true`) or GitLab CI (`GITLAB_CI=true`), every environment variable of the heldkeys step that looks like a credential, by value (`ghp_`, `AKIA`, `sk-ant-`, `npm_`, ...) or by name (`*_TOKEN`, `*_API_KEY`, `DATABASE_URL`, ...). The classification is the same one the local `env` check uses, so a CI scan and a laptop scan agree on what counts.

Variables with a dedicated rule are left to it: `GITHUB_TOKEN` and `GH_TOKEN` ([HK-CI-002](HK-CI-002.md)), the OIDC request variables ([HK-CI-003](HK-CI-003.md)), `ACTIONS_RUNTIME_TOKEN` ([HK-CI-004](HK-CI-004.md)) and GitLab's `CI_JOB_TOKEN` and the registry passwords derived from it ([HK-CI-007](HK-CI-007.md)).

The location starts with the workflow file (from `GITHUB_WORKFLOW_REF`, or `CI_CONFIG_PATH` on GitLab), so SARIF can point code scanning at the file where the fix goes.

## Why it matters for agents

A secret set in a workflow's or job's `env:` block is in the environment of every step of that job, including an agent step that never needed it. One `env` or `printenv` from a hijacked agent prints all of them, and every process the agent starts inherits them.

The scan sees the environment of the heldkeys step. An agent step in the same job gets that environment plus its own `with:` and `env:`, so run heldkeys in the agent's job, before the agent.

## How to fix

- Move secrets from workflow-level and job-level `env:` to the one step that needs them (step-level `env:`), and never to an agent step.
- Run steps that need deploy or publish credentials in a separate job from the agent.
- Prefer OIDC and short-lived cloud credentials over long-lived keys stored as secrets.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "ci-runtime",
  "rule": "HK-CI-001",
  "title": "npm access token",
  "location": ".github/workflows/review.yml env: NPM_TOKEN",
  "fingerprint": "npm_…702",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Scope secrets to the one step that needs them (step-level env:), never job- or workflow-level env, and never to an agent step.",
  "category": "ci-job"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format. heldkeys never prints the value.

## References

- [GitHub: using secrets in GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions)
- [GitLab: CI/CD variables security](https://docs.gitlab.com/ci/variables/#cicd-variable-security)
- [OWASP GenAI: LLM01 prompt injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
