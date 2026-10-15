# HK-WF-005: AI agent action pinned to a tag or branch, not a commit SHA

| Check | Runs in | Default severity |
|---|---|---|
| `workflows` | `heldkeys ci` | Medium |

## What it detects

An agent action (or agent reusable workflow) referenced as `owner/action@v1`, `@main` or any other ref that is not a full 40-character commit SHA. Local actions (`./...`) and `docker://` images are not reported here.

heldkeys only looks at agent actions. For pinning across all your actions, use zizmor's `unpinned-uses` audit or a tool like pinact or Dependabot.

## Why it matters for agents

Tags and branches are mutable: whoever can push to the action's repository can point `v1` at different code, and every workflow using `@v1` runs it on its next trigger. For most actions that is a supply-chain risk. For an agent action it is worse, because the agent step is by design the step that holds the model key, a write token and often the most secrets in the workflow.

This is not hypothetical. In March 2025 the `tj-actions/changed-files` tags were rewritten to point at a commit that dumped runner memory, including secrets, into public build logs (CVE-2025-30066). Every repository that pinned by tag ran it; the ones pinned by SHA did not.

## Vulnerable

```yaml
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Fixed

```yaml
      - uses: anthropics/claude-code-action@<full-40-character-sha> # v1.2.3
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Keep the version in a comment so humans and Dependabot can still tell which release it is; Dependabot updates SHA pins and their comments.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "workflows",
  "rule": "HK-WF-005",
  "title": "AI agent action not pinned to a commit SHA",
  "location": ".github/workflows/claude.yml:9 jobs.claude.steps[0] (uses: anthropics/claude-code-action@v1)",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "anthropics/claude-code-action at ref v1, which can be moved to other code; whoever controls that ref controls an agent holding this job's token and secrets",
  "fix": "Pin the action to a full commit SHA with the version in a comment (uses: owner/action@<sha> # v1.2.3).",
  "category": "workflow"
}
```

## References

- [GitHub: security hardening, using third-party actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
- [CVE-2025-30066 (tj-actions/changed-files)](https://www.cve.org/CVERecord?id=CVE-2025-30066)
- [zizmor: unpinned-uses audit](https://docs.zizmor.sh/audits/#unpinned-uses)
