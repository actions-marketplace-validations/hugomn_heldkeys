# HK-CI-005: GITHUB_TOKEN persisted in the git config by actions/checkout

| Check | Runs in | Default severity |
|---|---|---|
| `ci-runtime` | `heldkeys ci` | Medium. High on a self-hosted runner. |

## What it detects

Inside GitHub Actions, an `http.<url>.extraheader` with an `AUTHORIZATION` value in `.git/config` of the working directory (`--path`), or in a file that `.git/config` includes through `[include]` or `[includeIf]` (followed only inside the working directory or `RUNNER_TEMP`, where recent versions of `actions/checkout` keep it). That is where `actions/checkout` stores the job's token when `persist-credentials` is left at its default, `true`. The header value is never read beyond the word `AUTHORIZATION`, and never printed. The location is the file that holds the header: `.git/config`, or the included file. The `git-config` check also reads `.git/config` in `heldkeys ci`, but inside GitHub Actions it leaves this header to HK-CI-005, so the token is reported once.

## Why it matters for agents

The token stays there for the rest of the job so that later `git push` and `git fetch` steps work. It also means any process in the job can read it back, with `git config --get-regexp extraheader` or by opening the file, even when no step puts a token in the environment. An agent that runs in the checked-out directory holds whatever the job's `permissions:` grant.

## How to fix

- Set `persist-credentials: false` on `actions/checkout` in every job that runs an agent.
- If a later step must push, give that step its own token through step-level `env:`, in a job without an agent.

```yaml
      - uses: actions/checkout@<full-commit-sha> # v4
        with:
          persist-credentials: false
```

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "ci-runtime",
  "rule": "HK-CI-005",
  "title": "Checkout left GITHUB_TOKEN in git config",
  "location": ".git/config",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "http extraheader with an AUTHORIZATION value; git config --get-regexp extraheader prints it",
  "fix": "Set persist-credentials: false on actions/checkout in any job that runs an agent.",
  "category": "ci-job"
}
```

## References

- [actions/checkout: persist-credentials](https://github.com/actions/checkout#usage)
- [zizmor: artipacked audit](https://docs.zizmor.sh/audits/#artipacked)
