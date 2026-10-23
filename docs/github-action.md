# heldkeys GitHub Action

`hugomn/heldkeys` is a composite action that answers, for a GitHub Actions job, the question heldkeys asks everywhere: if an AI agent running here were hijacked by a prompt injection, which credentials could it use?

It downloads the heldkeys release binary for the runner, checks it against the SHA-256 file published with the release, and runs `heldkeys ci`. That does two things in one pass. It inventories the job's runtime exposure (secrets in the environment, `GITHUB_TOKEN`, OIDC, the token `actions/checkout` leaves in `.git/config`, tokens in the checkout's remote URLs, the runner type), and it statically analyses the AI agent steps in `.github/workflows` for the [HK-WF rules](rules/README.md#ci-rules-heldkeys-ci), following a job that calls a local reusable workflow (`uses: ./.github/workflows/...`) into the workflow it calls, with the caller's triggers, permissions and secrets. The Markdown report goes to the job summary. With `sarif: true`, a SARIF report is uploaded to code scanning, so findings show up in the Security tab and inline on pull requests.

Its inputs reach the shell through environment variables, never through `${{ }}` inside a script. The only other action it calls is `github/codeql-action/upload-sarif`, pinned to a full commit SHA, and only when `sarif` is `true`.

## Quick start

```yaml
name: heldkeys

on:
  pull_request:
  push:
    branches: [main]

permissions: {}

jobs:
  heldkeys:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # sarif: true uploads to code scanning
      # actions: read        # also needed for the upload in private repositories
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: hugomn/heldkeys@v0
        with:
          sarif: true
```

The step fails when a finding reaches `fail-on` (High by default), after the report is in the job summary and the SARIF upload is done, so a failing run still shows its findings.

> [!TIP]
> `@v0` follows the latest v0 release, which is convenient but means the code you run can change under you. For anything that matters, pin the action to a full commit SHA with the version in a comment, for example `uses: hugomn/heldkeys@<full-commit-sha> # v0.3.0`, and let Dependabot update it. The action installs the heldkeys binary of its own release unless you set `version`, so pinning the action pins the binary too. heldkeys reports unpinned agent actions itself ([HK-WF-005](rules/HK-WF-005.md)), and zizmor reports the rest.

## Inputs

| Input | Default | Description |
|---|---|---|
| `version` | this action's release | heldkeys release to install, such as `0.3.0`, or `latest` for the newest release. |
| `fail-on` | `high` | Fail the step when a finding reaches this level: `none`, `high`, `medium`, `low` or `long-lived-write`. |
| `format` | `text` | Format of the report printed to the log: `text`, `json`, `markdown` or `sarif`. |
| `sarif` | `false` | Write a SARIF report and upload it to code scanning with `github/codeql-action/upload-sarif` (category `heldkeys`). The job needs `security-events: write`, and `actions: read` in private repositories. |
| `path` | `.` | Directory of the repository to analyse, relative to the workspace. |
| `repo-secrets` | `false` | Also scan tracked files on the current branch for tokens of known formats ([HK-REPO-001](rules/HK-REPO-001.md)). |
| `config` | | Ignore rules file to use instead of `.heldkeys.toml` in `path`, relative to the workspace. See [Ignore rules and baselines](#ignore-rules-and-baselines). |
| `baseline` | | A previous heldkeys JSON report (`heldkeys ci --write-baseline`), relative to the workspace. Findings already in it are listed as ignored and do not fail the step. |

## Outputs

| Output | Description |
|---|---|
| `sarif-file` | Path of the SARIF report that was uploaded. Empty when `sarif` is `false`. |
| `markdown-file` | Path of the Markdown report (the job summary text), for example to post as a PR comment. |
| `summary` | The one-line verdict, for example `3 AI agent workflow risks, 2 credentials reachable in this job.` |

## Where to run it

The workflow analysis is the same wherever the action runs: it reads the YAML files. The runtime inventory is different. It sees the environment of the heldkeys step, which is the workflow's and the job's `env:` plus what the runner provides (`ACTIONS_ID_TOKEN_REQUEST_*` when the job has `id-token: write`, for example). An agent step in the same job inherits all of that, plus its own `with:` and `env:`.

So to see what your agent can reach, add heldkeys as a step in the agent's own job, before the agent runs, with `fail-on` set to what you are willing to hand the agent:

```yaml
jobs:
  claude:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      # Refuse to start the agent if its job exposes a High finding.
      - uses: hugomn/heldkeys@v0
        with:
          fail-on: high

      - uses: anthropics/claude-code-action@<full-commit-sha> # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Leave `sarif` off here. A dedicated job, as in the quick start, is the better place for the SARIF upload, because `security-events: write` is a permission the agent's job should not have.

## Report only, never fail

```yaml
      - uses: hugomn/heldkeys@v0
        with:
          fail-on: none
```

## Scan tracked files for tokens

`repo-secrets: true` runs `git ls-files` and matches every tracked text file under 1 MiB against the known token formats, reporting `file:line` and a fingerprint, never the value. It looks at the current tree only. For history, run gitleaks or betterleaks.

```yaml
      - uses: hugomn/heldkeys@v0
        with:
          repo-secrets: true
```

## A repository in a subdirectory

Point `path` at the checkout. SARIF paths are relative to it, and the action passes it to `upload-sarif` as `checkout_path`:

```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          path: app
          persist-credentials: false
      - uses: hugomn/heldkeys@v0
        with:
          path: app
          sarif: true
```

## Ignore rules and baselines

`heldkeys ci` reads ignore rules from `.heldkeys.toml` in `path`, and with `baseline` it leaves out the findings a previous run already reported, so the step fails only on new risks. Whatever is left out is still counted in the verdict ("1 AI agent workflow risk, 0 credentials reachable in this job (3 ignored by .heldkeys.toml, 2 in the baseline).") and listed in the job summary with each ignore rule's reason, and SARIF uploads those results as suppressed, with the reason as the justification. The file format is in the [README](../README.md#ignoring-findings-and-baselines).

Both files are part of the repository, which is also what makes them risky: on `pull_request` the checkout is the pull request's merge commit, so a pull request can add an ignore rule, or a baseline entry, for the very risk it introduces. heldkeys cannot tell offline whether the file changed against the base branch, so in a pull request run (`pull_request`, `pull_request_target`, `issue_comment` and the other untrusted triggers) it says so whenever ignore rules or the baseline come from the checkout: the verdict reads "(1 ignored by a file the pull request can change)" or "(2 in a baseline the pull request can change)", and a warning naming the file goes to the log (stderr), the job summary, JSON `notices` and the SARIF run's tool notifications. GitLab merge request pipelines (`CI_PIPELINE_SOURCE=merge_request_event`) get the same treatment.

The baseline itself only accepts a finding that is no worse than when it was recorded: a pull request that turns an accepted Medium into a High at the same place (for example by letting anyone trigger the agent) fails the step, and the finding says "was medium in the baseline". Ignore rules' `path` patterns match only the file a finding is in, never job ids or other text the pull request picks.

Two ways to close the gap:

- **CODEOWNERS.** Require a review from the people who own security for changes to these files, so an added ignore is a reviewed decision:

  ```text
  /.heldkeys.toml           @your-org/security
  /heldkeys-baseline.json   @your-org/security
  ```

- **Read them from the default branch.** Check the two files out from the default branch into a subdirectory and point `config` and `baseline` at that copy. A pull request then cannot change what is accepted; changes to the files take effect once they are merged. A file in a nested checkout like this one does not trigger the warning.

  ```yaml
      steps:
        - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
          with:
            persist-credentials: false
        - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
          with:
            ref: ${{ github.event.repository.default_branch }}
            path: .heldkeys-base
            sparse-checkout: |
              .heldkeys.toml
              heldkeys-baseline.json
            sparse-checkout-cone-mode: false
            persist-credentials: false
        - uses: hugomn/heldkeys@v0
          with:
            config: .heldkeys-base/.heldkeys.toml
            baseline: .heldkeys-base/heldkeys-baseline.json
  ```

  Both files must exist on the default branch: a `config` or `baseline` that is not there stops the step with exit code 2 rather than running without them.

To create the baseline, run `heldkeys ci --write-baseline heldkeys-baseline.json --fail-on none` where the check runs, so it sees the same job environment, or save the JSON report of a CI run (`format: json`) and commit it. A baseline only ever accepts findings; it never adds any, and `--no-ignore` on the binary shows everything again.

## Post the report as a PR comment

The job summary is usually enough. If you want a comment as well, post the `markdown-file` output from a job that has `pull-requests: write`. On pull requests from forks the token is read-only and the comment step will fail, which is the safe behaviour; do not switch to `pull_request_target` to get around it.

```yaml
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - id: heldkeys
        uses: hugomn/heldkeys@v0
        with:
          fail-on: none
      - if: github.event_name == 'pull_request'
        env:
          GH_TOKEN: ${{ github.token }}
          PR: ${{ github.event.pull_request.number }}
          REPORT: ${{ steps.heldkeys.outputs.markdown-file }}
        run: gh pr comment "$PR" --body-file "$REPORT"
```

The Markdown report keeps itself under GitHub's 65,536-character comment limit by folding details first and then capping the tables.

## Without the action

The binary does everything the action does. In any CI:

```sh
heldkeys ci --format markdown --fail-on none --output heldkeys.md
heldkeys ci --format sarif --fail-on none --output heldkeys.sarif
heldkeys ci   # text report; exits 1 on a High finding
```

`heldkeys ci` also recognises GitLab CI (`GITLAB_CI=true`) and reports the job token and the job environment there.

## How the binary is verified

The action downloads `heldkeys-<target>.tar.xz` and `heldkeys-<target>.tar.xz.sha256` from the GitHub release and refuses to run on a mismatch. That protects against a corrupted or truncated download, not against a compromised release, because both files come from the same place. Releases are built with GitHub build provenance (from v0.1.1); to check it, run `gh attestation verify heldkeys-<target>.tar.xz --repo hugomn/heldkeys` before using the binary.

Supported runners: Linux x64 and arm64 (static musl builds) and macOS x64 and arm64. Windows runners are not supported yet.

## What it reports

| Rule | Check | What it detects | Default severity |
|---|---|---|---|
| [HK-CI-001](rules/HK-CI-001.md) | `ci-runtime` | Credential in the CI job's environment | By format |
| [HK-CI-002](rules/HK-CI-002.md) | `ci-runtime` | GitHub token in the CI job's environment | By format |
| [HK-CI-003](rules/HK-CI-003.md) | `ci-runtime` | OIDC token requests available: the job can mint cloud credentials | Medium |
| [HK-CI-004](rules/HK-CI-004.md) | `ci-runtime` | Actions runtime token with write access to the cache and artifacts | Medium |
| [HK-CI-005](rules/HK-CI-005.md) | `ci-runtime` | GITHUB_TOKEN persisted in the git config by actions/checkout | Medium |
| [HK-CI-006](rules/HK-CI-006.md) | `ci-runtime` | CI job context: platform, workflow, trigger and runner (context) | Info |
| [HK-CI-007](rules/HK-CI-007.md) | `ci-runtime` | GitLab CI job token in the job's environment | Medium |
| [HK-WF-001](rules/HK-WF-001.md) | `workflows` | AI agent step on an untrusted trigger, holding secrets or write permissions | High, Medium or Low |
| [HK-WF-002](rules/HK-WF-002.md) | `workflows` | AI agent step runs in a checkout of the PR head on an untrusted trigger | High |
| [HK-WF-003](rules/HK-WF-003.md) | `workflows` | AI agent step in a job with write-all or unrestricted default permissions | High or Medium |
| [HK-WF-004](rules/HK-WF-004.md) | `workflows` | AI agent step receives secrets it does not need | High or Medium |
| [HK-WF-005](rules/HK-WF-005.md) | `workflows` | AI agent action pinned to a tag or branch, not a commit SHA | Medium |
| [HK-WF-006](rules/HK-WF-006.md) | `workflows` | AI agent allowed to run any shell command while holding a write token | High or Medium |
| [HK-WF-007](rules/HK-WF-007.md) | `workflows` | Workflow file that could not be analysed (context) | Info |
| [HK-REPO-001](rules/HK-REPO-001.md) | `repo-secrets` | Token of a known format in a tracked file | By format |
| [HK-GITCFG-001](rules/HK-GITCFG-001.md) | `git-config` | Credential embedded in a git url.<base>.insteadOf rewrite | High |
| [HK-GITCFG-002](rules/HK-GITCFG-002.md) | `git-config` | Authorization header in git http.extraheader | High |
| [HK-GITCFG-003](rules/HK-GITCFG-003.md) | `git-config` | Credential embedded in a git remote URL | High |

On a self-hosted runner every runtime finding that is not Info is rated one level higher, because files, caches and processes can outlive the job. [HK-REPO-001](rules/HK-REPO-001.md) only runs with `repo-secrets: true`. The `HK-GITCFG` rules read the checkout's `.git/config` only, never the runner's global git config, and leave the `Authorization` header `actions/checkout` writes to [HK-CI-005](rules/HK-CI-005.md), so that token is reported once. A workflow file heldkeys could not analyse (invalid YAML, a YAML alias bomb, over 1 MiB, a reusable-workflow call it cannot follow) is reported as [HK-WF-007](rules/HK-WF-007.md), and any other file it could not read, such as `.git/config`, as [HK-READ-001](rules/HK-READ-001.md); both are Info and never fail the step. The action has no input for `--strict`; run the binary directly (`heldkeys ci --strict`) if anything heldkeys could not analyse (HK-READ-001 or HK-WF-007) should fail the job.

heldkeys only looks at what AI agents can reach. For the rest of your workflows (template injection, cache poisoning, unpinned actions in general) run [zizmor](https://github.com/zizmorcore/zizmor) alongside it.
