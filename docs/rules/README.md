# Rules

Every finding heldkeys reports carries a stable rule id. An id never changes meaning once released; SARIF output and these pages key on it. Each page says what the rule detects, why it matters when an AI agent runs in that place, and how to fix it.

`heldkeys checks` prints the same list from the binary you have installed, and `heldkeys checks --format json` gives it to scripts. The tables below are generated from that JSON, and a test fails if a rule the binary declares has no page here.

## Local rules (`heldkeys scan` and `heldkeys preflight`)

| Rule | Check | What it detects | Default severity |
|---|---|---|---|
| [HK-ENV-001](HK-ENV-001.md) | `env` | Environment variable holding a token of a known format | By format |
| [HK-ENV-002](HK-ENV-002.md) | `env` | Credential-named environment variable with a secret-looking value | High or Medium |
| [HK-ENV-003](HK-ENV-003.md) | `env` | AWS access key pair in the environment | High or Medium |
| [HK-AWS-001](HK-AWS-001.md) | `aws` | Long-lived AWS access key in a credentials or config file | High |
| [HK-AWS-002](HK-AWS-002.md) | `aws` | Temporary AWS keys stored in a credentials or config file | Medium |
| [HK-AWS-003](HK-AWS-003.md) | `aws` | AWS SSO profile with a cached session token | Medium |
| [HK-AWS-004](HK-AWS-004.md) | `aws` | AWS SSO profile without a cached session (context) | Info |
| [HK-AWS-005](HK-AWS-005.md) | `aws` | AWS profile that assumes a role | Medium |
| [HK-AWS-006](HK-AWS-006.md) | `aws` | AWS profile that mints credentials with credential_process | Medium |
| [HK-AWS-007](HK-AWS-007.md) | `aws` | Cached assumed-role credentials in ~/.aws/cli/cache | Medium |
| [HK-AWS-008](HK-AWS-008.md) | `aws` | Cached AWS session credentials in the awsume cache | Medium |
| [HK-AWS-009](HK-AWS-009.md) | `aws` | AWS keys in an aws-vault file keyring | Low, or High with the passphrase in the environment |
| [HK-AWS-010](HK-AWS-010.md) | `aws` | Granted configured to keep AWS credentials in a file keyring | Low |
| [HK-GCP-001](HK-GCP-001.md) | `gcloud` | gcloud stored login refresh tokens | High |
| [HK-GCP-002](HK-GCP-002.md) | `gcloud` | Application default credentials with a user refresh token | High |
| [HK-GCP-003](HK-GCP-003.md) | `gcloud` | Google service account key file | High |
| [HK-GCP-004](HK-GCP-004.md) | `gcloud` | Google impersonation credentials with a source refresh token | High |
| [HK-GCP-005](HK-GCP-005.md) | `gcloud` | Google workload identity federation config | Medium |
| [HK-GCP-006](HK-GCP-006.md) | `gcloud` | Google credentials file of an unrecognised type | Medium |
| [HK-AZ-001](HK-AZ-001.md) | `azure` | Azure CLI MSAL cache with refresh tokens | High |
| [HK-AZ-002](HK-AZ-002.md) | `azure` | Azure CLI MSAL cache with access tokens only | Medium |
| [HK-AZ-003](HK-AZ-003.md) | `azure` | Azure CLI token cache encrypted for the current user | High |
| [HK-AZ-004](HK-AZ-004.md) | `azure` | Pre-MSAL Azure CLI token cache with refresh tokens | High |
| [HK-AZ-005](HK-AZ-005.md) | `azure` | Azure service principal secret stored by az login | High |
| [HK-KUBE-001](HK-KUBE-001.md) | `kube` | kubeconfig user with a static bearer token | High |
| [HK-KUBE-002](HK-KUBE-002.md) | `kube` | kubeconfig user reading a bearer token from a file | High |
| [HK-KUBE-003](HK-KUBE-003.md) | `kube` | kubeconfig user with a client certificate key | High |
| [HK-KUBE-004](HK-KUBE-004.md) | `kube` | kubeconfig user with a basic-auth password | High |
| [HK-KUBE-005](HK-KUBE-005.md) | `kube` | kubeconfig user with an exec credential plugin | Medium |
| [HK-KUBE-006](HK-KUBE-006.md) | `kube` | kubeconfig user with auth-provider tokens | High or Medium |
| [HK-DOCKER-001](HK-DOCKER-001.md) | `docker` | Registry login stored inline in ~/.docker/config.json | High |
| [HK-DOCKER-002](HK-DOCKER-002.md) | `docker` | Registry logins retrievable through a Docker credential helper | Medium |
| [HK-NETRC-001](HK-NETRC-001.md) | `netrc` | Token of a known format in ~/.netrc | By format |
| [HK-NETRC-002](HK-NETRC-002.md) | `netrc` | Plaintext password in ~/.netrc | High or Medium |
| [HK-GITCRED-001](HK-GITCRED-001.md) | `git-credentials` | Plaintext git login in a credential-store file | High |
| [HK-NPM-001](HK-NPM-001.md) | `npmrc` | npm registry credential in .npmrc | High |
| [HK-PYPI-001](HK-PYPI-001.md) | `pypirc` | Package index password or token in ~/.pypirc | High |
| [HK-CARGO-001](HK-CARGO-001.md) | `cargo-credentials` | Cargo registry token in credentials.toml | High |
| [HK-CLI-001](HK-CLI-001.md) | `cli-logins` | HashiCorp Vault token in ~/.vault-token | High |
| [HK-CLI-002](HK-CLI-002.md) | `cli-logins` | Terraform Cloud API token in credentials.tfrc.json | High |
| [HK-CLI-003](HK-CLI-003.md) | `cli-logins` | Vercel CLI login token in auth.json | High |
| [HK-CLI-004](HK-CLI-004.md) | `cli-logins` | Netlify CLI login token in config.json | High |
| [HK-CLI-005](HK-CLI-005.md) | `cli-logins` | Fly.io CLI access token in config.yml | High |
| [HK-CLI-006](HK-CLI-006.md) | `cli-logins` | Supabase CLI access token on disk | High |
| [HK-CLI-007](HK-CLI-007.md) | `cli-logins` | Cloudflare Wrangler OAuth or API token in its config | High |
| [HK-CLI-008](HK-CLI-008.md) | `cli-logins` | Stripe CLI API key in config.toml | High (live mode) or Low (test mode) |
| [HK-CLI-009](HK-CLI-009.md) | `cli-logins` | Doppler CLI token in .doppler.yaml | High |
| [HK-CLI-010](HK-CLI-010.md) | `cli-logins` | Railway CLI login token in config.json | High |
| [HK-CLI-011](HK-CLI-011.md) | `cli-logins` | Kaggle API key in kaggle.json | Medium |
| [HK-DOTENV-001](HK-DOTENV-001.md) | `dotenv` | Token of a known format in a .env file | By format |
| [HK-DOTENV-002](HK-DOTENV-002.md) | `dotenv` | Credential-named entry with a secret-looking value in a .env file | High or Medium |
| [HK-DOTENV-003](HK-DOTENV-003.md) | `dotenv` | Credential in an editor history copy of a .env file | Same as the value: by format, or High or Medium |
| [HK-SSH-001](HK-SSH-001.md) | `ssh-agent` | SSH key loaded in the running ssh-agent | Medium |
| [HK-SSH-002](HK-SSH-002.md) | `ssh-agent` | SSH private key file without a passphrase | High |
| [HK-GIT-001](HK-GIT-001.md) | `git-helper` | Git credential helper that stores logins in plaintext | Medium |
| [HK-GIT-002](HK-GIT-002.md) | `git-helper` | Git credential helper that caches logins in memory | Medium |
| [HK-GIT-003](HK-GIT-003.md) | `git-helper` | Git configured to use the GitHub CLI token | Medium |
| [HK-GIT-004](HK-GIT-004.md) | `git-helper` | Git credential helper backed by a keychain or other store | Medium |
| [HK-GIT-005](HK-GIT-005.md) | `git-helper` | GitHub CLI token stored in plaintext hosts.yml | High |
| [HK-GIT-006](HK-GIT-006.md) | `git-helper` | GitHub CLI login with its token in the OS keyring | High |
| [HK-GITCFG-001](HK-GITCFG-001.md) | `git-config` | Credential embedded in a git url.<base>.insteadOf rewrite | High |
| [HK-GITCFG-002](HK-GITCFG-002.md) | `git-config` | Authorization header in git http.extraheader | High |
| [HK-GITCFG-003](HK-GITCFG-003.md) | `git-config` | Credential embedded in a git remote URL | High |
| [HK-MCP-001](HK-MCP-001.md) | `mcp` | Token of a known format in an MCP server config (env, args, URL or headers) | By format |
| [HK-MCP-002](HK-MCP-002.md) | `mcp` | Credential-named value with a secret-looking value in an MCP server config | High or Medium |
| [HK-MCP-003](HK-MCP-003.md) | `mcp` | Project-level MCP config whose servers start when an agent opens the directory (context) | Info |
| [HK-AI-001](HK-AI-001.md) | `ai-logins` | OpenAI Codex CLI login or API key in auth.json | High |
| [HK-AI-002](HK-AI-002.md) | `ai-logins` | Claude Code OAuth login stored in .credentials.json | High |
| [HK-AI-003](HK-AI-003.md) | `ai-logins` | Credential or API key helper in Claude Code settings | By format, or Medium for apiKeyHelper |
| [HK-AI-004](HK-AI-004.md) | `ai-logins` | Gemini CLI OAuth login or API key on disk | High, or by format for ~/.gemini/.env |
| [HK-AI-005](HK-AI-005.md) | `ai-logins` | GitHub Copilot OAuth token in apps.json or hosts.json | Medium |
| [HK-AI-006](HK-AI-006.md) | `ai-logins` | Hugging Face access token on disk | Medium |
| [HK-SOCK-001](HK-SOCK-001.md) | `docker-socket` | Docker daemon socket reachable by this user | High |
| [HK-K8SSA-001](HK-K8SSA-001.md) | `k8s-service-account` | Readable Kubernetes service account token | High |
| [HK-META-001](HK-META-001.md) | `cloud-metadata` | Cloud instance metadata endpoint reachable (context) | Info |
| [HK-READ-001](HK-READ-001.md) | `read-errors` | A file a check looks at exists but could not be read or parsed (context) | Info |

"By format" means the severity comes from the token format: High for long-lived cloud, source-control and AI provider keys, Medium for short-lived ones, Low for test-mode keys.

## CI rules (`heldkeys ci`)

| Rule | Check | What it detects | Default severity |
|---|---|---|---|
| [HK-CI-001](HK-CI-001.md) | `ci-runtime` | Credential in the CI job's environment | By format |
| [HK-CI-002](HK-CI-002.md) | `ci-runtime` | GitHub token in the CI job's environment | By format |
| [HK-CI-003](HK-CI-003.md) | `ci-runtime` | OIDC token requests available: the job can mint cloud credentials | Medium |
| [HK-CI-004](HK-CI-004.md) | `ci-runtime` | Actions runtime token with write access to the cache and artifacts | Medium |
| [HK-CI-005](HK-CI-005.md) | `ci-runtime` | GITHUB_TOKEN persisted in the git config by actions/checkout | Medium |
| [HK-CI-006](HK-CI-006.md) | `ci-runtime` | CI job context: platform, workflow, trigger and runner (context) | Info |
| [HK-CI-007](HK-CI-007.md) | `ci-runtime` | GitLab CI job token in the job's environment | Medium |
| [HK-WF-001](HK-WF-001.md) | `workflows` | AI agent step on an untrusted trigger, holding secrets or write permissions | High, Medium or Low |
| [HK-WF-002](HK-WF-002.md) | `workflows` | AI agent step runs in a checkout of the PR head on an untrusted trigger | High |
| [HK-WF-003](HK-WF-003.md) | `workflows` | AI agent step in a job with write-all or unrestricted default permissions | High or Medium |
| [HK-WF-004](HK-WF-004.md) | `workflows` | AI agent step receives secrets it does not need | High or Medium |
| [HK-WF-005](HK-WF-005.md) | `workflows` | AI agent action pinned to a tag or branch, not a commit SHA | Medium |
| [HK-WF-006](HK-WF-006.md) | `workflows` | AI agent allowed to run any shell command while holding a write token | High or Medium |
| [HK-WF-007](HK-WF-007.md) | `workflows` | Workflow file that could not be analysed (context) | Info |
| [HK-REPO-001](HK-REPO-001.md) | `repo-secrets` | Token of a known format in a tracked file | By format |

On a self-hosted runner every `ci-runtime` finding that is not Info is rated one level higher, because files, caches and processes can outlive the job. `HK-WF-001` is rated one level lower when something restricts who can start the agent (an `if:` that only lets named actors, OWNER, MEMBER and COLLABORATOR, or same-repository pull requests through, on the job or on a job it needs, or claude-code-action's own write-access check; a negative check such as `github.actor != 'bot'` does not count). The `HK-WF` rules follow local reusable workflows into the workflow they call, with the caller's triggers, permissions and secrets. `HK-REPO-001` only runs with `heldkeys ci --repo-secrets`. The `git-config` check also runs in `heldkeys ci`, on the repository's `.git/config` only; inside GitHub Actions it leaves the checkout's `Authorization` header to `HK-CI-005`. `HK-READ-001` is reported in every mode (`scan`, `preflight` and `ci`). `--strict` makes `HK-READ-001` and `HK-WF-007` fail the run, the rules that mean something could not be analysed.

## Incident rules (`heldkeys incident black-october`)

| Rule | Check | What it detects | Default severity |
|---|---|---|---|
| [HK-LITELLM-001](HK-LITELLM-001.md) | `ioc-litellm` | litellm 1.107.0 installed in a Python environment | High |
| [HK-LITELLM-002](HK-LITELLM-002.md) | `ioc-litellm` | LiteLLM stealer or loader file in a site-packages directory | High |
| [HK-LITELLM-003](HK-LITELLM-003.md) | `ioc-litellm` | Marker or lock file of the LiteLLM stealer in the temp directory | High |
| [HK-LITELLM-004](HK-LITELLM-004.md) | `ioc-litellm` | PRIVCOLLECT_ACTIVE set in the environment by the LiteLLM stealer | High |
| [HK-LITELLM-005](HK-LITELLM-005.md) | `ioc-litellm` | Detached Python process of the LiteLLM remote code loader | High |
| [HK-LITELLM-006](HK-LITELLM-006.md) | `ioc-litellm` | LiteLLM Docker image with a compromised digest or the v1.107.0 tag | High, or Medium for the tag alone |
| [HK-LITELLM-007](HK-LITELLM-007.md) | `ioc-litellm` | Project requirements or lockfile pin litellm 1.107.0 | Medium |
| [HK-OVH-001](HK-OVH-001.md) | `ioc-ovhcloud` | ovhcloud CLI binary matching a published malicious build (MD5) | High |
| [HK-OVH-002](HK-OVH-002.md) | `ioc-ovhcloud` | ovhcloud CLI from the tampered release range, or installed in the tampering window | Medium, Low or Info |
| [HK-OVH-003](HK-OVH-003.md) | `ioc-ovhcloud` | envchecker working directory left by the OVHcloud CLI stealer | High |
| [HK-RT-001](HK-RT-001.md) | `runtime-versions` | PHP without the php2shell fixes (8.5.12, 8.4.27, 8.3.36, 8.2.35), or end of life | Low, or Medium for end of life |
| [HK-RT-002](HK-RT-002.md) | `runtime-versions` | Node.js without the October 2026 security release (26.12.1, 24.22.1, 22.23.4), or end of life | Low |
| [HK-BREACH-001](HK-BREACH-001.md) | `platform-breaches` | Railway login or project: environment variables stored there may have been read (21 Oct 2026) | Medium |
| [HK-BREACH-002](HK-BREACH-002.md) | `platform-breaches` | Zeabur login or project: the platform database was read (14 to 15 Oct 2026) | Medium |
| [HK-BREACH-003](HK-BREACH-003.md) | `platform-breaches` | OpenCode data on disk: provider keys linked in OpenCode Console may be exposed (17 Oct 2026) | Low |

The indicator checks (`ioc-litellm`, `ioc-ovhcloud`) decide the verdict: a High finding of theirs is a confirmed indicator and makes `heldkeys incident` exit 1; Medium and Low ones are signs of exposure to check. `runtime-versions` and `platform-breaches` findings are not credentials and never count as such; they are listed so the patch list, the rotation list and the notices from platforms come out of one run. Every incident report carries the date its indicator list was last checked against the advisories, and links them.

## Page template

New rule pages follow the same shape, so they are easy to scan:

1. A title line: `# HK-AREA-NNN: <summary>`, with the summary exactly as declared in the `Rule` const.
2. A table: check id, which command runs it, default severity.
3. **What it detects**: the files, variables or sockets read, and what in them counts.
4. **Why it matters for agents**: what a hijacked agent could do with it.
5. **How to fix**: concrete commands, most effective first.
6. **Example**: one finding as `heldkeys --format json` (or `heldkeys ci --format json`) reports it, with fake values. JSON keeps every field whole, where the text output cuts long titles and places to fit the terminal.
7. **References**: vendor documentation.
