//! The maintained list of AI agents: actions, reusable workflows and CLIs.
//!
//! Adding an agent means adding an `AgentAction` (for an action or reusable
//! workflow) or an `AGENT_COMMANDS` entry (for a CLI run from a `run:` step).

use super::script::{plain_args, program, shell_code, simple_commands};
use crate::yaml::Yaml;

/// An action (or reusable workflow) that runs an AI agent.
pub(super) struct AgentAction {
    /// `owner/repo` or `owner/repo/path`, matched case-insensitively against
    /// the part of `uses:` before `@`.
    pub prefix: &'static str,
    pub name: &'static str,
    /// Inputs (and env names) that carry the credentials the agent itself
    /// needs, per the action's README. Secrets passed here are expected.
    pub credential_inputs: &'static [&'static str],
    /// True if the action trades the job's OIDC token (`id-token: write`) for
    /// a GitHub App token of its own, which has write access to the repo.
    pub oidc_app_token: bool,
    /// True if the action refuses to run for actors without write access to
    /// the repo, unless its `allowed_non_write_users` input is set.
    pub checks_actor_write: bool,
}

/// Agent actions. Keep sorted by vendor; add new ones here.
pub(super) const AGENT_ACTIONS: &[AgentAction] = &[
    // https://github.com/anthropics/claude-code-action (v1: claude_args, settings)
    AgentAction {
        prefix: "anthropics/claude-code-action",
        name: "Claude Code",
        credential_inputs: &[
            "anthropic_api_key",
            "claude_code_oauth_token",
            "github_token",
        ],
        oidc_app_token: true,
        checks_actor_write: true,
    },
    // The lower-level action claude-code-action is built on.
    AgentAction {
        prefix: "anthropics/claude-code-base-action",
        name: "Claude Code",
        credential_inputs: &["anthropic_api_key", "claude_code_oauth_token"],
        oidc_app_token: false,
        checks_actor_write: false,
    },
    // https://github.com/openai/codex-action
    AgentAction {
        prefix: "openai/codex-action",
        name: "Codex",
        credential_inputs: &["openai-api-key", "azure-openai-api-key"],
        oidc_app_token: false,
        checks_actor_write: false,
    },
    // https://github.com/google-github-actions/run-gemini-cli
    AgentAction {
        prefix: "google-github-actions/run-gemini-cli",
        name: "Gemini CLI",
        credential_inputs: &["gemini_api_key", "google_api_key"],
        oidc_app_token: false,
        checks_actor_write: false,
    },
    // The earlier name of run-gemini-cli.
    AgentAction {
        prefix: "google-gemini/gemini-cli-action",
        name: "Gemini CLI",
        credential_inputs: &["gemini_api_key", "google_api_key"],
        oidc_app_token: false,
        checks_actor_write: false,
    },
    // https://github.com/actions/ai-inference: a single model call, but with
    // MCP tools enabled it acts on the repo with the token it is given.
    AgentAction {
        prefix: "actions/ai-inference",
        name: "GitHub AI inference",
        credential_inputs: &["token"],
        oidc_app_token: false,
        checks_actor_write: false,
    },
    // GitHub Agentic Workflows (gh-aw) are not listed: their compiled
    // `.lock.yml` files run the agent as a CLI in a `run:` step, which the
    // command list below catches, so listing the setup action would report
    // the same job twice.
    // Qodo PR-Agent (formerly Codium-ai/pr-agent).
    AgentAction {
        prefix: "qodo-ai/pr-agent",
        name: "PR-Agent",
        credential_inputs: &[],
        oidc_app_token: false,
        checks_actor_write: false,
    },
    AgentAction {
        prefix: "codium-ai/pr-agent",
        name: "PR-Agent",
        credential_inputs: &[],
        oidc_app_token: false,
        checks_actor_write: false,
    },
    // OpenHands resolver, used as a reusable workflow (`jobs.<id>.uses`).
    AgentAction {
        prefix: "all-hands-ai/openhands",
        name: "OpenHands",
        credential_inputs: &["llm_api_key"],
        oidc_app_token: false,
        checks_actor_write: false,
    },
    AgentAction {
        prefix: "openhands/openhands",
        name: "OpenHands",
        credential_inputs: &["llm_api_key"],
        oidc_app_token: false,
        checks_actor_write: false,
    },
];

/// The agent a CLI step runs: no documented inputs, model keys are expected.
pub(super) const CLI_AGENT: AgentAction = AgentAction {
    prefix: "",
    name: "agent CLI",
    credential_inputs: &[],
    oidc_app_token: false,
    checks_actor_write: false,
};

/// The Copilot coding agent, seen through its setup job.
pub(super) const COPILOT_AGENT: AgentAction = AgentAction {
    prefix: "",
    name: "Copilot coding agent",
    credential_inputs: &[],
    oidc_app_token: false,
    checks_actor_write: false,
};

/// A cloud model backend Claude Code can use instead of the Anthropic API.
/// With one selected, cloud credentials (or `id-token: write` to mint them)
/// are what the agent needs to reach its model, not an extra.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum CloudBackend {
    Bedrock,
    Vertex,
}

impl CloudBackend {
    pub(super) fn name(self) -> &'static str {
        match self {
            CloudBackend::Bedrock => "Amazon Bedrock",
            CloudBackend::Vertex => "Google Vertex AI",
        }
    }

    /// True if a secret's name says it is this cloud's credential.
    pub(super) fn owns_secret(self, name: &str) -> bool {
        let upper = name.to_ascii_uppercase();
        let markers: &[&str] = match self {
            CloudBackend::Bedrock => &["AWS"],
            CloudBackend::Vertex => &[
                "GOOGLE",
                "GCP",
                "GCLOUD",
                "CLOUDSDK",
                "SERVICE_ACCOUNT",
                "WORKLOAD_IDENTITY",
            ],
        };
        markers.iter().any(|m| upper.contains(m))
    }
}

/// The cloud backend a step selects: claude-code-action's `use_bedrock` /
/// `use_vertex` inputs, or Claude Code's `CLAUDE_CODE_USE_BEDROCK` /
/// `CLAUDE_CODE_USE_VERTEX` environment variables.
pub(super) fn cloud_backend(step: &Yaml) -> Option<CloudBackend> {
    let on = |node: &Yaml| match node {
        Yaml::Boolean(b) => *b,
        Yaml::Integer(i) => *i == 1,
        Yaml::String(s) => matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1"),
        _ => false,
    };
    let selects = |input: &str, env: &str| on(&step["with"][input]) || on(&step["env"][env]);
    if selects("use_bedrock", "CLAUDE_CODE_USE_BEDROCK") {
        Some(CloudBackend::Bedrock)
    } else if selects("use_vertex", "CLAUDE_CODE_USE_VERTEX") {
        Some(CloudBackend::Vertex)
    } else {
        None
    }
}

/// Copilot coding agent: its setup steps live in this file, in this job, and
/// run in the same environment the agent then works in.
pub(super) const COPILOT_SETUP_FILES: &[&str] =
    &["copilot-setup-steps.yml", "copilot-setup-steps.yaml"];
pub(super) const COPILOT_SETUP_JOB: &str = "copilot-setup-steps";

/// Agent CLIs that run as a command in a `run:` step: `(name, programs)`,
/// the CLI's own name and the package that provides it. Matched only as the
/// program of a simple command (see `script::program`), so that `npm install
/// -g @anthropic-ai/claude-code` or `echo claude` do not count, while
/// `timeout 600 claude`, `if claude ...; then`, `/usr/local/bin/claude`,
/// `npx -y @anthropic-ai/claude-code` and `bash -c 'claude ...'` do.
const AGENT_COMMANDS: &[(&str, &[&str])] = &[
    ("claude", &["claude", "@anthropic-ai/claude-code"]),
    ("codex", &["codex", "@openai/codex"]),
    ("gemini", &["gemini", "@google/gemini-cli"]),
    ("copilot", &["copilot", "@github/copilot"]),
    ("aider", &["aider", "aider-chat"]),
    ("opencode", &["opencode", "opencode-ai"]),
    ("cursor-agent", &["cursor-agent"]),
];

/// Arguments that only print something about the CLI, so the agent never runs.
const NOT_A_RUN: &[&str] = &["--version", "-v", "-V", "--help", "-h"];

/// The first agent CLI invoked in a `run:` script. Comments, quoted strings
/// and prose heredocs are not code, so `echo "codex ran"` and `cat <<EOF`
/// text that mentions `claude` do not count; neither does `gemini
/// --version`. The argument of `bash -c`/`eval` and a heredoc fed to a shell
/// (`bash <<'EOF'`) are code, and so is everything after a quote that is
/// never closed.
pub(super) fn agent_command(run: &str) -> Option<&'static str> {
    let code = shell_code(run, true);
    simple_commands(&code).find_map(|command| {
        let (name, args) = program(command)?;
        let (agent, _) = AGENT_COMMANDS
            .iter()
            .find(|(_, programs)| programs.contains(&name.as_str()))?;
        let args = plain_args(&args);
        let only_prints = matches!(args.as_slice(), [arg] if NOT_A_RUN.contains(arg));
        (!only_prints).then_some(*agent)
    })
}

/// `owner/repo[/path]` of a `uses:` value, without the `@ref`.
pub(super) fn action_name(uses: &str) -> &str {
    uses.split('@').next().unwrap_or(uses).trim()
}

pub(super) fn known_action(uses: &str) -> Option<&'static AgentAction> {
    let name = action_name(uses).to_ascii_lowercase();
    AGENT_ACTIONS
        .iter()
        .find(|a| name == a.prefix || name.starts_with(&format!("{}/", a.prefix)))
}

/// A full commit SHA (40 hex characters; 64 for SHA-256 repos).
pub(super) fn is_sha(reference: &str) -> bool {
    matches!(reference.len(), 40 | 64) && reference.chars().all(|c| c.is_ascii_hexdigit())
}

/// `uses:` for display: a full SHA is shortened to 7 characters, like git does.
pub(super) fn short_uses(uses: &str) -> String {
    match uses.split_once('@') {
        Some((name, reference)) if is_sha(reference) => format!("{name}@{}", &reference[..7]),
        _ => uses.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_commands_in_run_steps() {
        assert_eq!(agent_command("claude -p 'review'"), Some("claude"));
        assert_eq!(
            agent_command("npx -y @anthropic-ai/claude-code -p x"),
            Some("claude")
        );
        assert_eq!(
            agent_command("set -e\ncodex exec --full-auto 'fix'"),
            Some("codex")
        );
        assert_eq!(
            agent_command("cat prompt.md | gemini --yolo"),
            Some("gemini")
        );
        assert_eq!(agent_command("aider --message 'x'"), Some("aider"));
        assert_eq!(
            agent_command("RESULT=\"$(claude -p 'summarise')\""),
            Some("claude")
        );
        assert_eq!(
            agent_command("npm install -g @anthropic-ai/claude-code"),
            None
        );
        assert_eq!(agent_command("echo claude is great"), None);
        assert_eq!(agent_command("./scripts/claude-review.sh"), None);
        assert_eq!(agent_command("cargo test"), None);
    }

    #[test]
    fn prose_heredocs_and_comments_are_not_commands() {
        let script = "cat <<'NOTES'\nclaude review was done\nNOTES\necho \"it is time codex ran\"\ngemini --version || true\n# claude -p 'later'\n";
        assert_eq!(agent_command(script), None);
        assert_eq!(agent_command("echo 'x\n claude -p y'"), None);
        assert_eq!(
            agent_command("cat <<-EOF\n\tclaude\n\tEOF\nclaude -p go"),
            Some("claude")
        );
    }

    /// Shell constructs that hide an agent call: each script runs an agent,
    /// and each must be found.
    #[test]
    fn agent_calls_behind_shell_syntax_are_found() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "quoted heredoc",
                "bash <<'SCRIPT'\nclaude -p \"fix\" --dangerously-skip-permissions\nSCRIPT",
                "claude",
            ),
            (
                "arith shift",
                "x=$((1<<EOF))\nclaude -p fix\necho done",
                "claude",
            ),
            ("sh -c", "sh -c 'codex exec --full-auto fix'", "codex"),
            ("backslash", "\\claude -p fix", "claude"),
            ("command", "command claude -p fix", "claude"),
            ("timeout", "timeout 600 claude -p fix", "claude"),
            ("subshell", "(claude -p fix)", "claude"),
            ("if", "if claude -p fix; then echo ok; fi", "claude"),
            ("abs path", "/usr/local/bin/claude -p fix", "claude"),
            ("rel path", "./node_modules/.bin/claude -p fix", "claude"),
            (
                "npm exec",
                "npm exec -- @anthropic-ai/claude-code -p fix",
                "claude",
            ),
            ("env", "env ANTHROPIC_API_KEY=x claude -p fix", "claude"),
            ("cmd subst", "echo \"$(claude -p fix)\"", "claude"),
            ("group", "{ claude -p fix; }", "claude"),
            (
                "heredoc comment",
                "cat <<EOF # comment\nhi\nEOF\nclaude -p fix",
                "claude",
            ),
            (
                "quote splice",
                "echo 'it'\"'\"'s' && claude -p fix",
                "claude",
            ),
            (
                "escaped quotes",
                "echo \\\"\nclaude -p fix\necho \\\"",
                "claude",
            ),
            (
                "unterminated quote",
                "echo \"unterminated\nclaude -p fix",
                "claude",
            ),
            // More prefixes, wrappers and runners.
            ("while", "while ! claude -p fix; do sleep 1; done", "claude"),
            ("until", "until codex exec fix; do :; done", "codex"),
            ("else", "if true; then :; else gemini -p x; fi", "gemini"),
            ("or", "false || aider --yes", "aider"),
            ("assign", "FOO=1 BAR=\"x y\" claude -p fix", "claude"),
            ("nohup", "nohup claude -p fix &", "claude"),
            ("exec", "exec claude -p fix", "claude"),
            ("time", "time claude -p x", "claude"),
            ("stdbuf", "stdbuf -oL claude -p fix | tee out", "claude"),
            (
                "xargs",
                "git diff --name-only | xargs -n1 claude -p",
                "claude",
            ),
            ("sudo", "sudo -E -u runner claude -p fix", "claude"),
            ("bash -ec", "bash -ec \"codex exec fix\"", "codex"),
            ("eval", "eval \"$CMD\" && eval 'opencode run x'", "opencode"),
            ("pnpm dlx", "pnpm dlx @google/gemini-cli -p x", "gemini"),
            ("yarn dlx", "yarn dlx @openai/codex exec x", "codex"),
            (
                "bunx",
                "bunx @anthropic-ai/claude-code@latest -p x",
                "claude",
            ),
            ("npm x", "npm x --yes @github/copilot -- -p x", "copilot"),
            ("relative", "../bin/cursor-agent -p x", "cursor-agent"),
            ("pipe to sh", "cat <<EOF | sh\ncodex exec fix\nEOF", "codex"),
            (
                "python",
                "python3 - <<'PY'\nimport os\nPY\nclaude -p x",
                "claude",
            ),
        ];
        for (id, script, agent) in cases {
            assert_eq!(agent_command(script), Some(*agent), "{id}: {script:?}");
        }
    }

    #[test]
    fn mentions_of_agents_are_still_not_calls() {
        for script in [
            "npm install -g @anthropic-ai/claude-code",
            "echo claude is great",
            "./scripts/claude-review.sh",
            "cargo test",
            "cat <<'NOTES'\nclaude review was done\nNOTES",
            "cat <<EOF > notes.md\nrun claude -p x\nEOF",
            "echo \"it is time codex ran\"",
            "gemini --version || true",
            "claude --version 2>&1",
            "codex --help > /dev/null",
            "# claude -p 'later'",
            "echo 'x\n claude -p y'",
            "command -v claude",
            "which claude && type codex",
            "bash -c 'echo claude'",
            "for a in claude codex; do echo $a; done",
            "x=$((1<<2)); echo claude",
        ] {
            assert_eq!(agent_command(script), None, "{script:?}");
        }
    }

    #[test]
    fn sha_pins() {
        assert!(is_sha("0123456789abcdef0123456789abcdef01234567"));
        assert!(!is_sha("v1"));
        assert!(!is_sha("0123456"));
    }
}
