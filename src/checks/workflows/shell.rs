//! Shell grants: settings that let an agent run any command without asking.

use std::sync::LazyLock;

use regex::Regex;

use super::script::shell_code;
use super::secrets::strings_by_key;
use crate::sanitize::clip;
use crate::yaml::{self, Yaml};

/// Flags and settings that let an agent run any shell command without asking.
const SHELL_GRANTS: &[(&str, &str)] = &[
    (
        "--dangerously-skip-permissions",
        "claude --dangerously-skip-permissions",
    ),
    (
        "bypassPermissions",
        "claude permission mode bypassPermissions",
    ),
    (
        "--dangerously-bypass-approvals-and-sandbox",
        "codex --dangerously-bypass-approvals-and-sandbox",
    ),
    ("danger-full-access", "codex sandbox danger-full-access"),
    (
        "--full-auto",
        "codex --full-auto (runs commands without approval)",
    ),
    ("--yolo", "--yolo (approves every tool call)"),
    (
        "--yes-always",
        "aider --yes-always (runs the shell commands it suggests)",
    ),
    ("--allow-all-tools", "copilot --allow-all-tools"),
];

/// `Bash`, `Bash(*)`, `Bash(:*)` as an allowed tool: any shell command.
static UNRESTRICTED_BASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s,"'\[=])Bash(?:\(\s*\*?\s*(?::\s*\*)?\s*\))?(?:$|[\s,"'\]])"#)
        .expect("valid regex")
});
/// gemini's yolo approval mode, spelled as a flag or a setting.
static GEMINI_YOLO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)approval[-_]?mode["']?\s*[:=\s]\s*["']?yolo"#).expect("valid regex")
});
/// copilot's `--allow-tool shell` (unrestricted, unlike `shell(git)`).
static COPILOT_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"--allow-tool[ =]+["']?shell["']?(?:\s|$)"#).expect("valid regex")
});

/// A filtered shell tool in an allow list: `Bash(npm test:*)` (Claude Code),
/// `run_shell_command(make)` (Gemini CLI), `shell(npm)` (Copilot CLI).
static SHELL_TOOL_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Bash|run_shell_command|ShellTool|shell)\(([^)]*)\)").expect("valid regex")
});

/// Programs that run code the repository controls (its scripts, build files,
/// package.json, Makefile, conftest.py...) or any command they are given. An
/// agent allowed to start one of them, even with a fixed first argument such
/// as `npm test`, can run whatever a prompt injection (or the PR) puts there,
/// so the entry counts as a shell grant.
const RUNS_ANY_CODE: &[&str] = &[
    // Shells, and programs that run their arguments as a command.
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "pwsh",
    "powershell",
    "sudo",
    "su",
    "doas",
    "env",
    "xargs",
    "exec",
    "eval",
    "source",
    "nohup",
    "timeout",
    "nice",
    "find",
    "awk",
    "gawk",
    "sed",
    "docker",
    "podman",
    // Interpreters.
    "node",
    "deno",
    "bun",
    "tsx",
    "ts-node",
    "python",
    "python2",
    "python3",
    "ruby",
    "perl",
    "php",
    "lua",
    // Package managers and build runners: they run repository scripts.
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "yarn",
    "bunx",
    "pip",
    "pip3",
    "pipx",
    "uv",
    "uvx",
    "poetry",
    "pipenv",
    "pytest",
    "tox",
    "nox",
    "bundle",
    "rake",
    "composer",
    "make",
    "cmake",
    "ninja",
    "just",
    "task",
    "cargo",
    "go",
    "gradle",
    "gradlew",
    "mvn",
    "mvnw",
    "ant",
    "sbt",
    "dotnet",
    "swift",
];

/// `git` and `gh` subcommands that run arbitrary commands: `git -c
/// core.pager=...`, git aliases, `git rebase --exec`, `gh alias set --shell`.
const GIT_RUNS_ANY_CODE: &[&str] = &[
    "-c",
    "config",
    "alias",
    "submodule",
    "rebase",
    "bisect",
    "filter-branch",
];
const GH_RUNS_ANY_CODE: &[&str] = &["alias", "extension", "ext"];

/// If a filtered shell entry (the text inside `Bash(...)`) can still run code
/// the repository or the prompt controls, the program that does it.
fn runs_any_code(entry: &str) -> Option<String> {
    let command = entry.trim();
    let command = command
        .strip_suffix(":*")
        .or_else(|| command.strip_suffix('*'))
        .unwrap_or(command);
    let mut words = command.split_whitespace();
    let first = words.next()?.trim_end_matches(':');
    if first.starts_with("./") || first.starts_with("../") {
        return Some("a script from the repository".to_string());
    }
    let program = first.rsplit('/').next().unwrap_or(first);
    let sub = words.next().map(|w| w.trim_end_matches(':'));
    let any_sub = |list: &[&str]| sub.is_none_or(|s| s == "*" || list.contains(&s));
    let runs = RUNS_ANY_CODE.contains(&program)
        || (program == "git" && any_sub(GIT_RUNS_ANY_CODE))
        || (program == "gh" && any_sub(GH_RUNS_ANY_CODE));
    runs.then(|| match sub {
        Some(s) if program == "git" || program == "gh" => format!("{program} {s}"),
        _ => program.to_string(),
    })
}

/// The parts of `text` that list allowed tools: after `--allowedTools` /
/// `--allowed-tools` (Claude Code) or `--allow-tool` (Copilot CLI), up to the
/// next flag. Keeps `--disallowedTools Bash` and `--deny-tool` out.
fn allowed_tools_segments(text: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    for flag in [
        "--allowedTools",
        "--allowed-tools",
        "--allowed_tools",
        "--allow-tool",
    ] {
        let mut rest = text;
        while let Some(i) = rest.find(flag) {
            let after = &rest[i + flag.len()..];
            let end = after
                .find(" --")
                .or_else(|| after.find("\n--"))
                .unwrap_or(after.len());
            segments.push(&after[..end]);
            rest = after;
        }
    }
    segments
}

/// The tools a settings JSON (Claude Code's or Gemini CLI's, passed inline
/// as the action's `settings` input) allows. Only allow lists are read, so a
/// `deny: ["Bash"]` never counts as a grant. A path instead of JSON yields nothing.
fn settings_allow_list(text: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let lists = [
        &v["permissions"]["allow"], // Claude Code
        &v["coreTools"],            // Gemini CLI (older key)
        &v["tools"]["core"],        // Gemini CLI
        &v["allowedTools"],         // Gemini CLI, no confirmation (older key)
        &v["tools"]["allowed"],     // Gemini CLI, no confirmation
    ];
    lists
        .iter()
        .filter_map(|l| l.as_array())
        .flatten()
        .filter_map(|t| t.as_str().map(str::to_string))
        .collect()
}

/// Inputs and env names whose value is text for the model (a prompt, extra
/// instructions), not arguments. A prompt that mentions `--yolo` grants nothing.
fn is_prompt_text(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("prompt") || key.contains("instruction")
}

/// One place a grant can be spelled: an input or env value, or a script.
struct ArgText {
    key: String,
    /// The text as tool lists are read from it (quotes kept: `--allowedTools "Bash"`).
    text: String,
    /// The text flags are read from: for scripts, quoted strings removed, so
    /// `claude -p "never use --yolo"` grants nothing.
    flags: String,
}

/// Shell grants found in a step's inputs, env and script.
pub(super) fn shell_grants(step: &Yaml) -> Vec<String> {
    let mut grants: Vec<String> = Vec::new();
    let mut add = |g: &str| {
        if !grants.iter().any(|x| x == g) {
            grants.push(g.to_string());
        }
    };
    let mut texts: Vec<ArgText> = strings_by_key(&step["with"])
        .into_iter()
        .chain(strings_by_key(&step["env"]))
        .filter(|(key, _)| !is_prompt_text(key))
        .map(|(key, text)| ArgText {
            key,
            flags: text.clone(),
            text,
        })
        .collect();
    if let Some(run) = yaml::str_at(step, "run") {
        texts.push(ArgText {
            key: "run".to_string(),
            text: shell_code(run, false),
            flags: shell_code(run, true),
        });
    }
    for ArgText { key, text, flags } in &texts {
        for (needle, label) in SHELL_GRANTS {
            if flags.contains(needle) {
                add(label);
            }
        }
        let key = key.to_ascii_lowercase();
        let mut tool_lists: Vec<String> = allowed_tools_segments(text)
            .into_iter()
            .map(str::to_string)
            .collect();
        // claude-code-action v0 took a comma-separated `allowed_tools` input.
        if matches!(key.as_str(), "allowed_tools" | "allowedtools") {
            tool_lists.push(text.clone());
        }
        let settings = if key == "settings" {
            settings_allow_list(text)
        } else {
            Vec::new()
        };
        tool_lists.extend(settings.iter().cloned());
        if tool_lists.iter().any(|s| UNRESTRICTED_BASH.is_match(s)) {
            add("Bash allowed without a command filter");
        }
        for list in &tool_lists {
            for entry in SHELL_TOOL_ENTRY.captures_iter(list) {
                if let Some(program) = runs_any_code(&entry[1]) {
                    add(&format!("{} runs any code ({program})", clip(&entry[0])));
                }
            }
        }
        if settings
            .iter()
            .any(|t| t == "run_shell_command" || t == "ShellTool")
        {
            add("gemini run_shell_command without a command filter");
        }
        if GEMINI_YOLO.is_match(flags) {
            add("gemini approval mode yolo");
        }
        if COPILOT_SHELL.is_match(text) {
            add("copilot --allow-tool shell");
        }
        if key == "sandbox" && text.trim() == "danger-full-access" {
            add("codex sandbox danger-full-access");
        }
        if key == "safety-strategy" && text.trim() == "unsafe" {
            add("codex safety-strategy unsafe");
        }
    }
    grants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_json_allow_lists() {
        let step = |settings: &str| {
            let doc = yaml::load(&format!(
                "uses: anthropics/claude-code-action@v1\nwith:\n  settings: '{settings}'\n"
            ))
            .unwrap();
            shell_grants(&doc)
        };
        assert_eq!(
            step(r#"{"permissions": {"allow": ["Bash(*)", "Read"]}}"#),
            vec!["Bash allowed without a command filter"]
        );
        assert!(
            step(r#"{"permissions": {"allow": ["Bash(git diff:*)"], "deny": ["Bash"]}}"#)
                .is_empty()
        );
        assert_eq!(
            step(r#"{"coreTools": ["run_shell_command"]}"#),
            vec!["gemini run_shell_command without a command filter"]
        );
        assert!(step(r#"{"coreTools": ["run_shell_command(gh issue list)"]}"#).is_empty());
        assert!(step(".claude/settings.json").is_empty());
    }

    fn grants(yaml_text: &str) -> Vec<String> {
        shell_grants(&yaml::load(yaml_text).unwrap())
    }

    #[test]
    fn flags_in_prompts_and_quoted_text_grant_nothing() {
        assert!(
            grants("uses: anthropics/claude-code-action@v1\nwith:\n  prompt: Never pass --yolo or --dangerously-skip-permissions.\n  direct_prompt: use bypassPermissions\n  custom_instructions: --full-auto\n")
                .is_empty()
        );
        assert!(grants("run: claude -p \"do not use --yolo\"\n").is_empty());
        assert!(
            grants("run: |\n  # claude --dangerously-skip-permissions\n  claude -p hi\n")
                .is_empty()
        );
        assert!(grants("run: |\n  cat <<EOF > notes.md\n  run gemini --yolo\n  EOF\n").is_empty());
        assert_eq!(
            grants("run: gemini --yolo -p \"fix it\"\n"),
            vec!["--yolo (approves every tool call)"]
        );
        assert_eq!(
            grants("with:\n  claude_args: --dangerously-skip-permissions\n"),
            vec!["claude --dangerously-skip-permissions"]
        );
        assert_eq!(
            grants("run: claude -p x --allowedTools \"Bash\"\n"),
            vec!["Bash allowed without a command filter"]
        );
    }

    #[test]
    fn interpreters_and_build_runners_are_shell_grants() {
        for entry in [
            "npm test:*",
            "npm run docs:*",
            "npx:*",
            "make:*",
            "python:*",
            "/usr/bin/python3 -m pytest:*",
            "node scripts/x.js",
            "./scripts/lint.sh:*",
            "git:*",
            "git config:*",
            "git -c core.pager=less log",
            "gh alias set:*",
            "bash -c:*",
            "sudo:*",
            "cargo test:*",
        ] {
            assert!(runs_any_code(entry).is_some(), "{entry}");
        }
        for entry in [
            "gh pr diff:*",
            "gh pr view:*",
            "gh pr comment:*",
            "git diff:*",
            "git log:*",
            "cat",
            "grep",
            "ls:*",
            "",
        ] {
            assert_eq!(runs_any_code(entry), None, "{entry}");
        }
        assert_eq!(
            grants(
                "with:\n  claude_args: --allowedTools \"Read,Bash(npm test:*),Bash(gh pr diff:*)\" --disallowedTools \"Bash(make:*)\"\n"
            ),
            vec!["Bash(npm test:*) runs any code (npm)"]
        );
        assert_eq!(
            grants(
                "with:\n  settings: '{\"tools\": {\"core\": [\"run_shell_command(cat)\", \"run_shell_command(python3)\"]}}'\n"
            ),
            vec!["run_shell_command(python3) runs any code (python3)"]
        );
        assert_eq!(
            grants("run: copilot -p x --allow-tool 'shell(npm)' --deny-tool 'shell(git push)'\n"),
            vec!["shell(npm) runs any code (npm)"]
        );
    }
}
