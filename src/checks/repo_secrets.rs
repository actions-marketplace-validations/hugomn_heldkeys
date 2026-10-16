//! `repo-secrets`: tracked files on the current branch that contain tokens.
//!
//! Only with `ci --repo-secrets`. An agent working in the repository reads its
//! files, so a token committed there is a token the agent holds. This is a
//! fast sanity check of the current tree, not a gitleaks replacement: it does
//! not look at history. Use gitleaks or betterleaks for that.
//!
//! Tracked files come from `git ls-files`, run in `ctx.cwd` with a cleared
//! environment (only PATH and HOME from the context, HOME so that a CI
//! `safe.directory` setting still applies). The repository's own config is
//! attacker-controlled on a fork PR, so hooks, `core.fsmonitor` and every
//! transport are switched off on the command line, and optional index
//! writes and credential prompts are disabled: git only reads.
//!
//! Tracked symlinks that lead out of the repository are not followed (a PR
//! could otherwise make us report `/proc/self/environ` or a runner file as
//! "tracked"); they are reported by `read-errors` instead.

use std::process::{Command, Stdio};

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Finding, Rule};
use crate::fsutil;
use crate::redact;
use crate::rules;

pub struct RepoSecretsCheck;

const ID: &str = "repo-secrets";

const TRACKED_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-REPO-001",
    summary: "Token of a known format in a tracked file",
};

const RULES: &[Rule] = &[TRACKED_TOKEN];

/// Enough to show the problem without flooding a report on a vendored blob.
const MAX_FINDINGS: usize = 200;

/// Bytes inspected to decide a file is binary (git uses the same idea).
const BINARY_SNIFF: usize = 8000;

impl Check for RepoSecretsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "With --repo-secrets: tracked files on the current branch that contain tokens of a known format (no history; use gitleaks for that)."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        if !ctx.repo_secrets {
            return Vec::new();
        }
        let Some(files) = tracked_files(ctx) else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        let mut too_large = 0;
        for relative in files {
            match fsutil::try_read_text_within(
                &ctx.cwd,
                &ctx.cwd.join(&relative),
                fsutil::MAX_FILE_BYTES,
            ) {
                Ok(Some(text)) => findings.extend(scan_text(&relative, &text)),
                // Deleted but still tracked, or a submodule directory.
                Ok(None) | Err(fsutil::Unreadable::NotAFile) => {}
                // Vendored blobs and lockfiles: counted, not listed one by one.
                Err(fsutil::Unreadable::TooLarge { .. }) => too_large += 1,
                Err(reason) => ctx.note_unreadable(&ctx.cwd.join(&relative), reason),
            }
            if findings.len() >= MAX_FINDINGS {
                findings.truncate(MAX_FINDINGS);
                break;
            }
        }
        if too_large > 0 {
            ctx.note_unreadable(
                &ctx.cwd,
                format!(
                    "{too_large} tracked file(s) larger than 1 MiB were not scanned for tokens"
                ),
            );
        }
        findings
    }
}

/// `git ls-files -z` in the working directory, or `None` if it is not a repo
/// or git is missing.
fn tracked_files(ctx: &Context) -> Option<Vec<String>> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(&ctx.cwd)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "ls-files",
            "-z",
        ])
        .env_clear()
        // No index refresh (which would write the index and could run the
        // post-index-change hook), and never ask for credentials.
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    for var in ["PATH", "HOME"] {
        if let Some(value) = ctx.var(var) {
            command.env(var, value);
        }
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        output
            .stdout
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect(),
    )
}

/// Tokens in one tracked file, as `path:line` findings.
fn scan_text(relative: &str, text: &str) -> Vec<Finding> {
    if text.bytes().take(BINARY_SNIFF).any(|b| b == 0) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for m in rules::find_tokens(line) {
            let token = &line[m.start..m.end];
            if m.rule.id == "url-with-password" && is_example_url(token) {
                continue;
            }
            findings.push(
                Finding::new(
                    TRACKED_TOKEN,
                    m.rule.title,
                    format!("{}:{}", display::label(relative), n + 1),
                    m.rule.severity,
                    m.rule.lifetime,
                    m.rule.access,
                    "Revoke and rotate it, then remove it from the file; git history still has it, so scan history with gitleaks.",
                )
                .with_fingerprint(redact::fingerprint(token))
                .with_detail("tracked on the current branch: anyone who can read the repo, and any agent working in it, can use it"),
            );
        }
    }
    findings
}

/// `scheme://user:password@host` with a placeholder password, as found in
/// READMEs and sample configs.
fn is_example_url(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let userinfo = rest.split('@').next().unwrap_or("");
    let password = userinfo.split_once(':').map(|(_, p)| p).unwrap_or("");
    let lower = password.to_ascii_lowercase();
    rules::looks_like_placeholder(password)
        || ["password", "passwd", "secret", "pass"].contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, write};
    use crate::finding::Severity;
    use std::path::Path;

    /// A temporary repository with `files` staged (no commit needed: ls-files
    /// reads the index). git runs with an empty environment and HOME in the
    /// temp dir, so no user config is involved.
    fn repo(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, contents).unwrap();
        }
        git(dir.path(), &["init", "-q"]);
        git(dir.path(), &["add", "-A"]);
        dir
    }

    /// Runs git in `dir` with an empty environment and HOME in the temp dir,
    /// so no user config is involved.
    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("HOME", dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    fn scan(dir: &Path, enabled: bool) -> Vec<Finding> {
        let mut ctx = ctx_with_env(dir, &[]);
        ctx.repo_secrets = enabled;
        RepoSecretsCheck.run(&ctx)
    }

    #[test]
    fn finds_tokens_in_tracked_files_only() {
        let dir = repo(&[
            (
                "config/app.py",
                b"DEBUG = True\nGITHUB = \"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000401\"\n",
            ),
            (
                "README.md",
                b"Connect with postgres://user:password@localhost/db\n",
            ),
            (
                "logo.png",
                b"\x89PNG\0\0ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000402",
            ),
        ]);
        // Created after `git add`: untracked, so not scanned.
        write(dir.path(), "notes.txt", "AKIAIOSFODNN7EXAMPLE");
        let f = scan(dir.path(), true);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].location, "config/app.py:2");
        assert_eq!(f[0].fingerprint.as_deref(), Some("ghp_…401"));
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].rule, "HK-REPO-001");
    }

    #[cfg(unix)]
    #[test]
    fn tracked_symlinks_out_of_the_repo_are_not_read() {
        let outside = tempfile::tempdir().unwrap();
        write(
            outside.path(),
            "secret.txt",
            "token = ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000777\n",
        );
        let dir = repo(&[("a.txt", b"hello\n")]);
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            dir.path().join("leak.txt"),
        )
        .unwrap();
        git(dir.path(), &["add", "-A"]);
        let mut ctx = ctx_with_env(dir.path(), &[]);
        ctx.repo_secrets = true;
        assert!(RepoSecretsCheck.run(&ctx).is_empty());
        let problems = ctx.take_unreadable();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].0.ends_with("leak.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn repository_hooks_and_fsmonitor_never_run() {
        let dir = repo(&[("a.txt", b"hello\n")]);
        let marks = tempfile::tempdir().unwrap();
        let script = |name: &str| {
            let path = marks.path().join(format!("{name}.sh"));
            let mark = marks.path().join(format!("MARK-{name}"));
            std::fs::write(&path, format!("#!/bin/sh\ntouch '{}'\n", mark.display())).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let hooks = marks.path().join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        for hook in [
            "post-index-change",
            "reference-transaction",
            "post-checkout",
        ] {
            std::fs::copy(script(hook), hooks.join(hook)).unwrap();
        }
        let fsmonitor = script("fsmonitor");
        for (key, value) in [
            ("core.hooksPath", hooks.display().to_string()),
            ("core.fsmonitor", fsmonitor.display().to_string()),
            ("core.splitIndex", "true".to_string()),
            ("core.untrackedCache", "true".to_string()),
        ] {
            git(dir.path(), &["config", key, &value]);
        }
        let mut ctx = ctx_with_env(dir.path(), &[("PATH", "/usr/bin:/bin")]);
        ctx.repo_secrets = true;
        RepoSecretsCheck.run(&ctx);
        let marks_left: Vec<_> = fsutil::list_dir(marks.path())
            .into_iter()
            .filter(|p| fsutil::file_name(p).starts_with("MARK-"))
            .collect();
        assert!(marks_left.is_empty(), "{marks_left:?}");
    }

    #[test]
    fn off_unless_requested() {
        let dir = repo(&[("a.txt", b"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000403")]);
        assert!(scan(dir.path(), false).is_empty());
    }

    #[test]
    fn not_a_repository() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.txt",
            "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000404",
        );
        assert!(scan(dir.path(), true).is_empty());
    }

    #[test]
    fn example_urls() {
        assert!(is_example_url("postgres://user:password@localhost/db"));
        assert!(is_example_url("redis://:${REDIS_PASSWORD}@cache:6379"));
        assert!(!is_example_url(
            "postgres://app:FAKErT1vLx0pW@db.internal/app"
        ));
    }
}
