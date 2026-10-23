//! `runtime-versions`: PHP and Node.js builds without the fixes published
//! in the same week, reported only (they are not credentials).
//!
//! PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 (21 October 2026) fix two
//! unauthenticated remote code execution bugs, CVE-2026-109618 and
//! CVE-2026-109619 ("php2shell"); CISA's alert says to patch immediately
//! and to take 8.1 and older, which get no fix, offline. Node.js 26.12.1,
//! 24.22.1 and 22.23.4 (21 October 2026) fix CVE-2026-111497, an
//! out-of-bounds write in the Brotli decoder that permits remote code
//! execution, with nine other CVEs; the other lines are end of life.
//!
//! Versions come from `php --version` and `node --version` on `PATH`, from
//! the directories version managers and Homebrew keep installs in, and
//! from what the project pins: `FROM php:`/`node:` lines in Dockerfiles,
//! `image:` lines in compose files, `.nvmrc`, `.node-version`,
//! `.php-version` and `.tool-versions`.

use std::path::Path;

use crate::checks::Check;
use crate::checks::incident as inc;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;

pub struct RuntimesCheck;

const ID: &str = "runtime-versions";

pub const PHP: Rule = Rule {
    check: ID,
    id: "HK-RT-001",
    summary: "PHP without the php2shell fixes (8.5.12, 8.4.27, 8.3.36, 8.2.35), or end of life",
};

pub const NODE: Rule = Rule {
    check: ID,
    id: "HK-RT-002",
    summary: "Node.js without the October 2026 security release (26.12.1, 24.22.1, 22.23.4), or end of life",
};

const RULES: &[Rule] = &[PHP, NODE];

/// Where version managers and Homebrew keep installs: the last segment of
/// each match names the version.
const HOME_PHP: &[&[&str]] = &[
    &[".phpenv", "versions", "*"],
    &[".asdf", "installs", "php", "*"],
    &[".phpbrew", "php", "*"],
];
const ROOT_PHP: &[&[&str]] = &[
    &["opt", "homebrew", "Cellar", "php*", "*"],
    &["usr", "local", "Cellar", "php*", "*"],
];
const HOME_NODE: &[&[&str]] = &[
    &[".nvm", "versions", "node", "*"],
    &[".volta", "tools", "image", "node", "*"],
    &[".local", "share", "fnm", "node-versions", "*"],
    &[".fnm", "node-versions", "*"],
    &[".asdf", "installs", "nodejs", "*"],
];
const ROOT_NODE: &[&[&str]] = &[
    &["opt", "homebrew", "Cellar", "node*", "*"],
    &["usr", "local", "Cellar", "node*", "*"],
    &["usr", "local", "n", "versions", "node", "*"],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Runtime {
    Php,
    Node,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Below the fixed release of its line.
    Unpatched(&'static str),
    /// A line that gets no fix.
    EndOfLife,
}

fn php_state(v: (u32, u32, u32)) -> Option<State> {
    match v {
        (8, 5, p) if p < 12 => Some(State::Unpatched("8.5.12")),
        (8, 4, p) if p < 27 => Some(State::Unpatched("8.4.27")),
        (8, 3, p) if p < 36 => Some(State::Unpatched("8.3.36")),
        (8, 2, p) if p < 35 => Some(State::Unpatched("8.2.35")),
        (major, minor, _) if major < 8 || (major == 8 && minor < 2) => Some(State::EndOfLife),
        _ => None,
    }
}

fn node_state(v: (u32, u32, u32)) -> Option<State> {
    match v {
        (22, m, p) if (m, p) < (23, 4) => Some(State::Unpatched("22.23.4")),
        (24, m, p) if (m, p) < (22, 1) => Some(State::Unpatched("24.22.1")),
        (26, m, p) if (m, p) < (12, 1) => Some(State::Unpatched("26.12.1")),
        (major, _, _) => node_major_eol(major).then_some(State::EndOfLife),
    }
}

/// Lines that are end of life as of October 2026: 20 (April 2026), 21, 23,
/// 25 (June 2026) and everything older.
fn node_major_eol(major: u32) -> bool {
    major < 22 || matches!(major, 23 | 25)
}

impl Check for RuntimesCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "PHP and Node.js versions without the 21 Oct 2026 security fixes, or end of life: php and node on PATH, installs kept by version managers and Homebrew, and the versions the project pins in Dockerfiles, compose files, .nvmrc, .node-version, .php-version and .tool-versions."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (runtime, program) in [(Runtime::Php, "php"), (Runtime::Node, "node")] {
            if let Some(out) = inc::command_output(ctx, program, &["--version"])
                && let Some(v) = inc::parse_version(out.lines().next().unwrap_or_default())
            {
                let shown = inc::which(ctx, program)
                    .first()
                    .map(|p| ctx.display_path(p))
                    .unwrap_or_else(|| program.to_string());
                findings.extend(finding(runtime, v, format!("{program} on PATH ({shown})")));
            }
            let (home, root) = match runtime {
                Runtime::Php => (HOME_PHP, ROOT_PHP),
                Runtime::Node => (HOME_NODE, ROOT_NODE),
            };
            let mut installs = Vec::new();
            for pattern in home {
                installs.extend(inc::expand(&ctx.home, pattern));
            }
            for pattern in root {
                installs.extend(inc::expand(&ctx.root, pattern));
            }
            for dir in inc::dedup_paths(installs) {
                if let Some(v) = inc::parse_version(&fsutil::file_name(&dir)) {
                    findings.extend(finding(runtime, v, ctx.display_path(&dir)));
                }
            }
        }
        findings.extend(project_pins(ctx));
        findings
    }
}

fn finding(runtime: Runtime, v: (u32, u32, u32), location: String) -> Option<Finding> {
    let state = match runtime {
        Runtime::Php => php_state(v),
        Runtime::Node => node_state(v),
    }?;
    let version = format!("{}.{}.{}", v.0, v.1, v.2);
    Some(describe(runtime, &version, state, location))
}

fn describe(runtime: Runtime, version: &str, state: State, location: String) -> Finding {
    let (rule, name) = match runtime {
        Runtime::Php => (PHP, "PHP"),
        Runtime::Node => (NODE, "Node.js"),
    };
    let (title, severity, fix, detail) = match (runtime, state) {
        (Runtime::Php, State::Unpatched(fixed)) => (
            format!("{name} {version} without the php2shell fix"),
            Severity::Low,
            format!("Update to PHP {fixed} or later; CISA: patch immediately, internet-facing systems first, and take systems offline that cannot be updated."),
            "CVE-2026-109618 and CVE-2026-109619, unauthenticated remote code execution in PHP serving web requests",
        ),
        (Runtime::Php, State::EndOfLife) => (
            format!("{name} {version} is end of life and unpatched"),
            Severity::Medium,
            "PHP 8.1 and older get no fix: take PHP-based services offline until they run 8.2.35 or later.".to_string(),
            "CISA: unsupported versions should be taken offline until patched or updated",
        ),
        (Runtime::Node, State::Unpatched(fixed)) => (
            format!("{name} {version} without the Oct 2026 fix"),
            Severity::Low,
            format!("Update to Node.js {fixed} or later."),
            "CVE-2026-111497 (Brotli decoder out-of-bounds write, remote code execution) and nine more",
        ),
        (Runtime::Node, State::EndOfLife) => (
            format!("{name} {version} is end of life and unpatched"),
            Severity::Low,
            "This Node.js line gets no security fixes: move to 22.23.4, 24.22.1 or 26.12.1 or later.".to_string(),
            "end-of-life lines are always affected by a security release",
        ),
    };
    Finding::new(
        rule,
        title,
        location,
        severity,
        Lifetime::Unknown,
        Access::Unknown,
        fix,
    )
    .with_detail(detail)
}

/// Versions the project pins in its own files.
fn project_pins(ctx: &Context) -> Vec<Finding> {
    let tree = inc::project_tree(ctx, &is_pin_file);
    let mut findings = Vec::new();
    for path in tree.files {
        let Some(text) = ctx.read_project_file(&path) else {
            continue;
        };
        let shown = ctx.display_path(&path);
        for (line, runtime, version) in pinned_versions(&fsutil::file_name(&path), &text) {
            let location = match line {
                Some(n) => format!("{shown}:{n}"),
                None => shown.clone(),
            };
            findings.extend(pin_finding(runtime, &version, location));
        }
    }
    findings
}

fn is_pin_file(name: &str) -> bool {
    name.starts_with("Dockerfile")
        || name.ends_with(".Dockerfile")
        || name.ends_with(".dockerfile")
        || ((name.starts_with("docker-compose") || name.starts_with("compose"))
            && (name.ends_with(".yml") || name.ends_with(".yaml")))
        || matches!(
            name,
            ".nvmrc" | ".node-version" | ".php-version" | ".tool-versions"
        )
}

/// `(line, runtime, version text)` for every pin in `text`. The version
/// text may be a full `X.Y.Z` or just a major (`22`, `22-slim`).
fn pinned_versions(name: &str, text: &str) -> Vec<(Option<usize>, Runtime, String)> {
    let mut found = Vec::new();
    match name {
        ".nvmrc" | ".node-version" => {
            if let Some(v) = text.lines().next().map(str::trim).filter(|v| !v.is_empty()) {
                found.push((None, Runtime::Node, v.trim_start_matches('v').to_string()));
            }
        }
        ".php-version" => {
            if let Some(v) = text.lines().next().map(str::trim).filter(|v| !v.is_empty()) {
                found.push((None, Runtime::Php, v.to_string()));
            }
        }
        ".tool-versions" => {
            for (i, line) in text.lines().enumerate() {
                let mut parts = line.split_whitespace();
                match (parts.next(), parts.next()) {
                    (Some("php"), Some(v)) => {
                        found.push((Some(i + 1), Runtime::Php, v.to_string()))
                    }
                    (Some("nodejs"), Some(v)) => {
                        found.push((Some(i + 1), Runtime::Node, v.to_string()))
                    }
                    _ => {}
                }
            }
        }
        _ => {
            let re = regex::Regex::new(
                r"(?i)^\s*(?:FROM|image:)\s+(?:[\w.-]+(?::\d+)?/)*(?:library/)?(php|node):([0-9][\w.-]*)",
            )
            .expect("valid regex");
            for (i, line) in text.lines().enumerate() {
                if let Some(c) = re.captures(line) {
                    let runtime = if c[1].eq_ignore_ascii_case("php") {
                        Runtime::Php
                    } else {
                        Runtime::Node
                    };
                    found.push((Some(i + 1), runtime, c[2].to_string()));
                }
            }
        }
    }
    found
}

/// A pinned full version is judged like an installed one; a major alone
/// only when that whole line is end of life.
fn pin_finding(runtime: Runtime, version: &str, location: String) -> Option<Finding> {
    if let Some(v) = inc::parse_version(version) {
        return finding(runtime, v, location);
    }
    let major: u32 = version
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    let eol = match runtime {
        Runtime::Php => major < 8,
        Runtime::Node => node_major_eol(major),
    };
    eol.then(|| describe(runtime, &major.to_string(), State::EndOfLife, location))
}

#[allow(dead_code)]
fn _assert_path(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::incident::tests::project_ctx;
    use crate::checks::testutil::write;

    #[test]
    fn php_and_node_states() {
        assert_eq!(php_state((8, 4, 26)), Some(State::Unpatched("8.4.27")));
        assert_eq!(php_state((8, 4, 27)), None);
        assert_eq!(php_state((8, 5, 12)), None);
        assert_eq!(php_state((8, 2, 34)), Some(State::Unpatched("8.2.35")));
        assert_eq!(php_state((8, 1, 31)), Some(State::EndOfLife));
        assert_eq!(php_state((7, 4, 33)), Some(State::EndOfLife));
        assert_eq!(php_state((8, 6, 0)), None, "a newer line is not judged");
        assert_eq!(node_state((22, 23, 3)), Some(State::Unpatched("22.23.4")));
        assert_eq!(node_state((22, 23, 4)), None);
        assert_eq!(node_state((22, 24, 0)), None);
        assert_eq!(node_state((24, 21, 9)), Some(State::Unpatched("24.22.1")));
        assert_eq!(node_state((26, 12, 0)), Some(State::Unpatched("26.12.1")));
        assert_eq!(node_state((26, 12, 1)), None);
        assert_eq!(node_state((20, 19, 0)), Some(State::EndOfLife));
        assert_eq!(node_state((25, 9, 0)), Some(State::EndOfLife));
        assert_eq!(node_state((27, 0, 0)), None);
    }

    #[test]
    fn pins_are_read_from_project_files() {
        assert_eq!(
            pinned_versions(
                "Dockerfile",
                "FROM node:22.23.3-slim AS build\nFROM docker.io/library/php:8.3.35-fpm\nFROM ghcr.io/x/php:8.1.0\nFROM python:3.12\n"
            ),
            [
                (Some(1), Runtime::Node, "22.23.3-slim".to_string()),
                (Some(2), Runtime::Php, "8.3.35-fpm".to_string()),
                (Some(3), Runtime::Php, "8.1.0".to_string()),
            ]
        );
        assert_eq!(
            pinned_versions(
                "docker-compose.yml",
                "services:\n  web:\n    image: php:8.4.26-apache\n"
            ),
            [(Some(3), Runtime::Php, "8.4.26-apache".to_string())]
        );
        assert_eq!(
            pinned_versions(".nvmrc", "v22.23.3\n"),
            [(None, Runtime::Node, "22.23.3".to_string())]
        );
        assert_eq!(
            pinned_versions(".tool-versions", "nodejs 20.19.0\nphp 8.2.34\nruby 3.3.0\n"),
            [
                (Some(1), Runtime::Node, "20.19.0".to_string()),
                (Some(2), Runtime::Php, "8.2.34".to_string()),
            ]
        );
        assert!(pin_finding(Runtime::Node, "22-slim", "x".into()).is_none());
        assert_eq!(
            pin_finding(Runtime::Node, "20-alpine", "x".into())
                .unwrap()
                .title,
            "Node.js 20 is end of life and unpatched"
        );
        assert!(pin_finding(Runtime::Node, "lts/*", "x".into()).is_none());
    }

    #[test]
    fn installs_and_pins_become_findings() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".nvm/versions/node/v22.23.3")).unwrap();
        std::fs::create_dir_all(dir.path().join(".nvm/versions/node/v24.22.1")).unwrap();
        std::fs::create_dir_all(dir.path().join("opt/homebrew/Cellar/php@8.3/8.3.35")).unwrap();
        write(dir.path(), "project/Dockerfile", "FROM php:8.1.2-cli\n");
        write(dir.path(), "project/.nvmrc", "22\n");
        let ctx = project_ctx(dir.path(), &[]);
        let findings = RuntimesCheck.run(&ctx);
        let rows: Vec<(&str, &str, Severity)> = findings
            .iter()
            .map(|f| (f.title.as_str(), f.location.as_str(), f.severity))
            .collect();
        assert_eq!(
            rows,
            [
                (
                    "PHP 8.3.35 without the php2shell fix",
                    "~/opt/homebrew/Cellar/php@8.3/8.3.35",
                    Severity::Low
                ),
                (
                    "Node.js 22.23.3 without the Oct 2026 fix",
                    "~/.nvm/versions/node/v22.23.3",
                    Severity::Low
                ),
                (
                    "PHP 8.1.2 is end of life and unpatched",
                    "~/project/Dockerfile:1",
                    Severity::Medium
                ),
            ],
            "{findings:#?}"
        );
        assert!(findings.iter().all(|f| f.title.chars().count() <= 44));
    }
}
