//! Untrusted text must reach every output as inert text.
//!
//! Job ids, `uses:` values and config keys come from files a pull request or
//! a cloned repo controls. Whatever they contain, no output may carry a
//! terminal escape, a carriage return, a bidi control, a line that GitHub
//! Actions reads as a workflow command, or Markdown/HTML that renders as a
//! link, an image, a tag or an @mention in a job summary.
//!
//! Two layers are tested: the binary on a hostile fixture (end to end), and
//! the renderers on findings built by hand, which does not depend on what
//! any check reports.

mod common;

use std::sync::LazyLock;

use common::{fixture, run_in};
use heldkeys::finding::{Access, Finding, Lifetime, Rule, Severity};
use heldkeys::report::{self, Format, Mode, Report};
use regex::Regex;

const FORMATS: &[(&str, Format)] = &[
    ("text", Format::Text),
    ("json", Format::Json),
    ("markdown", Format::Markdown),
    ("sarif", Format::Sarif),
];

/// Characters that must never reach any output.
fn forbidden(c: char) -> bool {
    (c.is_control() && c != '\n')
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

/// Checks that hold for every format.
fn assert_inert(label: &str, out: &str) {
    if let Some(c) = out.chars().find(|&c| forbidden(c)) {
        panic!("{label}: output contains {c:?}:\n{out}");
    }
    for line in out.lines() {
        assert!(
            !line.trim_start().starts_with("::"),
            "{label}: a line reads as a workflow command: {line:?}"
        );
        assert!(!line.contains("##["), "{label}: legacy command: {line:?}");
    }
    // JSON and SARIF escape control characters, so check the decoded strings.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(out) {
        each_string(&v, &mut |s| {
            assert!(!s.chars().any(forbidden), "{label}: JSON string {s:?}");
            assert!(!s.trim_start().starts_with("::"), "{label}: {s:?}");
        });
    }
}

fn each_string(v: &serde_json::Value, f: &mut dyn FnMut(&str)) {
    match v {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(a) => a.iter().for_each(|v| each_string(v, f)),
        serde_json::Value::Object(o) => o.values().for_each(|v| each_string(v, f)),
        _ => {}
    }
}

/// Our own links to the rule docs, the only links the report may contain.
static RULE_LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[HK-[A-Z0-9-]+\]\(https://github\.com/hugomn/heldkeys/blob/main/docs/rules/HK-[A-Z0-9-]+\.md\)")
        .unwrap()
});

/// The HTML the Markdown report writes itself.
const OWN_TAGS: &[&str] = &[
    "<details>",
    "</details>",
    "<summary>",
    "</summary>",
    "<sub>",
    "</sub>",
];

/// `line` with every code span replaced by `CODE`. Markdown renders a code
/// span's content literally, so only text outside spans can become markup.
fn outside_code_spans(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let run_at = |i: usize| chars[i..].iter().take_while(|&&c| c == '`').count();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            out.push(chars[i]);
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }
        if chars[i] != '`' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let n = run_at(i);
        let mut j = i + n;
        let mut close = None;
        while j < chars.len() {
            if chars[j] == '`' {
                let m = run_at(j);
                if m == n {
                    close = Some(j);
                    break;
                }
                j += m;
            } else {
                j += 1;
            }
        }
        match close {
            Some(j) => {
                out.push_str("CODE");
                i = j + n;
            }
            None => {
                out.extend(std::iter::repeat_n('`', n));
                i += n;
            }
        }
    }
    out
}

/// Markdown-specific checks: outside code spans and our own rule links,
/// nothing may open a link or image, start an HTML tag, or mention anyone.
fn assert_inert_markdown(label: &str, out: &str) {
    assert!(!out.contains('\u{200b}'), "{label}: zero-width space");
    for line in out.lines() {
        let mut rest = RULE_LINK
            .replace_all(&outside_code_spans(line), "RULE")
            .into_owned();
        for tag in OWN_TAGS {
            rest = rest.replace(tag, "TAG");
        }
        for bad in ["<", "](", "![", "@"] {
            assert!(
                !rest.contains(bad),
                "{label}: {bad:?} outside a code span in {line:?}"
            );
        }
        // An unescaped `[` could still pair with a later `]`.
        let unescaped = |c: char| {
            rest.match_indices(c)
                .any(|(i, _)| i == 0 || !rest[..i].ends_with('\\'))
        };
        assert!(!unescaped('['), "{label}: unescaped [ in {line:?}");
    }
}

/// Strings an attacker would put in a job id or `uses:` value.
const PAYLOADS: &[&str] = &[
    "esc\u{1b}]0;PWNED\u{7}\u{1b}[2J\u{1b}[31mINJECTED\u{9b}31m",
    "cr\r\roverwrite",
    "x\n::error file=src/main.rs,line=1::backdoor\n::set-output name=a::b\n##[error]legacy",
    "::stop-commands::tok",
    "  ::warning::indented",
    "bidi\u{202E}evil\u{2066}x\u{2069}\u{200F}\u{061C}",
    "<a href=https://evil.example>click</a> <img src=x onerror=alert(1)>",
    "[link](https://evil.example) ![img](https://evil.example/pixel.png)",
    "\\[still](https://evil.example) a | b `code` *em* _em_ ~~s~~ #1 @octocat",
    "`` `[x](https://evil.example)` ``",
    "owner/action@v1](https://evil.example)",
];

fn rule() -> Rule {
    Rule {
        check: "workflows",
        id: "HK-WF-001",
        summary: "",
    }
}

fn hostile_findings() -> Vec<Finding> {
    PAYLOADS
        .iter()
        .flat_map(|p| {
            [Severity::High, Severity::Info].map(|severity| {
                Finding::new(
                    rule(),
                    *p,
                    format!(".github/workflows/x.yml:1 jobs.{p}.steps[0]"),
                    severity,
                    Lifetime::LongLived,
                    Access::Write,
                    format!("Pin {p} to a commit."),
                )
                .with_detail(*p)
                .with_fingerprint(Some((*p).to_string()))
            })
        })
        .collect()
}

#[test]
fn renderers_neutralise_hostile_findings() {
    let report = Report::new(Mode::Ci, hostile_findings());
    let own_colours = Regex::new("\u{1b}\\[[0-9;]*m").unwrap();
    for (name, format) in FORMATS {
        for (color, details) in [(false, false), (false, true), (true, false), (true, true)] {
            if (color || details) && *format != Format::Text {
                continue;
            }
            let options = report::TextOptions {
                color,
                details,
                ..report::TextOptions::plain()
            };
            let out = report::render(*format, &report, &options).unwrap();
            if color {
                // Our own colours are the only escapes allowed.
                let plain = own_colours.replace_all(&out, "");
                assert_inert(&format!("{name} (colour)"), &plain);
                continue;
            }
            assert_inert(name, &out);
            if *format == Format::Markdown {
                assert_inert_markdown(name, &out);
            }
        }
    }
}

#[test]
fn fixes_with_an_at_sign_stay_copy_pastable() {
    let f = Finding::new(
        rule(),
        "AI agent action not pinned to a commit SHA",
        ".github/workflows/a.yml:3",
        Severity::Medium,
        Lifetime::Unknown,
        Access::Unknown,
        "Pin the action (uses: owner/action@<sha> # v1.2.3).",
    );
    let out = report::render(
        Format::Markdown,
        &Report::new(Mode::Ci, vec![f]),
        &report::TextOptions::plain(),
    )
    .unwrap();
    assert!(out.contains("`owner/action@<sha>`"), "{out}");
    assert!(!out.contains('\u{200b}'));
}

#[test]
fn hostile_workflow_end_to_end() {
    let project = fixture("hostile/project");
    for (name, _) in FORMATS {
        let out = run_in(
            &fixture("hostile/home"),
            &project,
            &["ci", "--format", name, "--no-color", "--fail-on", "none"],
            &[],
        );
        assert_eq!(out.code, 0, "{name}: {}", out.stderr);
        assert_inert(name, &out.stdout);
        assert_inert(&format!("{name} stderr"), &out.stderr);
        if *name == "markdown" {
            assert_inert_markdown(name, &out.stdout);
        }
    }
    // The hostile job ids did reach the report, so the checks above saw them.
    let json = run_in(
        &fixture("hostile/home"),
        &project,
        &["ci", "--format", "json", "--fail-on", "none"],
        &[],
    );
    assert!(json.stdout.contains("INJECTED"), "{}", json.stdout);
    assert!(json.stdout.contains("evil.example"), "{}", json.stdout);
}

/// An ignore rule's reason and path come from `.heldkeys.toml`, which a
/// pull request can change: they reach every format, in the summary and the
/// "Ignored" section, as inert text, with the URL password scrubbed.
#[test]
fn hostile_config_end_to_end() {
    let config = fixture("config/hostile/config.toml");
    let config = config.to_str().unwrap();
    let project = fixture("hostile/project");
    for (name, _) in FORMATS {
        for details in [false, true] {
            let mut args = vec!["ci", "--format", name, "--no-color", "--fail-on", "none"];
            args.extend(["--config", config]);
            if details {
                args.push("--details");
            }
            let env = [
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_EVENT_NAME", "pull_request"),
            ];
            let out = run_in(&fixture("hostile/home"), &project, &args, &env);
            let label = format!("{name} config details={details}");
            assert_eq!(out.code, 0, "{label}: {}", out.stderr);
            assert_inert(&label, &out.stdout);
            assert_inert(&format!("{label} stderr"), &out.stderr);
            if *name == "markdown" {
                assert_inert_markdown(&label, &out.stdout);
            }
            assert!(!out.stdout.contains("FAKEcfgPASSWORD1103"), "{label}");
            // The hostile reason did reach the report.
            assert!(out.stdout.contains("pwned"), "{label}: {}", out.stdout);
        }
    }
}

/// Workflows built to make the analysis slow, or to flood the report with
/// one huge name. Each must finish well under the bound below, which is
/// generous for debug builds and busy machines.
#[test]
fn oversized_workflow_names_stay_fast_and_clipped() {
    let n = 200_000;
    let job_id = format!("j{}", "x".repeat(n));
    let cases = [
        // `//` after `//` in a `uses:` value: quadratic userinfo scan.
        (
            "slashes.yml",
            format!(
                "on: issue_comment\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: \"openai/codex-action@v1{}\"\n",
                "/".repeat(n)
            ),
        ),
        // `((` before many `<<`: quadratic arithmetic check.
        (
            "shifts.yml",
            format!(
                "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: \"(({}\"\n",
                " x<<a".repeat(80_000)
            ),
        ),
        // A huge job id on an agent step (an explicit key: YAML refuses
        // plain keys over 1024 characters).
        (
            "job-id.yml",
            format!(
                "on: issue_comment\njobs:\n  ? {job_id}\n  : runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n"
            ),
        ),
    ];
    for (name, yaml) in cases {
        let project = tempfile::tempdir().unwrap();
        let dir = project.path().join(".github").join("workflows");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), yaml).unwrap();
        let started = std::time::Instant::now();
        let out = run_in(
            &fixture("empty"),
            project.path(),
            &["ci", "--format", "json", "--fail-on", "none"],
            &[],
        );
        let took = started.elapsed();
        assert_eq!(out.code, 0, "{name}: {}", out.stderr);
        assert!(
            took < std::time::Duration::from_secs(10),
            "{name}: {took:?}"
        );
        let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
        let findings = v["findings"].as_array().unwrap();
        if name != "shifts.yml" {
            assert!(
                findings.iter().any(|f| f["rule"] == "HK-WF-001"),
                "{name}: {findings:?}"
            );
        }
        for f in findings {
            let location = f["location"].as_str().unwrap();
            let detail = f["detail"].as_str().unwrap_or("");
            assert!(location.chars().count() < 400, "{name}: {location}");
            assert!(!location.contains(&"x".repeat(300)), "{name}");
            assert!(!location.contains(&"/".repeat(300)), "{name}");
            assert!(detail.chars().count() < 1_000, "{name}: {detail}");
        }
    }
}
