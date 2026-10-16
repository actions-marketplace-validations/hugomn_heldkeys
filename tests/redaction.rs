//! The redaction guarantee: no fixture secret ever appears in full in any
//! output, in any format, on stdout or stderr.
//!
//! Secrets come from two sources, so the list cannot silently rot:
//! the explicit lists in `common`, and every FAKE-containing token found by
//! reading the fixture files themselves.

mod common;

use std::path::{Path, PathBuf};

use common::{
    ENV_SECRETS, FAKE_SSH_KEY, FAKE_SSH_KEY_BODY, FIXTURE_SECRETS, copy_dir, fixture, run_in,
};

/// Any 10-character slice of a secret counts as a leak. A fingerprint shows
/// at most 4 + 3 characters, so a legitimate output never contains 10 in a row.
const WINDOW: usize = 10;

const FORMATS: &[&str] = &["text", "json", "markdown", "sarif"];

fn all_secrets() -> Vec<String> {
    let mut secrets: Vec<String> = FIXTURE_SECRETS.iter().map(|s| s.to_string()).collect();
    secrets.extend(ENV_SECRETS.iter().map(|(_, v)| v.to_string()));
    secrets.extend(FAKE_SSH_KEY_BODY.iter().map(|s| s.to_string()));
    secrets.extend(tokens_in_fixtures());
    secrets.sort();
    secrets.dedup();
    secrets
}

/// Every token containing "FAKE" in any fixture file.
fn tokens_in_fixtures() -> Vec<String> {
    let mut files = Vec::new();
    collect_files(&fixture(""), &mut files);
    let mut tokens = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        for token in text.split(|c: char| c.is_whitespace() || "\"'=,:@{}[]".contains(c)) {
            if token.contains("FAKE") && token.len() >= 12 {
                tokens.push(token.to_string());
            }
        }
    }
    tokens
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn windows(secret: &str) -> Vec<String> {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= WINDOW {
        return vec![secret.to_string()];
    }
    chars.windows(WINDOW).map(|w| w.iter().collect()).collect()
}

fn assert_no_leak(label: &str, output: &str, secrets: &[String]) {
    for secret in secrets {
        for window in windows(secret) {
            assert!(
                !output.contains(&window),
                "{label}: output contains {window:?} from a fixture secret"
            );
        }
    }
}

/// Every home fixture, each with the env secrets set and the project as cwd.
fn cases(tmp: &Path) -> Vec<(String, PathBuf, PathBuf)> {
    let mut cases: Vec<(String, PathBuf, PathBuf)> = ["empty", "full", "aws-sso", "gh-keyring"]
        .iter()
        .map(|c| (c.to_string(), fixture(c), fixture("project")))
        .collect();
    // MCP configs of every client, with project-level configs in the cwd.
    cases.push((
        "mcp".to_string(),
        fixture("mcp/home"),
        fixture("mcp/project"),
    ));
    // CLI logins in every format (JSON, TOML, YAML, INI, plain, .env), AWS
    // session caches, and editor history copies of .env files.
    cases.push((
        "logins".to_string(),
        fixture("logins/home"),
        fixture("logins/project"),
    ));
    // The full fixture plus an SSH key, in a temporary copy.
    let ssh_home = tmp.join("full-with-ssh");
    copy_dir(&fixture("full"), &ssh_home);
    std::fs::create_dir_all(ssh_home.join(".ssh")).unwrap();
    std::fs::write(ssh_home.join(".ssh/id_ed25519"), FAKE_SSH_KEY).unwrap();
    cases.push(("full-with-ssh".to_string(), ssh_home, fixture("project")));
    cases
}

#[test]
fn no_secret_reaches_any_output() {
    let secrets = all_secrets();
    assert!(
        secrets.len() > 30,
        "secret list looks too small: {}",
        secrets.len()
    );
    let tmp = tempfile::tempdir().unwrap();
    let mut checked = 0;
    let cases = cases(tmp.path());
    let case_count = cases.len();
    for (name, home, cwd) in cases {
        for mode in ["scan", "ci"] {
            for format in FORMATS {
                let out = run_in(
                    &home,
                    &cwd,
                    &[mode, "--format", format, "--no-color"],
                    ENV_SECRETS,
                );
                let label = format!("{name} {mode} {format}");
                assert_no_leak(&label, &out.stdout, &secrets);
                assert_no_leak(&label, &out.stderr, &secrets);
                // Every format must render, or its output would go unchecked.
                assert_ne!(out.code, 2, "{label}: {}", out.stderr);
                checked += 1;
            }
        }
        // The --details view prints every finding.
        for mode in ["scan", "ci"] {
            let out = run_in(&home, &cwd, &[mode, "--details", "--no-color"], ENV_SECRETS);
            assert_no_leak(&format!("{name} {mode} --details"), &out.stdout, &secrets);
        }
        // --output file, too.
        let file = tmp.path().join(format!("{name}.json"));
        run_in(
            &home,
            &cwd,
            &["--format", "json", "--output", file.to_str().unwrap()],
            ENV_SECRETS,
        );
        assert_no_leak(&name, &std::fs::read_to_string(&file).unwrap(), &secrets);
    }
    assert_eq!(checked, case_count * 2 * FORMATS.len());
}

/// `ci` inside a (simulated) GitHub Actions job, where `ci-runtime` reads the
/// environment and `workflows` reads a project's workflow files.
#[test]
fn ci_runtime_output_has_no_secrets() {
    let secrets = all_secrets();
    let mut env: Vec<(&str, &str)> = ENV_SECRETS.to_vec();
    env.extend([
        ("GITHUB_ACTIONS", "true"),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
        (
            "GITHUB_WORKFLOW_REF",
            "octo/repo/.github/workflows/review.yml@refs/heads/main",
        ),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.invalid/t"),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "FAKEoidcREQUESTtoken0601"),
        ("ACTIONS_RUNTIME_TOKEN", "FAKEruntimeTOKEN0602"),
        ("GH_TOKEN", "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000603"),
    ]);
    let extra = [
        "FAKEoidcREQUESTtoken0601",
        "FAKEruntimeTOKEN0602",
        "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000603",
    ];
    let secrets: Vec<String> = secrets
        .into_iter()
        .chain(extra.iter().map(|s| s.to_string()))
        .collect();
    let cwd = fixture("workflows/secrets");
    for format in FORMATS {
        let out = run_in(&fixture("empty"), &cwd, &["ci", "--format", format], &env);
        assert_eq!(out.code, 1, "{format}: {}", out.stderr);
        assert!(
            out.stdout.contains("HK-CI-") || *format == "text",
            "{format}"
        );
        assert_no_leak(format, &out.stdout, &secrets);
        assert_no_leak(format, &out.stderr, &secrets);
    }
}

#[test]
fn preflight_never_leaks() {
    let secrets = all_secrets();
    let tmp = tempfile::tempdir().unwrap();
    for (name, home, cwd) in cases(tmp.path()) {
        for format in ["text", "json"] {
            let out = run_in(
                &home,
                &cwd,
                &["preflight", "--format", format, "--fail-on", "low"],
                ENV_SECRETS,
            );
            let label = format!("{name} preflight {format}");
            assert_ne!(out.code, 2, "{label}: {}", out.stderr);
            assert_no_leak(&label, &out.stdout, &secrets);
            assert_no_leak(&label, &out.stderr, &secrets);
        }
    }
}

/// Findings left out by an ignore rule or a baseline are still listed (the
/// "Ignored" section, JSON `suppressed`, SARIF results with suppressions):
/// they must be as redacted as the rest.
#[test]
fn ignored_findings_never_leak() {
    let secrets = all_secrets();
    let tmp = tempfile::tempdir().unwrap();
    // One ignore rule per declared rule id: a single catch-all is refused.
    let mut text = String::new();
    for check in heldkeys::checks::all_checks() {
        for rule in check.rules() {
            text.push_str(&format!(
                "[[ignore]]\nrule = \"{}\"\nreason = \"redaction test: everything is ignored\"\n",
                rule.id
            ));
        }
    }
    let config = tmp.path().join("ignore-all.toml");
    std::fs::write(&config, text).unwrap();
    let config = config.to_str().unwrap();
    for (name, home, cwd) in cases(tmp.path()) {
        let baseline = tmp.path().join(format!("{name}-baseline.json"));
        let baseline = baseline.to_str().unwrap();
        for mode in ["scan", "ci"] {
            let written = run_in(
                &home,
                &cwd,
                &[mode, "--write-baseline", baseline, "--quiet"],
                ENV_SECRETS,
            );
            assert_ne!(written.code, 2, "{name} {mode}: {}", written.stderr);
            assert_no_leak(
                &format!("{name} {mode} baseline file"),
                &std::fs::read_to_string(baseline).unwrap(),
                &secrets,
            );
            for format in FORMATS {
                for extra in [["--config", config], ["--baseline", baseline]] {
                    let mut args = vec![mode, "--format", format, "--no-color", "--details"];
                    args.extend(extra);
                    let out = run_in(&home, &cwd, &args, ENV_SECRETS);
                    let label = format!("{name} {mode} {format} {}", extra[0]);
                    assert_eq!(
                        out.code, 0,
                        "{label}: everything is suppressed: {}",
                        out.stderr
                    );
                    assert_no_leak(&label, &out.stdout, &secrets);
                    assert_no_leak(&label, &out.stderr, &secrets);
                }
            }
        }
    }
}

#[test]
fn fingerprints_have_the_safe_shape() {
    let tmp = tempfile::tempdir().unwrap();
    for (name, home, cwd) in cases(tmp.path()) {
        let out = run_in(&home, &cwd, &["--format", "json"], ENV_SECRETS);
        let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
        for f in v["findings"].as_array().unwrap() {
            if let Some(fp) = f["fingerprint"].as_str() {
                let (head, tail) = fp.split_once('…').unwrap_or_else(|| panic!("{name}: {fp}"));
                assert!(
                    head.chars().count() <= 4 && tail.chars().count() <= 3,
                    "{name}: {fp}"
                );
            }
        }
    }
}

#[test]
fn explicit_secret_list_matches_the_fixtures() {
    // Keeps FIXTURE_SECRETS honest: each entry must really be in a fixture.
    let mut files = Vec::new();
    collect_files(&fixture(""), &mut files);
    let all: String = files
        .iter()
        .map(|f| std::fs::read_to_string(f).unwrap_or_default())
        .collect();
    for secret in FIXTURE_SECRETS {
        assert!(all.contains(secret), "{secret} is not in any fixture");
    }
}

/// Secrets inside text the checks print: URL passwords in a section name, a
/// kubeconfig user name, an .npmrc key and a bare .env line, and a token in
/// a `git fetch` command quoted by a workflow finding. `Report::new` scrubs
/// what a check lets through.
#[test]
fn secrets_inside_names_and_urls_never_reach_output() {
    let secrets = all_secrets();
    let hostile: Vec<&String> = secrets.iter().filter(|s| s.contains("070")).collect();
    assert!(hostile.len() >= 8, "hostile fixture secrets: {hostile:?}");
    let home = fixture("hostile/home");
    let cwd = fixture("hostile/project");
    for mode in ["scan", "ci"] {
        for format in FORMATS {
            let out = run_in(
                &home,
                &cwd,
                &[mode, "--format", format, "--no-color", "--fail-on", "none"],
                &[],
            );
            let label = format!("hostile {mode} {format}");
            assert_eq!(out.code, 0, "{label}: {}", out.stderr);
            assert_no_leak(&label, &out.stdout, &secrets);
            assert_no_leak(&label, &out.stderr, &secrets);
        }
    }
}

/// The same guarantee without any check in between: findings built by hand
/// with secrets in every text field, rendered in every format.
#[test]
fn report_scrubs_secrets_in_every_field() {
    use heldkeys::finding::{Access, Finding, Lifetime, Rule, Severity};
    use heldkeys::report::{self, Format, Mode, Report};

    let secrets: Vec<String> = [
        "FAKEurlPASSWORD0801",
        "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000802",
        "FAKEbarePASSWORD0803",
        "FAKEnpmPASSWORD0804",
        concat!("xoxb-", "FAKE080500"),
        "FAKEqueryVALUE0806",
        "FAKEcutPASSWORDthatGOESon0807",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let rule = Rule {
        check: "test",
        id: "HK-TEST-001",
        summary: "",
    };
    let texts = [
        "~/.gitconfig [credential \"https://alice:FAKEurlPASSWORD0801@github.example.com\"]",
        "env: ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000802",
        "run: git fetch x-access-token:FAKEbarePASSWORD0803@github.com/o/r",
        "~/.npmrc (//eve:FAKEnpmPASSWORD0804@registry.example.com/)",
        concat!("token xoxb-", "FAKE080500 in a key"),
        "https://api.example.com/v1?api_key=FAKEqueryVALUE0806&x=1",
        "run: git fetch https://x-access-token:FAKEcutPASSWORDthatGOESon0807",
    ];
    let findings: Vec<Finding> = texts
        .iter()
        .map(|t| {
            Finding::new(
                rule,
                *t,
                *t,
                Severity::High,
                Lifetime::LongLived,
                Access::Write,
                *t,
            )
            .with_detail(*t)
        })
        .collect();
    let report = Report::new(Mode::Scan, findings);
    for format in [Format::Text, Format::Json, Format::Markdown, Format::Sarif] {
        for details in [false, true] {
            let options = report::TextOptions {
                details,
                ..report::TextOptions::plain()
            };
            let out = report::render(format, &report, &options).unwrap();
            assert_no_leak(&format!("{format:?}"), &out, &secrets);
        }
    }
    // The 16-character Slack token is too short for a fingerprint.
    assert!(report.findings[4].title.contains("token *** in a key"));
}

/// Secrets in the `scrub` fixture and the `.git/config` the test adds.
const SCRUB_SECRETS: &[&str] = &[
    "pa/ssFAKEslash0901",
    "FAKEpct0902",
    "FAKEdigest0903",
    "FAKEbearer0904abcdef",
    "FAKEnpm0905",
    "pa/ssFAKEnpm0905",
    "FAKEnpmTOKENvalue0906",
    "pa/ssFAKEcred0907",
    "pa/ssFAKEurl0908",
    "ab/cdFAKEremote0909",
    "FAKEbare0910xyz",
    "FAKEquery0911",
    "FAKEfrag0912",
    "FAKEcode0913",
    "FAKEflag0914",
    "FAKEflag0915",
    "FAKEflag0916",
    "FAKEflag0917",
    "FAKE%2Fpct0918",
    "FAKE/pct0918",
];

/// URL passwords with an unencoded `/` or an encoded colon, a host dressed
/// up as an image digest, Authorization and Bearer values, secret fragment
/// and query parameters, and secret flags: in workflow job ids, `.npmrc`
/// keys, git config sections and remote URLs, through every format.
#[test]
fn scrubber_shapes_never_reach_output() {
    let secrets: Vec<String> = SCRUB_SECRETS.iter().map(|s| s.to_string()).collect();
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().join("project");
    copy_dir(&fixture("scrub/project"), &cwd);
    std::fs::create_dir_all(cwd.join(".git")).unwrap();
    std::fs::write(
        cwd.join(".git/config"),
        "[remote \"origin\"]\n\turl = https://u:ab/cdFAKEremote0909@github.com/o/r.git\n[remote \"up\"]\n\turl = https://u:FAKE%2Fpct0918@github.com/o/r.git\n",
    )
    .unwrap();
    let home = fixture("scrub/home");
    for mode in ["scan", "ci"] {
        for format in FORMATS {
            let out = run_in(
                &home,
                &cwd,
                &[mode, "--format", format, "--fail-on", "none"],
                &[],
            );
            let label = format!("scrub {mode} {format}");
            assert_eq!(out.code, 0, "{label}: {}", out.stderr);
            assert_no_leak(&label, &out.stdout, &secrets);
            assert_no_leak(&label, &out.stderr, &secrets);
        }
    }
}

/// The same shapes in every text field of hand-made findings.
#[test]
fn report_scrubs_scrubber_shapes_in_every_field() {
    use heldkeys::finding::{Access, Finding, Lifetime, Rule, Severity};
    use heldkeys::report::{self, Format, Mode, Report};

    let texts = [
        "https://user:pa/ssFAKEslash0901@host.example.com/x",
        "https://user%3AFAKEpct0902@host.example.com",
        "x://u:FAKEdigest0903@sha256:abc",
        "Authorization: Bearer FAKEbearer0904abcdef",
        "~/.npmrc (//u:pa/ssFAKEnpm0905@registry.example.com/)",
        "curl -H Bearer FAKEbare0910xyz",
        "https://h.example.com/?access_token=FAKEquery0911&x=1",
        "https://h.example.com/#access_token=FAKEfrag0912",
        "https://h.example.com/a?code=FAKEcode0913",
        "tool --password FAKEflag0914",
        "tool --api-key=FAKEflag0915",
        "tool --token FAKEflag0916",
        "tool --secret=FAKEflag0917",
    ];
    let rule = Rule {
        check: "test",
        id: "HK-TEST-001",
        summary: "",
    };
    let findings: Vec<Finding> = texts
        .iter()
        .map(|t| {
            Finding::new(
                rule,
                *t,
                *t,
                Severity::High,
                Lifetime::LongLived,
                Access::Write,
                *t,
            )
            .with_detail(*t)
        })
        .collect();
    let report = Report::new(Mode::Scan, findings);
    let secrets: Vec<String> = SCRUB_SECRETS.iter().map(|s| s.to_string()).collect();
    for format in [Format::Text, Format::Json, Format::Markdown, Format::Sarif] {
        for details in [false, true] {
            let options = report::TextOptions {
                details,
                ..report::TextOptions::plain()
            };
            let out = report::render(format, &report, &options).unwrap();
            assert_no_leak(&format!("{format:?}"), &out, &secrets);
        }
    }
}

/// In the Markdown report (a PR comment or job summary), URLs from the
/// scanned files are never clickable: outside code spans the only links are
/// heldkeys' own rule pages.
#[test]
fn markdown_links_only_to_rule_pages() {
    let out = run_in(
        &fixture("empty"),
        &fixture("scrub/project"),
        &["ci", "--format", "markdown", "--fail-on", "none"],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("evil.example/job"), "{}", out.stdout);
    assert!(out.stdout.contains("evil.example/fix"), "{}", out.stdout);
    // Drop code spans, then our own rule links.
    let mut outside = String::new();
    let mut rest = out.stdout.as_str();
    while let Some(start) = rest.find('`') {
        outside.push_str(&rest[..start]);
        let fence: String = rest[start..].chars().take_while(|&c| c == '`').collect();
        let after = &rest[start + fence.len()..];
        rest = match after.find(&fence) {
            Some(end) => &after[end + fence.len()..],
            None => after,
        };
    }
    outside.push_str(rest);
    let outside = outside.replace(
        "(https://github.com/hugomn/heldkeys/blob/main/docs/rules/",
        "(RULE/",
    );
    for needle in ["http", "www."] {
        assert!(
            !outside.contains(needle),
            "{needle} outside a code span:\n{}",
            out.stdout
        );
    }
}
