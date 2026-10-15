//! End-to-end tests of the binary: flags, formats, exit codes.

mod common;

use common::{ENV_SECRETS, fixture, run, run_in};

#[test]
fn empty_home_reports_nothing() {
    let out = run("empty", &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout, "No credentials reachable from here.\n");
}

#[test]
fn full_home_text_report() {
    let out = run("full", &["scan", "--no-color"]);
    assert_eq!(out.code, 0, "scan does not fail by default: {}", out.stderr);
    assert!(
        out.stdout.starts_with("heldkeys: "),
        "the summary leads: {}",
        out.stdout
    );
    assert!(out.stdout.contains("\nFix these first\n"));
    assert!(out.stdout.contains("Long-lived AWS access key"));
    assert!(out.stdout.contains("~/.aws/credentials [default]"));
    assert!(out.stdout.contains("AKIA…PLE"));
    assert!(out.stdout.contains("\nNext steps\n"));
    let last: Vec<&str> = out.stdout.lines().rev().take(2).collect();
    assert!(last[1].contains("credentials reachable,"), "{last:?}");
    assert!(last[0].ends_with("it can use all of them."), "{last:?}");
    // One line, as before, when the terminal is wide enough.
    let wide = run_in(
        &fixture("full"),
        &fixture("full"),
        &["--no-color"],
        &[("COLUMNS", "200")],
    );
    let last = wide.stdout.lines().last().unwrap();
    assert!(last.contains("credentials reachable,"), "{last}");
    assert!(last.ends_with("it can use all of them."), "{last}");
    assert!(
        !out.stdout.contains('\u{1b}'),
        "no colour when not a terminal"
    );
}

#[test]
fn details_flag_lists_every_finding_by_file() {
    let json: serde_json::Value =
        serde_json::from_str(&run("full", &["--format", "json"]).stdout).unwrap();
    let total = json["findings"].as_array().unwrap().len();
    for flag in ["--details", "-v"] {
        let out = run("full", &["scan", flag, "--no-color"]);
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert!(
            out.stdout
                .contains("\n  ~/.aws/credentials\n    HIGH    Long-lived AWS access key"),
            "{}",
            out.stdout
        );
        let rows = out
            .stdout
            .lines()
            .filter(|l| {
                ["    HIGH ", "    MEDIUM ", "    LOW ", "    INFO "]
                    .iter()
                    .any(|t| l.starts_with(t))
            })
            .count();
        assert_eq!(rows, total, "{}", out.stdout);
    }
    // --details and --quiet do not go together.
    assert_eq!(run("full", &["--details", "--quiet"]).code, 2);
}

#[test]
fn every_local_check_fires_on_the_full_fixture() {
    let out = run("full", &["--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let checks: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["check"].as_str().unwrap())
        .collect();
    for id in [
        "aws",
        "gcloud",
        "azure",
        "kube",
        "docker",
        "netrc",
        "git-credentials",
        "npmrc",
        "pypirc",
        "cargo-credentials",
        "git-helper",
        "k8s-service-account",
        "mcp",
    ] {
        assert!(checks.contains(&id), "{id} missing from {checks:?}");
    }
}

#[test]
fn json_report_schema() {
    let out = run("full", &["--format", "json"]);
    assert_eq!(out.code, 0);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["schema"], "heldkeys/v1");
    assert_eq!(v["mode"], "scan");
    assert_eq!(v["tool"]["name"], "heldkeys");
    let findings = v["findings"].as_array().unwrap();
    assert!(findings.len() > 20, "{}", findings.len());
    assert_eq!(
        v["summary"]["credentials"].as_u64().unwrap() as usize,
        findings.len() - v["summary"]["info"].as_u64().unwrap() as usize
    );
    for f in findings {
        assert!(f["rule"].as_str().unwrap().starts_with("HK-"), "{f}");
        for key in [
            "check", "rule", "title", "location", "severity", "lifetime", "access", "fix",
        ] {
            assert!(f[key].is_string(), "{key} in {f}");
        }
    }
    // Most severe first.
    assert_eq!(findings[0]["severity"], "high");
}

#[test]
fn fail_on_thresholds() {
    assert_eq!(run("full", &["--fail-on", "high"]).code, 1);
    assert_eq!(run("full", &["--fail-on", "long-lived-write"]).code, 1);
    assert_eq!(run("full", &["--fail-on", "none"]).code, 0);
    assert_eq!(run("empty", &["--fail-on", "low"]).code, 0);
    // aws-sso has a role profile (medium) but nothing high.
    assert_eq!(run("aws-sso", &["--fail-on", "high"]).code, 0);
    assert_eq!(run("aws-sso", &["--fail-on", "medium"]).code, 1);
}

#[test]
fn flags_work_after_the_subcommand_and_before_it() {
    assert_eq!(run("full", &["--fail-on", "high", "scan"]).code, 1);
    assert_eq!(run("full", &["scan", "--fail-on", "high"]).code, 1);
}

#[test]
fn quiet_prints_only_the_summary() {
    let out = run("full", &["--quiet"]);
    assert_eq!(out.stdout.lines().count(), 1, "{}", out.stdout);
    assert!(out.stdout.contains("credentials reachable"));
}

#[test]
fn output_file_gets_the_report() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("report.json");
    let out = run(
        "full",
        &["--format", "json", "--output", file.to_str().unwrap()],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout.lines().count(), 1);
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    assert_eq!(v["schema"], "heldkeys/v1");
}

#[test]
fn environment_credentials() {
    let empty = fixture("empty");
    let out = run_in(&empty, &empty, &["--format", "json"], ENV_SECRETS);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let locations: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["location"].as_str().unwrap())
        .collect();
    for expected in [
        "env: GITHUB_TOKEN",
        "env: ANTHROPIC_API_KEY",
        "env: MY_SERVICE_PASSWORD",
        "env: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY",
        "env: DATABASE_URL",
    ] {
        assert!(
            locations.contains(&expected),
            "{expected} not in {locations:?}"
        );
    }
    assert_eq!(locations.len(), 5, "{locations:?}");
}

#[test]
fn dotenv_in_working_directory() {
    let out = run_in(&fixture("empty"), &fixture("project"), &["--no-color"], &[]);
    assert!(
        out.stdout.contains("./.env: OPENAI_API_KEY"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("./apps/web/.env: GITHUB_TOKEN"));
    assert!(!out.stdout.contains("node_modules"));
}

#[test]
fn ssh_keys_in_a_temporary_home() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".ssh")).unwrap();
    std::fs::write(tmp.path().join(".ssh/id_ed25519"), common::FAKE_SSH_KEY).unwrap();
    let out = run_in(tmp.path(), tmp.path(), &["--no-color"], &[]);
    assert!(
        out.stdout.contains("SSH private key without a passphrase"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("~/.ssh/id_ed25519"));
}

#[test]
fn ci_mode_defaults() {
    let out = run("empty", &["ci"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = run("empty", &["ci", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["mode"], "ci");
}

#[test]
fn checks_subcommand() {
    let out = run("empty", &["checks"]);
    assert_eq!(out.code, 0);
    for id in [
        "env",
        "aws",
        "ssh-agent",
        "docker-socket",
        "cloud-metadata",
        "workflows",
        "ci-runtime",
    ] {
        assert!(out.stdout.contains(&format!("  {id} ")), "{id}");
    }
    let out = run("empty", &["checks", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert!(
        v.as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "mcp" && c["mode"] == "scan")
    );
    let aws = v
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "aws")
        .unwrap();
    assert_eq!(aws["rules"][0]["id"], "HK-AWS-001");
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(run("empty", &["--format", "yaml"]).code, 2);
    assert_eq!(run("empty", &["--bogus"]).code, 2);
    let empty = fixture("empty");
    let missing = empty.join("does-not-exist");
    let out = run_in(&missing, &empty, &[], &[]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("error:"), "{}", out.stderr);
}

#[test]
fn markdown_and_sarif_formats() {
    let out = run("full", &["--format", "markdown"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.starts_with("## heldkeys scan\n"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("| High |"));

    let out = run("full", &["--format", "sarif"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert!(!v["runs"][0]["results"].as_array().unwrap().is_empty());
}

/// `dotenv-cases`: template placeholders, public frontend keys and shared
/// token formats, as found in real projects.
#[test]
fn dotenv_false_positives_and_vendor_titles() {
    let out = run_in(
        &fixture("empty"),
        &fixture("dotenv-cases"),
        &["--format", "json", "--strict"],
        &[],
    );
    assert_eq!(
        out.code, 0,
        "an empty or commented MCP config is not a read error: {}",
        out.stdout
    );
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let findings: Vec<(String, String, String)> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["location"].as_str().unwrap().to_string(),
                f["title"].as_str().unwrap().to_string(),
                f["severity"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let get = |location: &str| {
        findings
            .iter()
            .find(|f| f.0 == location)
            .map(|f| (f.1.as_str(), f.2.as_str()))
    };
    // Templates: placeholders are not findings; a real-looking token is,
    // one level lower.
    let template: Vec<&(String, String, String)> = findings
        .iter()
        .filter(|f| f.0.contains(".env.example"))
        .collect();
    assert_eq!(template.len(), 1, "{template:?}");
    assert_eq!(
        get("./.env.example: SLACK_BOT_TOKEN"),
        Some(("Slack token in a template file", "medium"))
    );
    // Frontend: public by design is skipped, a secret in the bundle is High.
    for skipped in [
        "NEXT_PUBLIC_POSTHOG_KEY",
        "VITE_RECAPTCHA_SITE_KEY",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY",
        "REACT_APP_GOOGLE_CLIENT_ID",
    ] {
        assert!(
            get(&format!("./apps/web/.env.local: {skipped}")).is_none(),
            "{skipped}"
        );
    }
    for exposed in [
        "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
        "VITE_STRIPE_SECRET_KEY",
    ] {
        assert_eq!(
            get(&format!("./apps/web/.env.local: {exposed}")),
            Some(("Secret exposed to the frontend bundle", "high")),
            "{exposed}"
        );
    }
    // Shared formats are titled after the vendor the name gives.
    for (name, title, severity) in [
        ("WORKOS_API_KEY", "WorkOS test-mode API key", "low"),
        ("STRIPE_SECRET_KEY", "Stripe live secret key", "high"),
        ("PAYMENTS_KEY", "Test-mode secret key (sk_test_)", "low"),
        ("DEEPSEEK_API_KEY", "DeepSeek API key", "high"),
        ("MOONSHOT_API_KEY", "Moonshot API key", "high"),
        ("LLM_API_KEY", "OpenAI-style API key", "high"),
        (
            "GITHUB_APP_SECRET",
            "Possible cloud or SCM credential",
            "medium",
        ),
    ] {
        assert_eq!(
            get(&format!("./.env: {name}")),
            Some((title, severity)),
            "{name}"
        );
    }
    // A local development database is not a credential.
    assert!(get("./.env: DATABASE_URL").is_none());
    for f in v["findings"].as_array().unwrap() {
        assert_eq!(f["category"], "project-env", "{f}");
    }
}
