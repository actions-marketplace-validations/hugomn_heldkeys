//! End-to-end tests of `heldkeys ci`: workflow fixtures, the CI runtime and
//! `--repo-secrets`, run through the binary with a controlled environment.

mod common;

use std::path::Path;
use std::process::Command;

use common::{Output, fixture, run_in};

fn ci(case: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut all = vec!["ci"];
    all.extend_from_slice(args);
    run_in(
        &fixture("empty"),
        &fixture(&format!("workflows/{case}")),
        &all,
        env,
    )
}

fn rules(out: &Output) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let mut r: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap().to_string())
        .collect();
    r.sort();
    r.dedup();
    r
}

#[test]
fn safe_agent_workflow_passes() {
    let out = ci("safe", &[], &[]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert_eq!(
        out.stdout,
        "No AI agent workflow risks and no credentials reachable in this job.\n"
    );
}

#[test]
fn each_rule_fixture_reports_its_rule() {
    for (case, rule, code) in [
        ("untrusted-trigger", "HK-WF-001", 1),
        ("pr-head-checkout", "HK-WF-002", 1),
        ("permissions", "HK-WF-003", 1),
        ("secrets", "HK-WF-004", 1),
        ("unpinned", "HK-WF-005", 0), // Medium only: below ci's default --fail-on high
        ("shell", "HK-WF-006", 1),
    ] {
        let out = ci(case, &["--format", "json"], &[]);
        assert_eq!(out.code, code, "{case}: {}", out.stderr);
        assert!(
            rules(&out).contains(&rule.to_string()),
            "{case}: {}",
            out.stdout
        );
    }
    assert_eq!(ci("unpinned", &["--fail-on", "medium"], &[]).code, 1);
}

#[test]
fn sarif_points_at_workflow_lines() {
    let out = ci("shell", &["--format", "sarif"], &[]);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 4);
    for r in results {
        assert_eq!(r["ruleId"], "HK-WF-006");
        let physical = &r["locations"][0]["physicalLocation"];
        let uri = physical["artifactLocation"]["uri"].as_str().unwrap();
        assert!(uri.starts_with(".github/workflows/"), "{uri}");
        assert!(physical["region"]["startLine"].as_u64().unwrap() > 1);
    }
}

#[test]
fn markdown_job_summary() {
    let out = ci("pr-head-checkout", &["--format", "markdown"], &[]);
    assert!(out.stdout.starts_with("## heldkeys ci\n"), "{}", out.stdout);
    assert!(out.stdout.contains("[HK-WF-002]("));
    assert!(out.stdout.contains("<details>"));
}

#[test]
fn github_actions_runtime() {
    let out = ci(
        "safe",
        &["--format", "json"],
        &[
            ("GITHUB_ACTIONS", "true"),
            (
                "GITHUB_WORKFLOW_REF",
                "octo/repo/.github/workflows/review.yml@refs/heads/main",
            ),
            ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.invalid/t"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "FAKEoidcREQUESTtoken0701"),
            (
                "NPM_TOKEN",
                concat!("npm_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0702"),
            ),
        ],
    );
    assert_eq!(out.code, 1, "an npm token in the job env is High");
    assert_eq!(rules(&out), vec!["HK-CI-001", "HK-CI-003", "HK-CI-006"]);
}

/// A throwaway git repository with one tracked file holding a fake token.
fn git_repo(dir: &Path) {
    std::fs::write(
        dir.join("settings.py"),
        concat!("TOKEN = 'ghp_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKE000703'\n"),
    )
    .unwrap();
    for args in [vec!["init", "-q"], vec!["add", "-A"]] {
        let ok = Command::new("git")
            .args(&args)
            .current_dir(dir)
            .env_clear()
            .env("HOME", dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }
}

#[test]
fn repo_secrets_flag() {
    let tmp = tempfile::tempdir().unwrap();
    git_repo(tmp.path());
    let empty = fixture("empty");

    let off = run_in(&empty, tmp.path(), &["ci", "--format", "json"], &[]);
    assert!(rules(&off).is_empty(), "{}", off.stdout);

    let on = run_in(
        &empty,
        tmp.path(),
        &["ci", "--repo-secrets", "--format", "json"],
        &[],
    );
    assert_eq!(on.code, 1, "{}", on.stderr);
    let v: serde_json::Value = serde_json::from_str(&on.stdout).unwrap();
    let f = &v["findings"][0];
    assert_eq!(f["rule"], "HK-REPO-001");
    assert_eq!(f["location"], "settings.py:1");
    assert_eq!(f["fingerprint"], "ghp_…703");
    assert!(!on.stdout.contains("FAKEFAKEFAKEFAKE"));
}

#[test]
fn ci_summary_separates_workflow_risks_from_job_credentials() {
    let out = ci(
        "untrusted-trigger",
        &["--quiet"],
        &[
            ("GITHUB_ACTIONS", "true"),
            (
                "NPM_TOKEN",
                concat!("npm_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0702"),
            ),
        ],
    );
    assert_eq!(
        out.stdout,
        "4 AI agent workflow risks, 1 credential reachable in this job.\n"
    );
}

#[test]
fn checkout_commands_are_named_not_quoted() {
    for format in ["text", "json", "markdown", "sarif"] {
        let out = ci("pr-head-checkout", &["--format", format], &[]);
        assert_eq!(out.code, 1, "{format}: {}", out.stderr);
        for leak in ["FETCHFAKE", "x-access-token"] {
            assert!(!out.stdout.contains(leak), "{format}: {}", out.stdout);
        }
    }
    let json = ci("pr-head-checkout", &["--format", "json"], &[]);
    assert!(
        json.stdout
            .contains("run: git fetch ... pull/<n>/head on pull_request_target")
    );
}

#[test]
fn reusable_dispatch_workflow_fails_ci() {
    let out = ci("reusable", &["--format", "json"], &[]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let high = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["severity"] == "high")
        .unwrap();
    assert_eq!(high["rule"], "HK-WF-001");
    let location = high["location"].as_str().unwrap();
    assert!(
        location.starts_with(".github/workflows/gemini-dispatch.yml:")
            && location.contains(" -> .github/workflows/gemini-review.yml:"),
        "{location}"
    );
}

/// `--strict` fails closed on a workflow heldkeys could not analyse
/// (HK-WF-007), not only on unreadable files.
#[test]
fn strict_fails_on_an_unparsable_workflow() {
    let tmp = tempfile::tempdir().unwrap();
    let workflows = tmp.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    std::fs::write(workflows.join("broken.yml"), "on: [\n").unwrap();
    let home = fixture("empty");

    let lenient = run_in(&home, tmp.path(), &["ci", "--format", "json"], &[]);
    assert_eq!(lenient.code, 0, "{}", lenient.stdout);
    assert_eq!(rules(&lenient), ["HK-WF-007"]);

    let strict = run_in(&home, tmp.path(), &["ci", "--strict", "--quiet"], &[]);
    assert_eq!(strict.code, 1, "{}", strict.stdout);
}

/// A token in the checkout's remote URL is found in `ci` mode too, and the
/// AUTHORIZATION header actions/checkout persists is reported once (as
/// HK-CI-005), not again as HK-GITCFG-002.
#[test]
fn ci_reads_the_checkouts_git_config() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
    std::fs::write(
        tmp.path().join(".git/config"),
        "[remote \"origin\"]\n\turl = https://x-access-token:ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000994@github.com/o/r.git\n[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46RkFLRQ==\n",
    )
    .unwrap();
    let env = [("GITHUB_ACTIONS", "true")];
    let out = run_in(
        &fixture("empty"),
        tmp.path(),
        &["ci", "--format", "json"],
        &env,
    );
    assert_eq!(out.code, 1, "{}", out.stdout);
    let found = rules(&out);
    assert!(found.contains(&"HK-GITCFG-003".to_string()), "{found:?}");
    assert!(found.contains(&"HK-CI-005".to_string()), "{found:?}");
    assert!(!found.contains(&"HK-GITCFG-002".to_string()), "{found:?}");
    assert!(!out.stdout.contains("FAKEFAKEFAKEFAKEFAKEFAKE"));

    // Outside a CI job, `ci` still reads it (and reports the header itself).
    let local = run_in(
        &fixture("empty"),
        tmp.path(),
        &["ci", "--format", "json"],
        &[],
    );
    assert_eq!(local.code, 1, "{}", local.stdout);
    assert_eq!(rules(&local), ["HK-GITCFG-002", "HK-GITCFG-003"]);
}

#[test]
fn gemini_dispatch_template_passes_at_the_default_threshold() {
    // The agent job needs a job gated on the commenter's association, so
    // HK-WF-001 is Medium, below ci's default --fail-on high.
    let out = ci("gemini-dispatch", &["--format", "json"], &[]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let wf1: Vec<&serde_json::Value> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "HK-WF-001")
        .collect();
    assert_eq!(wf1.len(), 1, "{}", out.stdout);
    assert_eq!(wf1[0]["severity"], "medium");
    assert!(
        wf1[0]["detail"]
            .as_str()
            .unwrap()
            .contains("gated by an if: on the actor in a job it needs")
    );
    assert_eq!(ci("gemini-dispatch", &["--fail-on", "medium"], &[]).code, 1);
}
