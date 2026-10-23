//! `heldkeys incident <set>`: the verdict, the exit code, and what each
//! format carries.

mod common;

use common::{fixture, run, run_in};

fn incident_run(args: &[&str], env: &[(&str, &str)]) -> common::Output {
    let mut all = vec!["incident", "black-october"];
    all.extend_from_slice(args);
    run_in(
        &fixture("incident/home"),
        &fixture("incident/project"),
        &all,
        env,
    )
}

#[test]
fn an_empty_home_is_clean_and_exits_zero() {
    let out = run("empty", &["incident", "black-october", "--no-color"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.starts_with(
            "heldkeys incident black-october: no known indicators, 0 credentials reachable from "
        ),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains("Indicators as published up to 2026-10-23")
    );
    assert!(out.stdout.contains("\nAdvisories\n"));
    assert!(
        out.stdout
            .contains("Nothing to clean up for the known indicators, and no credentials reachable")
    );
    let last = out.stdout.lines().last().unwrap();
    assert_eq!(
        last,
        "No known compromise indicators found. No credentials reachable from here."
    );
    assert!(!out.stdout.contains("Compromise indicators\n"));
}

#[test]
fn the_fixture_is_compromised_and_exits_one() {
    let out = incident_run(&["--no-color"], &[("PRIVCOLLECT_ACTIVE", "1")]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    let first = out.stdout.lines().next().unwrap();
    assert!(
        first.starts_with("heldkeys incident black-october: ")
            && first.contains("compromise indicators found, "),
        "{first}"
    );
    for heading in [
        "\nCompromise indicators\n",
        "\nRotate these first\n",
        "\nUnpatched runtimes (not credentials)\n",
        "\nPlatforms that disclosed a breach\n",
        "\nNext steps\n",
        "\nAdvisories\n",
    ] {
        assert!(
            out.stdout.contains(heading),
            "{heading:?} in\n{}",
            out.stdout
        );
    }
    assert!(out.stdout.contains("litellm 1.107.0 installed"));
    assert!(out.stdout.contains("LiteLLM loader lock file"));
    assert!(out.stdout.contains("Treat this host as compromised"));
    assert!(
        out.stdout.contains("Railway CLI login token"),
        "the credential inventory runs too"
    );
    assert!(
        out.stdout
            .contains("Run `heldkeys incident black-october --details`")
    );
    // The summary line is wider than the terminal, so it is split at its
    // sentences; the verdict sentence comes right before the last line.
    let lines: Vec<&str> = out.stdout.lines().collect();
    let verdict = lines[lines.len() - 2];
    assert!(
        verdict.ends_with(" compromise indicators found.")
            && verdict.trim_start_matches(|c: char| c.is_ascii_digit()) != verdict,
        "{verdict}"
    );
    assert!(
        lines[lines.len() - 1].starts_with("Treat this host as compromised"),
        "{}",
        lines[lines.len() - 1]
    );
    // Nothing of the fixture's fake tokens leaks.
    for secret in common::FIXTURE_SECRETS {
        assert!(!out.stdout.contains(secret), "{secret}");
    }
}

#[test]
fn json_carries_the_incident_object() {
    let out = incident_run(&["--format", "json"], &[]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["mode"], "incident");
    assert_eq!(v["incident"]["set"], "black-october");
    assert_eq!(v["incident"]["as_of"], "2026-10-23");
    assert_eq!(v["incident"]["verdict"], "compromised");
    assert!(v["incident"]["indicators"].as_u64().unwrap() >= 5);
    assert_eq!(v["incident"]["indicators"], v["summary"]["indicators"]);
    assert_eq!(
        v["summary"]["exposures"], 2,
        "the pin and the Caskroom version"
    );
    assert_eq!(
        v["summary"]["runtimes"], 3,
        "nvm 22.23.3, Dockerfile PHP, .nvmrc 20"
    );
    assert_eq!(
        v["summary"]["breaches"], 4,
        "Railway login and project, Zeabur, OpenCode"
    );
    assert!(v["incident"]["advisories"].as_array().unwrap().len() >= 8);
    let rules: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    for rule in [
        "HK-LITELLM-001",
        "HK-LITELLM-002",
        "HK-LITELLM-003",
        "HK-LITELLM-007",
        "HK-OVH-002",
        "HK-RT-001",
        "HK-RT-002",
        "HK-BREACH-001",
        "HK-BREACH-002",
        "HK-BREACH-003",
        "HK-CLI-010",
    ] {
        assert!(rules.contains(&rule), "{rule} in {rules:?}");
    }
    // Indicators are not credentials.
    let credentials = v["summary"]["credentials"].as_u64().unwrap();
    assert!((1..4).contains(&credentials), "{credentials}");
    // The categories serialise as kebab-case.
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["category"] == "indicators")
    );
}

#[test]
fn a_pin_alone_is_exposure_not_compromise() {
    let out = run_in(
        &fixture("empty"),
        &fixture("incident/project"),
        &["incident", "black-october", "--format", "json"],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["incident"]["verdict"], "exposed");
    assert_eq!(v["incident"]["indicators"], 0);
    assert_eq!(v["incident"]["exposures"], 1);
    let text = run_in(
        &fixture("empty"),
        &fixture("incident/project"),
        &["incident", "black-october", "--no-color"],
        &[],
    );
    assert!(
        text.stdout
            .starts_with("heldkeys incident black-october: 1 sign of exposure to check, "),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("Check the signs of exposure above"));
}

#[test]
fn scan_never_runs_the_incident_checks() {
    let out = incident_run(&[], &[]);
    assert_eq!(out.code, 1);
    let scan = run_in(
        &fixture("incident/home"),
        &fixture("incident/project"),
        &["scan", "--format", "json"],
        &[],
    );
    assert_eq!(scan.code, 0, "{}", scan.stderr);
    let v: serde_json::Value = serde_json::from_str(&scan.stdout).unwrap();
    assert!(v.get("incident").is_none());
    assert!(
        !v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule"].as_str().unwrap().starts_with("HK-LITELLM")),
        "{}",
        scan.stdout
    );
}

#[test]
fn markdown_and_sarif_carry_the_indicators() {
    let md = incident_run(&["--format", "markdown"], &[]);
    assert_eq!(md.code, 1);
    assert!(md.stdout.starts_with("## heldkeys incident\n"));
    assert!(md.stdout.contains("### Compromise indicators\n"));
    assert!(md.stdout.contains("| [HK-LITELLM-001](https://github.com/hugomn/heldkeys/blob/main/docs/rules/HK-LITELLM-001.md) |"));
    assert!(md.stdout.contains("### Advisories\n"));
    assert!(
        md.stdout
            .contains("<https://docs.litellm.ai/blog/security-incident-oct-21-2026>")
    );
    let sarif = incident_run(&["--format", "sarif"], &[]);
    assert_eq!(sarif.code, 1);
    let v: serde_json::Value = serde_json::from_str(&sarif.stdout).unwrap();
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["ruleId"] == "HK-LITELLM-001"));
}

#[test]
fn details_and_quiet_views() {
    let details = incident_run(&["--details", "--no-color"], &[]);
    assert_eq!(details.code, 1);
    assert!(details.stdout.contains("\nCompromise indicators\n"));
    assert!(details.stdout.contains("Indicators as published up to"));
    assert!(details.stdout.contains("\nAdvisories\n"));
    let quiet = incident_run(&["--quiet"], &[]);
    assert_eq!(quiet.code, 1);
    assert_eq!(quiet.stdout.lines().count(), 1, "{}", quiet.stdout);
    assert!(quiet.stdout.contains("compromise indicators found."));
}

#[test]
fn ignore_rules_apply_to_incident_findings() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("heldkeys.toml");
    std::fs::write(
        &config,
        "[[ignore]]\nrule = \"HK-RT-001\"\nreason = \"patched tonight\"\n",
    )
    .unwrap();
    let out = incident_run(
        &[
            "--format",
            "json",
            "--config",
            &config.display().to_string(),
        ],
        &[],
    );
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["summary"]["runtimes"], 2);
    assert_eq!(v["summary"]["ignored"], 1);
}

#[test]
fn checks_lists_the_incident_group() {
    let out = run("empty", &["checks"]);
    assert!(out.stdout.contains("\nincident:\n"), "{}", out.stdout);
    assert!(out.stdout.contains("ioc-litellm"));
    assert!(out.stdout.contains("HK-BREACH-003"));
    let json = run("empty", &["checks", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert!(
        v.as_array()
            .unwrap()
            .iter()
            .any(|c| c["mode"] == "incident" && c["id"] == "runtime-versions")
    );
}

#[test]
fn an_unknown_set_is_a_usage_error() {
    let out = run("empty", &["incident", "black-friday"]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("black-october"), "{}", out.stderr);
}
