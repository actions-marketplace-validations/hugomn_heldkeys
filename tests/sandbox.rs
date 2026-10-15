//! End-to-end tests of `preflight` and of the `scan --docker/--kube` flags.
//!
//! Nothing here runs docker or kubectl: the environment is cleared (so they
//! are not even on PATH), and every remote case stops at validation, before
//! any command would run.

mod common;

use common::{fixture, run, run_in};

#[test]
fn preflight_passes_with_nothing_reachable() {
    let out = run("empty", &["preflight"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(
        out.stdout,
        "heldkeys preflight: PASS, no credentials reachable\n"
    );
}

#[test]
fn preflight_fails_on_high_by_default() {
    let out = run("full", &["preflight"]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    let mut lines = out.stdout.lines();
    let verdict = lines.next().unwrap();
    assert!(
        verdict.starts_with("heldkeys preflight: FAIL, ")
            && verdict.contains("high-severity credentials reachable"),
        "{verdict}"
    );
    // Then one line per finding that caused the failure.
    // At most 10, then how many more.
    let rest: Vec<&str> = lines.collect();
    assert!(!rest.is_empty());
    let (reasons, more) = rest.split_at(rest.len().min(10));
    assert!(
        reasons.iter().all(|l| l.starts_with("  HIGH  ")),
        "{rest:?}"
    );
    assert!(
        more.is_empty() || (more.len() == 1 && more[0].starts_with("  +")),
        "{rest:?}"
    );
    assert!(
        rest.iter()
            .any(|l| l.contains("~/.aws/credentials [default]  AKIA…PLE"))
    );
}

#[test]
fn preflight_thresholds() {
    let out = run("full", &["preflight", "--fail-on", "none"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.starts_with("heldkeys preflight: PASS, "));
    assert!(out.stdout.contains("none reach --fail-on none"));

    let out = run("full", &["preflight", "--fail-on", "long-lived-write"]);
    assert_eq!(out.code, 1);
    assert!(out.stdout.contains("long-lived write credential"));

    // aws-sso has a role profile (medium) but nothing high.
    assert_eq!(run("aws-sso", &["preflight"]).code, 0);
    assert_eq!(
        run("aws-sso", &["preflight", "--fail-on", "medium"]).code,
        1
    );
}

#[test]
fn preflight_quiet_is_one_line() {
    let out = run("full", &["preflight", "--quiet"]);
    assert_eq!(out.code, 1);
    assert_eq!(out.stdout.lines().count(), 1, "{}", out.stdout);
}

#[test]
fn preflight_json() {
    let out = run("full", &["preflight", "--format", "json"]);
    assert_eq!(out.code, 1);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["schema"], "heldkeys/v1");
    assert_eq!(v["preflight"]["result"], "fail");
    assert_eq!(v["preflight"]["fail_on"], "high");
    assert!(v["preflight"]["triggered"].as_u64().unwrap() > 0);
    // The verdict still reaches the log, on stderr.
    assert!(
        out.stderr.starts_with("heldkeys preflight: FAIL, "),
        "{}",
        out.stderr
    );

    let out = run("empty", &["preflight", "--format", "json"]);
    assert_eq!(out.code, 0);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["preflight"]["result"], "pass");
}

#[test]
fn preflight_output_file() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("preflight.json");
    let out = run(
        "full",
        &[
            "preflight",
            "--format",
            "json",
            "--output",
            file.to_str().unwrap(),
        ],
    );
    assert_eq!(out.code, 1);
    assert!(out.stdout.starts_with("heldkeys preflight: FAIL, "));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    assert_eq!(v["preflight"]["result"], "fail");
}

#[test]
fn preflight_rejects_other_formats() {
    let out = run("full", &["preflight", "--format", "sarif"]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("--format text or json"),
        "{}",
        out.stderr
    );
}

#[test]
fn remote_flag_combinations_are_usage_errors() {
    assert_eq!(
        run("empty", &["scan", "--docker", "a", "--kube", "b"]).code,
        2
    );
    assert_eq!(run("empty", &["scan", "-n", "ns"]).code, 2);
    assert_eq!(run("empty", &["scan", "-c", "agent"]).code, 2);
    assert_eq!(run("empty", &["scan", "--binary", "/x/heldkeys"]).code, 2);
}

#[test]
fn remote_names_are_validated_before_anything_runs() {
    let out = run("empty", &["scan", "--docker", "a;rm -rf /"]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("invalid container name"),
        "{}",
        out.stderr
    );
    let out = run("empty", &["scan", "--kube", "pod", "-n", "a/b"]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("invalid namespace name"),
        "{}",
        out.stderr
    );
}

#[test]
fn remote_scan_needs_a_linux_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let not_elf = tmp.path().join("heldkeys");
    std::fs::write(&not_elf, "#!/bin/sh\n").unwrap();
    let empty = fixture("empty");
    let out = run_in(
        &empty,
        &empty,
        &[
            "scan",
            "--docker",
            "agent-box",
            "--binary",
            not_elf.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("is not a Linux binary") && out.stderr.contains("--binary <path>"),
        "{}",
        out.stderr
    );
}
