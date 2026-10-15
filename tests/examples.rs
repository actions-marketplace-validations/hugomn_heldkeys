//! The workflows in `examples/` do what their comments say: the vulnerable
//! one trips every HK-WF rule, the hardened one none.

mod common;

use common::{fixture, run_in};

/// `heldkeys ci --format json` on a repository holding only `example`, and
/// the sorted, de-duplicated rule ids it reports.
fn workflow_rules(example: &str) -> (i32, Vec<String>) {
    let repo = tempfile::tempdir().unwrap();
    let workflows = repo.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(example);
    std::fs::copy(&source, workflows.join(example)).unwrap();

    let out = run_in(
        &fixture("empty"),
        repo.path(),
        &["ci", "--format", "json"],
        &[],
    );
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let mut rules: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap().to_string())
        .collect();
    rules.sort();
    rules.dedup();
    (out.code, rules)
}

#[test]
fn vulnerable_example_trips_every_workflow_rule() {
    let (code, rules) = workflow_rules("vulnerable-agent-workflow.yml");
    assert_eq!(code, 1);
    assert_eq!(
        rules,
        [
            "HK-WF-001",
            "HK-WF-002",
            "HK-WF-003",
            "HK-WF-004",
            "HK-WF-005",
            "HK-WF-006"
        ]
    );
}

#[test]
fn hardened_example_has_no_workflow_findings() {
    let (code, rules) = workflow_rules("hardened-agent-workflow.yml");
    assert_eq!(code, 0);
    assert!(rules.is_empty(), "{rules:?}");
}
