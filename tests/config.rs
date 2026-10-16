//! Ignore rules (`.heldkeys.toml`) and baselines, end to end: which files
//! are read, what is refused, and how every format counts and lists what
//! was left out.

mod common;

use std::path::{Path, PathBuf};

use common::{Output, copy_dir, fixture, run_in};

fn repo() -> PathBuf {
    fixture("config/repo")
}

/// `heldkeys ci` on `cwd`, with an empty home.
fn ci(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut all = vec!["ci"];
    all.extend_from_slice(args);
    run_in(&fixture("empty"), cwd, &all, env)
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_str(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", out.stdout))
}

fn rules(v: &serde_json::Value, list: &str) -> Vec<String> {
    let mut r: Vec<String> = v[list]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap().to_string())
        .collect();
    r.sort();
    r
}

#[test]
fn project_config_ignores_and_counts() {
    let out = ci(&repo(), &["--format", "json"], &[]);
    // HK-WF-001 is High and its ignore rule expired: the run still fails.
    assert_eq!(out.code, 1, "{}", out.stderr);
    let v = json(&out);
    assert_eq!(rules(&v, "findings"), ["HK-WF-001"]);
    assert_eq!(rules(&v, "suppressed"), ["HK-WF-005"]);
    let s = &v["suppressed"][0];
    assert_eq!(s["by"], "config");
    assert_eq!(s["reason"], "pinned via Renovate");
    assert_eq!(s["source"], "./.heldkeys.toml");
    assert_eq!(s["severity"], "medium");
    assert!(
        s["location"]
            .as_str()
            .unwrap()
            .starts_with(".github/workflows/claude.yml:")
    );
    assert_eq!(v["summary"]["ignored"], 1);
    assert_eq!(v["summary"]["in_baseline"], 0);
    // The expired ignore is a warning, not an error.
    assert!(
        out.stderr.contains(
            "warning: ./.heldkeys.toml: the ignore rule for HK-WF-001 expired on 2020-01-31"
        ),
        "{}",
        out.stderr
    );
}

#[test]
fn text_shows_every_matching_ignore() {
    let out = ci(&repo(), &["--no-color"], &[]);
    let text = &out.stdout;
    assert!(
        text.ends_with(
            "1 AI agent workflow risk, 0 credentials reachable in this job (1 ignored by .heldkeys.toml).\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("\nIgnored\n  1 finding ignored by ./.heldkeys.toml\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "  HK-WF-005 at .github/workflows/claude.yml: 1 finding; pinned via Renovate"
        ),
        "{text}"
    );
    // Only --details lists the findings themselves.
    assert!(!text.contains("HK-WF-005: pinned via Renovate"), "{text}");
    let details = ci(&repo(), &["--no-color", "--details"], &[]).stdout;
    let ignored = details
        .split("\nIgnored\n")
        .nth(1)
        .expect("an Ignored section");
    assert!(
        ignored.contains("    MEDIUM  AI agent action not pinned"),
        "{details}"
    );
    assert!(
        ignored.contains("HK-WF-005: pinned via Renovate"),
        "{details}"
    );
}

#[test]
fn no_ignore_and_no_config_show_everything() {
    for flag in ["--no-ignore", "--no-config"] {
        let out = ci(&repo(), &["--format", "json", flag], &[]);
        let v = json(&out);
        assert_eq!(rules(&v, "findings"), ["HK-WF-001", "HK-WF-005"], "{flag}");
        assert_eq!(v["suppressed"], serde_json::json!([]), "{flag}");
        assert!(!out.stderr.contains("expired"), "{flag}: {}", out.stderr);
        let text = ci(&repo(), &[flag], &[]).stdout;
        assert!(
            !text.contains("Ignored") && !text.contains("ignored by"),
            "{text}"
        );
    }
}

#[test]
fn explicit_config_replaces_the_project_file() {
    let hostile = fixture("config/hostile/config.toml");
    let out = ci(
        &repo(),
        &["--format", "json", "--config", hostile.to_str().unwrap()],
        &[],
    );
    let v = json(&out);
    // Both workflows match its catch-all `HK-WF-*` with `path = "*"`; the
    // project file's expired rule is not read, so nothing is said about it.
    assert_eq!(rules(&v, "findings"), Vec::<String>::new());
    assert_eq!(rules(&v, "suppressed"), ["HK-WF-001", "HK-WF-005"]);
    assert!(out.stderr.is_empty(), "{}", out.stderr);
    assert_eq!(out.code, 0);

    let missing = ci(&repo(), &["--config", "does-not-exist.toml"], &[]);
    assert_eq!(missing.code, 2);
    assert!(
        missing
            .stderr
            .contains("config file does-not-exist.toml does not exist")
    );
}

#[test]
fn invalid_configs_are_refused() {
    for (file, message) in [
        (
            "unknown-key",
            "ignore #1: unknown key `reasons`; expected rule, path, location, reason or expires",
        ),
        ("missing-reason", "ignore #1: `reason` is required"),
        (
            "broad",
            "ignore #1: `rule = \"HK-*\"` would ignore every finding",
        ),
        (
            "bad-date",
            "ignore #1: `expires` must be a date written YYYY-MM-DD",
        ),
        ("syntax", "syntax.toml: line 2: "),
    ] {
        let path = fixture(&format!("config/invalid/{file}.toml"));
        let out = ci(&repo(), &["--config", path.to_str().unwrap()], &[]);
        assert_eq!(out.code, 2, "{file}: {}", out.stdout);
        assert!(out.stdout.is_empty(), "{file}: {}", out.stdout);
        assert!(out.stderr.contains(message), "{file}: {}", out.stderr);
    }
}

#[test]
fn a_broken_project_file_stops_the_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo");
    copy_dir(&repo(), &dir);
    std::fs::copy(
        fixture("config/invalid/unknown-key.toml"),
        dir.join(".heldkeys.toml"),
    )
    .unwrap();
    let out = ci(&dir, &[], &[]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("./.heldkeys.toml: ignore #1: unknown key"),
        "{}",
        out.stderr
    );
    // --no-config and --no-ignore do not read it at all.
    assert_eq!(ci(&dir, &["--no-config"], &[]).code, 1);
    assert_eq!(ci(&dir, &["--no-ignore"], &[]).code, 1);
}

#[cfg(unix)]
#[test]
fn a_project_file_symlinked_out_of_the_tree_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo");
    copy_dir(&repo(), &dir);
    std::fs::remove_file(dir.join(".heldkeys.toml")).unwrap();
    std::os::unix::fs::symlink(
        fixture("config/hostile/config.toml"),
        dir.join(".heldkeys.toml"),
    )
    .unwrap();
    let out = ci(&dir, &[], &[]);
    assert_eq!(out.code, 2, "{}", out.stdout);
    assert!(
        out.stderr
            .contains("cannot read ./.heldkeys.toml: symlink leads outside"),
        "{}",
        out.stderr
    );
}

#[test]
fn user_config_applies_to_local_scans_only() {
    let home = fixture("config/home");
    let scan = run_in(&home, &repo(), &["--format", "json"], &[]);
    let v = json(&scan);
    assert_eq!(
        rules(&v, "findings"),
        Vec::<String>::new(),
        "{}",
        scan.stdout
    );
    let suppressed = v["suppressed"].as_array().unwrap();
    let sources: Vec<&str> = suppressed
        .iter()
        .map(|s| s["source"].as_str().unwrap())
        .collect();
    assert!(sources.contains(&"./.heldkeys.toml"), "{sources:?}");
    assert!(
        sources.contains(&"~/.config/heldkeys/config.toml"),
        "{sources:?}"
    );
    let text = run_in(&home, &repo(), &["--no-color"], &[]).stdout;
    assert!(
        text.ends_with("No credentials reachable from here (2 ignored by config).\n"),
        "{text}"
    );
    // Without the user config, the project's .env is reported.
    let v = json(&run_in(
        &fixture("empty"),
        &repo(),
        &["--format", "json"],
        &[],
    ));
    assert_eq!(rules(&v, "findings"), ["HK-DOTENV-001"]);
    assert_eq!(rules(&v, "suppressed"), ["HK-DOTENV-001"]);
    // `ci` never reads the home config: the runner's home is not yours.
    let v = json(&run_in(&home, &repo(), &["ci", "--format", "json"], &[]));
    assert!(
        v["suppressed"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["source"] == "./.heldkeys.toml")
    );
}

#[test]
fn preflight_applies_ignores_and_says_so() {
    let out = run_in(&fixture("config/home"), &repo(), &["preflight"], &[]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert_eq!(
        out.stdout,
        "heldkeys preflight: PASS, no credentials reachable (2 ignored by config)\n"
    );
}

#[test]
fn markdown_lists_ignores_and_expired_rules() {
    let md = ci(&repo(), &["--format", "markdown"], &[]).stdout;
    assert!(
        md.contains("**1 AI agent workflow risk, 0 credentials reachable in this job \\(1 ignored by .heldkeys.toml\\).**"),
        "{md}"
    );
    assert!(
        md.contains("### Ignored (1)\n\n1 finding ignored by ./.heldkeys.toml.\n"),
        "{md}"
    );
    assert!(
        md.contains("| `HK-WF-005` | `.github/workflows/claude.yml` | 1 | pinned via Renovate | `./.heldkeys.toml` | 2099-12-31 |"),
        "{md}"
    );
    assert!(
        md.contains(
            "- Expired on 2020-01-31, no longer applied: `HK-WF-001` in `./.heldkeys.toml`"
        ),
        "{md}"
    );
    assert!(
        md.contains("<details><summary>Ignored findings (1)</summary>"),
        "{md}"
    );
}

#[test]
fn sarif_marks_ignored_results_as_suppressed() {
    let v = json(&ci(&repo(), &["--format", "sarif"], &[]));
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    let open: Vec<&serde_json::Value> = results
        .iter()
        .filter(|r| r.get("suppressions").is_none())
        .collect();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0]["ruleId"], "HK-WF-001");
    let ignored = results.iter().find(|r| r["ruleId"] == "HK-WF-005").unwrap();
    assert_eq!(
        ignored["suppressions"],
        serde_json::json!([{
            "kind": "external",
            "status": "accepted",
            "justification": "pinned via Renovate",
        }])
    );
    assert_eq!(
        ignored["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        ".github/workflows/claude.yml"
    );
}

#[test]
fn a_pull_request_checkout_is_called_out() {
    let notice = |event: &str| {
        format!(
            "Ignore rules were read from ./.heldkeys.toml in the checkout of this {event} run, which the pull request can change."
        )
    };
    for event in ["pull_request", "pull_request_target", "issue_comment"] {
        let env = [("GITHUB_ACTIONS", "true"), ("GITHUB_EVENT_NAME", event)];
        let out = ci(&repo(), &["--no-color"], &env);
        let expected = notice(event);
        assert!(
            out.stdout
                .replace("\n    ", " ")
                .contains(&format!("Warning: {expected}")),
            "{event}: {}",
            out.stdout
        );
        // The verdict names who can change the file that left findings out.
        assert!(
            out.stdout
                .ends_with("(1 ignored by a file the pull request can change).\n"),
            "{event}: {}",
            out.stdout
        );
        // stderr, whatever the format.
        assert!(
            out.stderr
                .contains(&format!("heldkeys: warning: {expected}")),
            "{}",
            out.stderr
        );

        let md = ci(&repo(), &["--format", "markdown"], &env);
        assert!(
            md.stdout
                .contains(&format!("> **Warning:** {}", expected.replace('_', "\\_"))),
            "{}",
            md.stdout
        );
        assert!(md.stderr.contains(&expected));

        let json = ci(&repo(), &["--format", "json"], &env);
        assert!(json.stderr.contains(&expected));
        let v = serde_json::from_str::<serde_json::Value>(&json.stdout).unwrap();
        let notices = v["notices"].as_array().unwrap();
        assert_eq!(notices.len(), 1);
        assert!(notices[0].as_str().unwrap().starts_with(&expected));

        let sarif: serde_json::Value =
            serde_json::from_str(&ci(&repo(), &["--format", "sarif"], &env).stdout).unwrap();
        let n = &sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
        assert_eq!(n["level"], "warning");
        assert!(
            n["message"]["text"]
                .as_str()
                .unwrap()
                .starts_with(&expected)
        );

        // Named with --config, the checkout's own file is still the pull
        // request's; a copy from elsewhere (the default branch) is not.
        let own = repo().join(".heldkeys.toml");
        let out = ci(&repo(), &["--config", own.to_str().unwrap()], &env);
        assert!(out.stdout.contains("Warning:"), "{event}: {}", out.stdout);
        let base = fixture("config/hostile/config.toml");
        let out = ci(&repo(), &["--config", base.to_str().unwrap()], &env);
        assert!(!out.stdout.contains("Warning:"), "{event}: {}", out.stdout);
        assert!(
            !out.stderr.contains("warning: Ignore rules"),
            "{}",
            out.stderr
        );
    }
    let push = [("GITHUB_ACTIONS", "true"), ("GITHUB_EVENT_NAME", "push")];
    let out = ci(&repo(), &["--format", "json"], &push);
    assert!(!out.stdout.contains("Warning:") && !out.stderr.contains("checkout"));
    assert_eq!(json(&out)["notices"], serde_json::json!([]));
}

#[test]
fn a_gitlab_merge_request_and_a_baseline_in_the_checkout_are_called_out() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("repo");
    copy_dir(&repo(), &dir);
    let write = ci(
        &dir,
        &[
            "--write-baseline",
            dir.join("base.json").to_str().unwrap(),
            "--fail-on",
            "none",
            "--no-config",
            "--quiet",
        ],
        &[],
    );
    assert_eq!(write.code, 0, "{}", write.stderr);
    let env = [
        ("GITLAB_CI", "true"),
        ("CI_PIPELINE_SOURCE", "merge_request_event"),
    ];
    let base = dir.join("base.json");
    let out = ci(
        &dir,
        &["--no-color", "--baseline", base.to_str().unwrap()],
        &env,
    );
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(
        out.stderr.contains(
            "in the checkout of this merge request pipeline, which the merge request can change"
        ),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains("was read from the checkout of this merge request pipeline"),
        "{}",
        out.stderr
    );
    assert!(
        out.stdout.ends_with(
            "(1 ignored by a file the merge request can change, 1 in a baseline the merge request can change).\n"
        ),
        "{}",
        out.stdout
    );
    // A push pipeline reads the same files without a warning.
    let push = [("GITLAB_CI", "true"), ("CI_PIPELINE_SOURCE", "push")];
    let out = ci(&dir, &["--baseline", base.to_str().unwrap()], &push);
    assert!(
        out.stderr.is_empty() || !out.stderr.contains("checkout"),
        "{}",
        out.stderr
    );
    assert!(out.stdout.contains("in the baseline)"), "{}", out.stdout);
}

/// Writes a baseline from one copy of a project and applies it to another
/// copy elsewhere: the locations match because they are compared relative to
/// the scanned directory and without line numbers.
#[test]
fn baseline_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");
    let source = fixture("workflows/untrusted-trigger");
    copy_dir(&source, &first);
    copy_dir(&source, &second);
    let baseline = tmp.path().join("heldkeys-baseline.json");
    let baseline_arg = baseline.to_str().unwrap();

    let before = ci(&first, &["--format", "json"], &[]);
    assert_eq!(
        before.code, 1,
        "the fixture fails on High: {}",
        before.stderr
    );
    let total = json(&before)["findings"].as_array().unwrap().len();

    let write = ci(
        &first,
        &[
            "--write-baseline",
            baseline_arg,
            "--fail-on",
            "none",
            "--quiet",
        ],
        &[],
    );
    assert_eq!(write.code, 0, "{}", write.stderr);
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(written["schema"], heldkeys::JSON_SCHEMA);
    assert_eq!(written["findings"].as_array().unwrap().len(), total);

    // Every finding is in the baseline: the run passes, and says why.
    let after = ci(
        &second,
        &["--format", "json", "--baseline", baseline_arg],
        &[],
    );
    assert_eq!(after.code, 0, "{}", after.stdout);
    let v = json(&after);
    assert_eq!(v["findings"], serde_json::json!([]));
    assert_eq!(v["summary"]["in_baseline"], total);
    assert!(
        v["suppressed"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["by"] == "baseline")
    );
    let text = ci(&second, &["--baseline", baseline_arg], &[]).stdout;
    assert!(
        text.ends_with(&format!(
            "No AI agent workflow risks and no credentials reachable in this job ({total} in the baseline).\n"
        )),
        "{text}"
    );

    // Lines moving does not make a finding new.
    for entry in std::fs::read_dir(second.join(".github/workflows")).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("# moved down\n\n{text}")).unwrap();
    }
    assert_eq!(ci(&second, &["--baseline", baseline_arg], &[]).code, 0);

    // A new risk still fails, and only it is reported.
    std::fs::copy(
        repo().join(".github/workflows/triage.yml"),
        second.join(".github/workflows/new-agent.yml"),
    )
    .unwrap();
    let new = ci(
        &second,
        &["--format", "json", "--baseline", baseline_arg],
        &[],
    );
    assert_eq!(new.code, 1, "{}", new.stdout);
    let v = json(&new);
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0]["location"]
            .as_str()
            .unwrap()
            .starts_with(".github/workflows/new-agent.yml:")
    );
    // --no-ignore shows everything again.
    let all = json(&ci(
        &second,
        &[
            "--format",
            "json",
            "--baseline",
            baseline_arg,
            "--no-ignore",
        ],
        &[],
    ));
    assert_eq!(all["findings"].as_array().unwrap().len(), total + 1);
}

/// In `scan` mode project files are reported under the home directory
/// (`~/a/.env`); a baseline written in `~/a` still matches in `~/b`.
#[test]
fn baseline_locations_are_relative_to_the_scanned_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    for name in ["a", "b"] {
        std::fs::create_dir_all(home.join(name)).unwrap();
        std::fs::copy(repo().join(".env"), home.join(name).join(".env")).unwrap();
    }
    let baseline = home.join("base.json");
    let b = baseline.to_str().unwrap();
    let write = run_in(
        home,
        &home.join("a"),
        &["--write-baseline", b, "--quiet"],
        &[],
    );
    assert_eq!(write.code, 0, "{}", write.stderr);
    let written = std::fs::read_to_string(&baseline).unwrap();
    assert!(written.contains("\"origin\": \"~/a\""), "{written}");
    assert!(
        written.contains("\"location\": \"~/a/.env: OPENAI_API_KEY\""),
        "{written}"
    );
    let v = json(&run_in(
        home,
        &home.join("b"),
        &["--format", "json", "--baseline", b],
        &[],
    ));
    assert_eq!(v["findings"], serde_json::json!([]), "{v}");
    assert_eq!(v["summary"]["in_baseline"], 1);
    // A different token in the same place is a new finding.
    std::fs::write(
        home.join("b/.env"),
        "OPENAI_API_KEY=sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE0904\n",
    )
    .unwrap();
    let v = json(&run_in(
        home,
        &home.join("b"),
        &["--format", "json", "--baseline", b],
        &[],
    ));
    assert_eq!(rules(&v, "findings"), ["HK-DOTENV-001"]);
}

#[test]
fn bad_baselines_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.json");
    let out = ci(&repo(), &["--baseline", missing.to_str().unwrap()], &[]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("does not exist"), "{}", out.stderr);
    let other = tmp.path().join("other.json");
    std::fs::write(&other, "{\"version\": \"2.1.0\", \"runs\": []}").unwrap();
    let out = ci(&repo(), &["--baseline", other.to_str().unwrap()], &[]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("is not a heldkeys JSON report"),
        "{}",
        out.stderr
    );
}

/// A job id is text the pull request picks: a trusted rule for
/// `path = "*fixtures*"` must not hide a new agent job named `fixtures-bot`,
/// whether the rule comes from --config or the project file.
#[test]
fn path_patterns_see_the_file_not_the_job_id() {
    let dir = fixture("config/job-named-fixtures");
    let trusted = dir.join(".heldkeys.toml");
    for args in [
        vec!["--format", "json"],
        vec!["--format", "json", "--config", trusted.to_str().unwrap()],
    ] {
        let out = ci(&dir, &args, &[]);
        assert_eq!(out.code, 1, "{}", out.stdout);
        let v = json(&out);
        assert_eq!(rules(&v, "findings"), ["HK-WF-001", "HK-WF-005"]);
        assert_eq!(v["suppressed"], serde_json::json!([]));
    }
}

/// The baseline accepted a gated agent (Medium); the pull request lets
/// anyone trigger it (High). Same rule, same place, no fingerprint: it is
/// still reported, and says what it was.
#[test]
fn a_baselined_finding_that_got_worse_still_fails() {
    let dir = fixture("config/escalated");
    let base = dir.join("base.json");
    let out = ci(
        &dir,
        &["--format", "json", "--baseline", base.to_str().unwrap()],
        &[],
    );
    assert_eq!(out.code, 1, "{}", out.stdout);
    let v = json(&out);
    assert_eq!(v["suppressed"], serde_json::json!([]));
    let f = &v["findings"][0];
    assert_eq!(f["rule"], "HK-WF-001");
    assert_eq!(f["severity"], "high");
    assert!(
        f["detail"]
            .as_str()
            .unwrap()
            .ends_with("; was medium in the baseline"),
        "{f}"
    );
    // Written again from the current run, the baseline accepts it.
    let tmp = tempfile::tempdir().unwrap();
    let fresh = tmp.path().join("base.json");
    let fresh = fresh.to_str().unwrap();
    ci(
        &dir,
        &["--write-baseline", fresh, "--fail-on", "none", "--quiet"],
        &[],
    );
    assert_eq!(ci(&dir, &["--baseline", fresh], &[]).code, 0);
}

/// A finding that is in no file (an environment variable) has no path to
/// match; `location` names it exactly.
#[test]
fn location_targets_a_finding_without_a_file() {
    let tmp = tempfile::tempdir().unwrap();
    let env = [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_TOKEN", "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000905"),
    ];
    let run = |config: &str| {
        let file = tmp.path().join("cfg.toml");
        std::fs::write(&file, config).unwrap();
        json(&ci(
            &fixture("empty"),
            &["--format", "json", "--config", file.to_str().unwrap()],
            &env,
        ))
    };
    let v = run(
        "[[ignore]]\nrule = \"HK-CI-002\"\nlocation = \"env: GITHUB_TOKEN\"\nreason = \"read-only token\"\n",
    );
    assert_eq!(rules(&v, "suppressed"), ["HK-CI-002"]);
    // A path never matches it, not even one that spells the location.
    let v = run("[[ignore]]\nrule = \"HK-CI-002\"\npath = \"env: GITHUB_TOKEN\"\nreason = \"r\"\n");
    assert_eq!(v["suppressed"], serde_json::json!([]));
    let v = run("[[ignore]]\nrule = \"HK-CI-002\"\nlocation = \"env: GITHUB\"\nreason = \"r\"\n");
    assert_eq!(v["suppressed"], serde_json::json!([]));
}
