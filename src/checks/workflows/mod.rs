//! `workflows`: static analysis of `.github/workflows/*.yml` for AI agent steps.
//!
//! The question for every agent step: if text the agent reads (an issue, a PR,
//! a comment, a file in the checkout) carries a prompt injection, what can the
//! hijacked agent do with what this step hands it? We look at
//!
//! - the triggers: can an outsider start the workflow and feed it text?
//! - the job's effective `permissions` (the GITHUB_TOKEN the agent holds);
//! - the secrets the step receives through `with:` and `env:`;
//! - whether it runs in a checkout of the PR head (attacker-controlled files);
//! - whether the agent action is pinned, and whether it may run any shell command.
//!
//! Local reusable workflows are followed: a called workflow is analysed with
//! its caller's triggers, permissions and secrets (see `reusable`), once per
//! distinct caller context (see `calls`).
//!
//! Trigger semantics follow zizmor (https://github.com/zizmorcore/zizmor),
//! the reference linter for GitHub Actions. We deliberately do not repeat its
//! generic audits (template injection, artipacked, unpinned non-agent
//! actions...): run zizmor for those. These rules are only about agent steps.
//!
//! The pieces live in submodules:
//! - `agents`: the maintained list of agent actions and CLIs;
//! - `triggers`: untrusted events, `permissions:` and actor gates;
//! - `secrets`: which secrets reach a step, and which are more than it needs;
//! - `shell`: settings that let an agent run any command;
//! - `checkout`: steps that check out the PR head;
//! - `reusable`: what a called workflow inherits from its callers;
//! - `calls`: following local calls once per caller context, with a budget;
//! - `job`: one job's agent steps, and what each one holds;
//! - `rules`: one function per HK-WF rule, turning the above into findings.

mod agents;
mod calls;
mod checkout;
mod job;
mod reusable;
mod rules;
mod script;
mod secrets;
mod shell;
mod triggers;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Finding, Rule};
use crate::fsutil;
use crate::sanitize::clip;
use crate::yaml::{self, Yaml};

use calls::CallGraph;
use job::{Emit, analyze_job};
use reusable::{JobCall, Reach, job_call, local_workflow};
use triggers::{needs_gated_jobs, triggers, untrusted_triggers};

pub use triggers::UNTRUSTED_TRIGGERS;

pub struct WorkflowsCheck;

const ID: &str = "workflows";

/// A workflow file that was read and parsed.
struct WorkflowFile {
    /// The file name, e.g. `review.yml`.
    name: String,
    /// Repo-relative, so SARIF can point at it and text output stays short.
    file: String,
    doc: Yaml,
    lines: BTreeMap<String, usize>,
    /// Jobs that only run when an actor gate on a job they need let it
    /// through (`triggers::needs_gated_jobs`).
    needs_gated: BTreeSet<String>,
}

impl WorkflowFile {
    /// `file:line path`, e.g. `.github/workflows/x.yml:12 jobs.review`.
    /// The file name and the path (which holds a job id) come from the
    /// repository, so each is clipped to `sanitize::MAX_SHOWN` characters.
    fn position(&self, path: &str) -> String {
        let (file, shown) = (clip(&self.file), clip(path));
        match self.lines.get(path) {
            Some(line) => format!("{file}:{line} {shown}"),
            None => format!("{file} {shown}"),
        }
    }

    fn location(&self, path: &str, what: &str) -> String {
        format!("{} ({})", self.position(path), clip(what))
    }

    /// Only ever started by another workflow.
    fn only_workflow_call(&self) -> bool {
        let on = triggers(&self.doc);
        !on.is_empty() && on.iter().all(|t| t == "workflow_call")
    }
}

/// Every workflow file in the directory: the ones that parsed, and an Info
/// finding for each one that did not.
struct Workflows {
    files: Vec<WorkflowFile>,
    /// Files that exist but could not be analysed (already reported).
    failed: BTreeSet<String>,
    findings: Vec<Finding>,
}

impl Workflows {
    fn get(&self, name: &str) -> Option<&WorkflowFile> {
        self.files.iter().find(|f| f.name == name)
    }
}

impl Check for WorkflowsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Static analysis of .github/workflows: AI agent steps (also through local reusable workflows), the secrets and permissions they get, untrusted triggers, PR-head checkouts, pinning and shell grants."
    }

    fn rules(&self) -> &'static [Rule] {
        rules::RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let all = load_all(&ctx.cwd);
        // Workflows some local workflow calls.
        let called: BTreeSet<&str> = all
            .files
            .iter()
            .flat_map(|wf| yaml::entries(&wf.doc["jobs"]))
            .filter_map(|(_, job)| yaml::str_at(job, "uses").and_then(local_workflow))
            .collect();
        let mut findings = all.findings.clone();
        let mut calls = CallGraph::new(&all);
        for wf in &all.files {
            let reach = Reach::top(&wf.name, untrusted_triggers(&wf.doc));
            let emit = if wf.only_workflow_call() && called.contains(wf.name.as_str()) {
                Emit::PinningOnly
            } else {
                Emit::All
            };
            for (job_id, job) in yaml::entries(&wf.doc["jobs"]) {
                match job_call(job) {
                    JobCall::None => findings.extend(analyze_job(wf, &reach, emit, job_id, job)),
                    // A pure callee's calls are followed when its callers are.
                    _ if emit == Emit::PinningOnly => {}
                    _ => calls.follow(wf, &reach, None, job_id, job),
                }
            }
        }
        findings.extend(calls.into_findings());
        // The same finding can be reached from more than one place.
        let mut seen = BTreeSet::new();
        findings.retain(|f| seen.insert(format!("{f:?}")));
        findings
    }
}

fn load_all(cwd: &Path) -> Workflows {
    let dir = cwd.join(".github").join("workflows");
    let mut all = Workflows {
        files: Vec::new(),
        failed: BTreeSet::new(),
        findings: Vec::new(),
    };
    for path in fsutil::list_dir(&dir) {
        let name = fsutil::file_name(&path);
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        match load_file(cwd, &path, &name) {
            Ok(Some(wf)) => all.files.push(wf),
            Ok(None) => {}
            Err(reason) => {
                let file = format!(".github/workflows/{}", clip(&name));
                all.findings
                    .push(rules::not_analysed(&file, &file, &reason));
                all.failed.insert(name);
            }
        }
    }
    all
}

/// Reads and parses one workflow, refusing symlinks that lead out of the
/// working tree (a repository controls its own files, not ours) and YAML
/// over the alias and size budget. `Ok(None)` for files with nothing to
/// analyse (missing, empty, only comments, a directory); `Err` with the
/// reason for files that may hold agent steps we could not see.
fn load_file(root: &Path, path: &Path, name: &str) -> Result<Option<WorkflowFile>, String> {
    let text = match fsutil::try_read_text_within(root, path, fsutil::MAX_FILE_BYTES) {
        Ok(Some(text)) => text,
        Ok(None) | Err(fsutil::Unreadable::NotAFile) => return Ok(None),
        Err(reason) => return Err(reason.to_string()),
    };
    let blank = text.lines().all(|l| {
        let l = l.trim();
        l.is_empty() || l.starts_with('#') || l == "---"
    });
    if blank {
        return Ok(None);
    }
    let doc = yaml::load_checked(&text)?;
    if doc.as_hash().is_none() {
        return Err("not a YAML mapping, so not a workflow".to_string());
    }
    Ok(Some(WorkflowFile {
        name: name.to_string(),
        file: format!(".github/workflows/{name}"),
        lines: yaml::line_index(&text),
        needs_gated: needs_gated_jobs(&doc),
        doc,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, fixture, write};
    use crate::finding::Severity;

    fn fixture_findings(case: &str) -> Vec<Finding> {
        let dir = fixture(&format!("workflows/{case}"));
        WorkflowsCheck.run(&Context::new(
            dir.clone(),
            dir.clone(),
            dir,
            BTreeMap::new(),
        ))
    }

    fn rules_of(findings: &[Finding]) -> Vec<&str> {
        let mut r: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        r.sort();
        r.dedup();
        r
    }

    fn inline(yaml: &str) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/agent.yml", yaml);
        WorkflowsCheck.run(&ctx_with_env(dir.path(), &[]))
    }

    fn inline_files(files: &[(&str, &str)]) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        for (name, yaml) in files {
            write(dir.path(), &format!(".github/workflows/{name}"), yaml);
        }
        WorkflowsCheck.run(&ctx_with_env(dir.path(), &[]))
    }

    #[test]
    fn local_reusable_workflows_run_with_the_callers_trigger_token_and_secrets() {
        let f = fixture_findings("reusable");
        let found: Vec<(&str, Severity, &str)> = f
            .iter()
            .map(|f| (f.rule, f.severity, f.location.split(' ').next().unwrap()))
            .collect();
        let mut expected = vec![
            (
                "HK-WF-001",
                Severity::High,
                ".github/workflows/gemini-dispatch.yml:15",
            ),
            (
                "HK-WF-004",
                Severity::Medium,
                ".github/workflows/gemini-dispatch.yml:15",
            ),
            (
                "HK-WF-005",
                Severity::Medium,
                ".github/workflows/gemini-review.yml:19",
            ),
            (
                "HK-WF-001",
                Severity::Medium,
                ".github/workflows/triage-caller.yml:8",
            ),
        ];
        let mut found_sorted = found.clone();
        found_sorted.sort_by_key(|x| format!("{x:?}"));
        expected.sort_by_key(|x| format!("{x:?}"));
        assert_eq!(found_sorted, expected, "{f:#?}");

        let wf1 = f
            .iter()
            .find(|f| f.rule == "HK-WF-001" && f.severity == Severity::High)
            .unwrap();
        // The location names both files: the caller job, then the agent step.
        assert_eq!(
            wf1.location,
            ".github/workflows/gemini-dispatch.yml:15 jobs.review -> .github/workflows/gemini-review.yml:19 jobs.review.steps[1] (uses: google-github-actions/run-gemini-cli@v0)"
        );
        let d = wf1.detail.as_deref().unwrap();
        assert!(
            d.contains("on pull_request_review_comment, issue_comment, issues"),
            "{d}"
        );
        assert!(
            d.contains("issues: write, pull-requests: write, id-token: write"),
            "{d}"
        );
        assert!(d.contains("secrets GEMINI_API_KEY"), "{d}");
        let wf4 = f.iter().find(|f| f.rule == "HK-WF-004").unwrap();
        assert!(
            wf4.detail
                .as_deref()
                .unwrap()
                .contains("every repository secret through secrets: inherit at .github/workflows/gemini-dispatch.yml:15 jobs.review"),
            "{wf4:#?}"
        );
        // Only the passed secret, and the caller's read-only token.
        let triage = f
            .iter()
            .find(|f| f.location.contains("triage-caller.yml"))
            .unwrap();
        let d = triage.detail.as_deref().unwrap();
        assert!(
            d.contains("holds a read-only token and secrets OPENAI_API_KEY"),
            "{d}"
        );
        assert!(!d.contains("AWS"), "{d}");
    }

    #[test]
    fn caller_permissions_cap_the_callee() {
        let callee = "on: workflow_call\njobs:\n  fix:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: openai/codex-action@0123456789abcdef0123456789abcdef01234567\n        with:\n          openai-api-key: ${{ secrets.OPENAI_API_KEY }}\n          sandbox: danger-full-access\n";
        // A write-all caller: the callee, which sets nothing, inherits it.
        let f = inline_files(&[
            (
                "caller.yml",
                "on: issue_comment\njobs:\n  go:\n    uses: ./.github/workflows/fix.yml\n    permissions: write-all\n    secrets: inherit\n",
            ),
            ("fix.yml", callee),
        ]);
        let rules = rules_of(&f);
        assert_eq!(
            rules,
            vec!["HK-WF-001", "HK-WF-003", "HK-WF-004", "HK-WF-006"],
            "{f:#?}"
        );
        assert!(
            f.iter()
                .all(|f| f.severity == Severity::High || f.rule == "HK-WF-004")
        );
        // A read-only caller: no shell finding, and no default-permissions one.
        let f = inline_files(&[
            (
                "caller.yml",
                "on: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  go:\n    uses: ./.github/workflows/fix.yml\n    secrets:\n      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n",
            ),
            ("fix.yml", callee),
        ]);
        assert!(f.is_empty(), "{f:#?}");
        // The same callee on its own, called by nobody: read as a workflow.
        let f = inline_files(&[("fix.yml", callee)]);
        assert_eq!(rules_of(&f), vec!["HK-WF-003", "HK-WF-006"], "{f:#?}");
    }

    #[test]
    fn caller_gates_count() {
        let f = inline_files(&[
            (
                "caller.yml",
                "on: issue_comment\njobs:\n  go:\n    if: github.event.comment.author_association == 'OWNER'\n    uses: ./.github/workflows/agent.yml\n    permissions:\n      contents: write\n    secrets: inherit\n",
            ),
            (
                "agent.yml",
                "on: workflow_call\njobs:\n  a:\n    steps:\n      - run: codex exec 'fix'\n",
            ),
        ]);
        let wf1 = f.iter().find(|f| f.rule == "HK-WF-001").unwrap();
        assert_eq!(wf1.severity, Severity::Medium, "{wf1:#?}");
    }

    #[test]
    fn gates_on_needed_jobs_count() {
        let wf1 = |yaml: &str| {
            let f = inline(yaml);
            f.into_iter()
                .find(|f| f.rule == "HK-WF-001")
                .unwrap_or_else(|| panic!("no HK-WF-001 for {yaml}"))
        };
        let workflow = |agent_if: &str, middle_if: &str| {
            format!(
                "on: issue_comment\npermissions:\n  contents: write\njobs:\n  dispatch:\n    if: contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.comment.author_association)\n    runs-on: x\n    steps:\n      - run: echo ok\n  middle:\n    needs: dispatch\n{middle_if}    runs-on: x\n    steps:\n      - run: echo ok\n  agent:\n    needs: [middle]\n{agent_if}    runs-on: x\n    steps:\n      - run: codex exec 'fix'\n"
            )
        };
        // Skipped with the gated job, two needs away.
        let gated = wf1(&workflow("", ""));
        assert_eq!(gated.severity, Severity::Medium, "{gated:#?}");
        assert!(
            gated
                .detail
                .as_deref()
                .unwrap()
                .contains("gated by an if: on the actor in a job it needs"),
            "{gated:#?}"
        );
        // A status function lets the job run when the gated job was skipped.
        for status in ["always()", "${{ !cancelled() }}", "failure()"] {
            let on_agent = format!("    if: \"{status}\"\n");
            let f = wf1(&workflow(&on_agent, ""));
            assert_eq!(f.severity, Severity::High, "{status} on the agent: {f:#?}");
            let f = wf1(&workflow("", &on_agent));
            assert_eq!(f.severity, Severity::High, "{status} in between: {f:#?}");
        }
        // An outputs check is no status function: still gated.
        let f = wf1(&workflow("    if: needs.middle.outputs.go == 'yes'\n", ""));
        assert_eq!(f.severity, Severity::Medium, "{f:#?}");
    }

    #[test]
    fn gates_on_needed_jobs_reach_called_workflows() {
        let caller = |dispatch_if: &str, review_if: &str| {
            format!(
                "on: issue_comment\njobs:\n  dispatch:\n    if: {dispatch_if}\n    runs-on: x\n    steps:\n      - run: echo ok\n  review:\n    needs: dispatch\n    if: {review_if}\n    uses: ./.github/workflows/agent.yml\n    permissions:\n      contents: write\n    secrets: inherit\n"
            )
        };
        let agent = "on: workflow_call\njobs:\n  a:\n    steps:\n      - run: codex exec 'fix'\n";
        let wf1 = |caller: &str| {
            inline_files(&[("caller.yml", caller), ("agent.yml", agent)])
                .into_iter()
                .find(|f| f.rule == "HK-WF-001")
                .unwrap()
        };
        let owner = "github.event.comment.author_association == 'OWNER'";
        let f = wf1(&caller(owner, "needs.dispatch.outputs.command == 'review'"));
        assert_eq!(f.severity, Severity::Medium, "{f:#?}");
        let f = wf1(&caller(owner, "always()"));
        assert_eq!(f.severity, Severity::High, "{f:#?}");
        // Not a gate: `null == false` holds on comment events.
        let f = wf1(&caller(
            "github.event.pull_request.head.repo.fork == false",
            "success()",
        ));
        assert_eq!(f.severity, Severity::High, "{f:#?}");
    }

    #[test]
    fn run_gemini_cli_dispatch_template_is_gated() {
        let f = fixture_findings("gemini-dispatch");
        let wf1: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-WF-001").collect();
        assert_eq!(wf1.len(), 1, "{f:#?}");
        assert_eq!(wf1[0].severity, Severity::Medium, "{f:#?}");
        assert!(
            wf1[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("gated by an if: on the actor in a job it needs"),
            "{f:#?}"
        );
        assert!(!f.iter().any(|f| f.severity == Severity::High), "{f:#?}");
    }

    #[test]
    fn call_cycles_depth_and_missing_files_are_reported() {
        let call = |next: &str| {
            format!(
                "on: [workflow_call, issues]\njobs:\n  next:\n    uses: ./.github/workflows/{next}\n    secrets: inherit\n"
            )
        };
        let f = inline_files(&[("a.yml", &call("b.yml")), ("b.yml", &call("a.yml"))]);
        assert!(!f.is_empty());
        assert!(f.iter().all(|f| f.rule == "HK-WF-007"), "{f:#?}");
        assert!(
            f.iter().any(|f| f
                .detail
                .as_deref()
                .unwrap()
                .contains("called in a cycle (a.yml -> b.yml -> a.yml)")),
            "{f:#?}"
        );

        let agent = "on: workflow_call\njobs:\n  a:\n    steps:\n      - run: claude -p hi --dangerously-skip-permissions\n";
        let deep = inline_files(&[
            (
                "w1.yml",
                "on: issues\npermissions: write-all\njobs:\n  next:\n    uses: ./.github/workflows/w2.yml\n",
            ),
            (
                "w2.yml",
                &call("w3.yml").replace("[workflow_call, issues]", "workflow_call"),
            ),
            (
                "w3.yml",
                &call("w4.yml").replace("[workflow_call, issues]", "workflow_call"),
            ),
            (
                "w4.yml",
                &call("w5.yml").replace("[workflow_call, issues]", "workflow_call"),
            ),
            ("w5.yml", agent),
        ]);
        let info: Vec<&Finding> = deep.iter().filter(|f| f.rule == "HK-WF-007").collect();
        assert_eq!(info.len(), 1, "{deep:#?}");
        assert!(info[0].location.starts_with(".github/workflows/w4.yml"));
        assert!(
            info[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("more than 3 reusable-workflow calls deep")
        );

        // Three calls deep is still followed.
        let f = inline_files(&[
            (
                "w1.yml",
                "on: issues\npermissions: write-all\njobs:\n  next:\n    uses: ./.github/workflows/w2.yml\n",
            ),
            (
                "w2.yml",
                &call("w3.yml").replace("[workflow_call, issues]", "workflow_call"),
            ),
            (
                "w3.yml",
                &call("w4.yml").replace("[workflow_call, issues]", "workflow_call"),
            ),
            ("w4.yml", agent),
        ]);
        let wf1 = f.iter().find(|f| f.rule == "HK-WF-001").unwrap();
        assert!(wf1.location.starts_with(".github/workflows/w1.yml:4 jobs.next -> .github/workflows/w2.yml:3 jobs.next -> .github/workflows/w3.yml:3 jobs.next -> .github/workflows/w4.yml:5"), "{wf1:#?}");

        let f = inline_files(&[("a.yml", &call("gone.yml"))]);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(
            f[0].detail
                .as_deref()
                .unwrap()
                .starts_with("could not analyse .github/workflows/gone.yml:")
        );
    }

    #[test]
    fn reusable_fan_out_is_analysed_once_per_context() {
        // a -> 30 jobs -> b -> 30 jobs -> c -> 30 jobs -> d with 30 agent
        // jobs: 810,000 agent-step visits if every call chain is walked.
        let started = std::time::Instant::now();
        let f = fixture_findings("fanout");
        let elapsed = started.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
        // One finding per agent job and rule (001, 003, 004, 005, 006).
        assert_eq!(f.len(), 150, "{:#?}", &f[..3.min(f.len())]);
        for rule in [
            "HK-WF-001",
            "HK-WF-003",
            "HK-WF-004",
            "HK-WF-005",
            "HK-WF-006",
        ] {
            assert_eq!(f.iter().filter(|x| x.rule == rule).count(), 30, "{rule}");
        }
        let wf1 = f
            .iter()
            .find(|x| x.rule == "HK-WF-001" && x.location.contains("jobs.k7.steps[0]"))
            .unwrap();
        // claude-code-action checks the actor's write access itself.
        assert_eq!(wf1.severity, Severity::Medium);
        assert!(
            wf1.location.starts_with(".github/workflows/d.yml:"),
            "{wf1:#?}"
        );
        let d = wf1.detail.as_deref().unwrap();
        assert!(
            d.ends_with(
                "; .github/workflows/d.yml is reached from 30 callers: .github/workflows/c.yml:4 jobs.j0, .github/workflows/c.yml:8 jobs.j1, .github/workflows/c.yml:12 jobs.j2 +27 more"
            ),
            "{d}"
        );
    }

    #[test]
    fn callers_in_the_same_context_share_one_finding() {
        let caller = |job: &str| {
            format!(
                "on: issues\npermissions: write-all\njobs:\n  {job}:\n    uses: ./.github/workflows/agent.yml\n"
            )
        };
        let agent = "on: workflow_call\njobs:\n  a:\n    steps:\n      - run: claude -p hi --dangerously-skip-permissions\n";
        let f = inline_files(&[
            ("one.yml", &caller("first")),
            ("two.yml", &caller("second")),
            ("agent.yml", agent),
        ]);
        let wf1: Vec<&Finding> = f.iter().filter(|x| x.rule == "HK-WF-001").collect();
        assert_eq!(wf1.len(), 1, "{f:#?}");
        assert!(
            wf1[0]
                .location
                .starts_with(".github/workflows/agent.yml:5 jobs.a.steps[0]")
        );
        assert!(
            wf1[0].detail.as_deref().unwrap().ends_with(
                "; .github/workflows/agent.yml is reached from 2 callers: .github/workflows/one.yml:4 jobs.first, .github/workflows/two.yml:4 jobs.second"
            ),
            "{f:#?}"
        );
        // A read-only caller is a different context: reported on its own,
        // with its own chain.
        let f = inline_files(&[
            ("one.yml", &caller("first")),
            (
                "two.yml",
                &caller("second").replace("write-all", "read-all"),
            ),
            ("agent.yml", agent),
        ]);
        assert!(f.iter().any(|x| {
            x.rule == "HK-WF-006"
                && x.location
                    .starts_with(".github/workflows/one.yml:4 jobs.first -> ")
        }));
        assert!(!f.iter().any(|x| x.location.contains("two.yml")), "{f:#?}");
    }

    #[test]
    fn called_job_visits_are_capped() {
        // 60 callers, each passing a differently named secret (60 contexts), into a
        // workflow with 40 jobs: 2,400 job visits.
        let mut caller = String::from("on: issue_comment\npermissions: write-all\njobs:\n");
        for i in 0..60 {
            caller.push_str(&format!(
                "  c{i}:\n    uses: ./.github/workflows/callee.yml\n    secrets:\n      KEY_{i}: ${{{{ secrets.FAKE_{i} }}}}\n"
            ));
        }
        let mut callee = String::from("on: workflow_call\njobs:\n");
        for i in 0..40 {
            callee.push_str(&format!(
                "  a{i}:\n    steps:\n      - run: claude -p hi\n        env:\n          K: ${{{{ secrets.KEY_{i} }}}}\n"
            ));
        }
        let started = std::time::Instant::now();
        let f = inline_files(&[("caller.yml", &caller), ("callee.yml", &callee)]);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let capped: Vec<&Finding> = f
            .iter()
            .filter(|x| {
                x.detail
                    .as_deref()
                    .unwrap_or("")
                    .contains("more than 2000 jobs")
            })
            .collect();
        assert_eq!(capped.len(), 1, "{capped:#?}");
        assert_eq!(capped[0].rule, "HK-WF-007");
        assert_eq!(capped[0].severity, Severity::Info);
        // 50 contexts x 40 jobs fit the budget; each gives a few findings.
        assert!(f.len() < 2_000 * 4, "{}", f.len());
    }

    #[test]
    fn local_calls_outside_the_workflows_directory_are_reported() {
        let f = inline_files(&[(
            "a.yml",
            "on: issue_comment\njobs:\n  up:\n    uses: ./.github/workflows/../../evil.yml\n  abs:\n    uses: /etc/passwd.yml\n  dot:\n    uses: ./.github/workflows/.\n  remote:\n    uses: octo/repo/.github/workflows/x.yml@v1\n",
        )]);
        assert_eq!(f.len(), 3, "{f:#?}");
        for (job, uses) in [
            ("up", "./.github/workflows/../../evil.yml"),
            ("abs", "/etc/passwd.yml"),
            ("dot", "./.github/workflows/."),
        ] {
            let found = f
                .iter()
                .find(|x| x.location.ends_with(&format!("jobs.{job}")))
                .unwrap_or_else(|| panic!("{job}: {f:#?}"));
            assert_eq!(found.rule, "HK-WF-007");
            assert_eq!(found.severity, Severity::Info);
            assert_eq!(
                found.detail.as_deref().unwrap(),
                format!(
                    "could not analyse {uses}: local reusable workflow outside .github/workflows not followed"
                )
            );
        }
    }

    #[test]
    fn titles_fit_the_text_report_column() {
        let mut titles = BTreeSet::new();
        for case in [
            "untrusted-trigger",
            "pr-head-checkout",
            "permissions",
            "secrets",
            "unpinned",
            "shell",
            "reusable",
            "fanout",
        ] {
            titles.extend(fixture_findings(case).into_iter().map(|f| f.title));
        }
        titles.extend(inline("on: [\n").into_iter().map(|f| f.title));
        titles.extend(
            inline("on: push\njobs:\n  a:\n    steps:\n      - run: claude --dangerously-skip-permissions\n")
                .into_iter()
                .map(|f| f.title),
        );
        assert!(titles.len() >= 8, "{titles:?}");
        for title in titles {
            assert!(title.chars().count() <= 44, "{title}");
        }
    }

    #[test]
    fn safe_agent_workflow_has_no_findings() {
        let f = fixture_findings("safe");
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn untrusted_trigger_with_write_token() {
        let f = fixture_findings("untrusted-trigger");
        let wf1: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-WF-001").collect();
        assert_eq!(wf1.len(), 4, "{f:#?}");
        let write = wf1
            .iter()
            .find(|f| f.location.contains("issue-write.yml"))
            .unwrap();
        assert_eq!(write.severity, Severity::High);
        assert_eq!(
            write.location,
            ".github/workflows/issue-write.yml:18 jobs.claude.steps[1] (uses: anthropics/claude-code-action@0123456)"
        );
        assert!(write.detail.as_deref().unwrap().contains("issue_comment"));
        let read = wf1
            .iter()
            .find(|f| f.location.contains("issue-read.yml"))
            .unwrap();
        assert_eq!(read.severity, Severity::Medium);
        let gated = wf1
            .iter()
            .find(|f| f.location.contains("gated.yml"))
            .unwrap();
        assert_eq!(gated.severity, Severity::Medium);
        let negative = wf1
            .iter()
            .find(|f| f.location.contains("not-the-bot.yml"))
            .unwrap();
        assert_eq!(negative.severity, Severity::High);
        assert!(!negative.detail.as_deref().unwrap().contains("gated"));
        assert_eq!(rules_of(&f), vec!["HK-WF-001"]);
    }

    #[test]
    fn pr_head_checkout_before_agent() {
        let f = fixture_findings("pr-head-checkout");
        let wf2: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-WF-002").collect();
        assert_eq!(wf2.len(), 3, "{f:#?}");
        assert!(wf2.iter().all(|f| f.severity == Severity::High));
        assert!(wf2.iter().any(|f| {
            f.location.contains("prt.yml")
                && f.detail
                    .as_deref()
                    .unwrap()
                    .contains("github.event.pull_request.head.sha")
        }));
        assert!(wf2.iter().any(|f| f.location.contains("comment.yml")
            && f.detail.as_deref().unwrap().contains("gh pr checkout")));
        // A token in the fetched URL never reaches the finding.
        let fetch = wf2
            .iter()
            .find(|f| f.location.contains("fetch-token.yml"))
            .unwrap();
        assert!(
            fetch
                .detail
                .as_deref()
                .unwrap()
                .starts_with("run: git fetch ... pull/<n>/head on pull_request_target;")
        );
        for finding in &f {
            let all = format!("{finding:?}");
            assert!(!all.contains("FETCHFAKE"), "{all}");
        }
        // pull_request (not _target) checks out the head by default: fine.
        assert!(!wf2.iter().any(|f| f.location.contains("pull-request.yml")));
        // Checkout after the agent step does not count.
        assert!(!wf2.iter().any(|f| f.location.contains("after.yml")));
    }

    #[test]
    fn broad_permissions() {
        let f = fixture_findings("permissions");
        let wf3: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-WF-003").collect();
        assert_eq!(wf3.len(), 2, "{f:#?}");
        let all = wf3
            .iter()
            .find(|f| f.location.contains("write-all.yml"))
            .unwrap();
        assert_eq!(all.severity, Severity::High);
        let default = wf3
            .iter()
            .find(|f| f.location.contains("default.yml"))
            .unwrap();
        assert_eq!(default.severity, Severity::Medium);
        assert!(
            default
                .detail
                .as_deref()
                .unwrap()
                .contains("Set permissions explicitly")
        );
        // Job-level permissions override workflow-level write-all.
        assert!(!wf3.iter().any(|f| f.location.contains("job-override.yml")));
        assert_eq!(rules_of(&f), vec!["HK-WF-003"]);
    }

    #[test]
    fn excess_secrets() {
        let f = fixture_findings("secrets");
        let wf4: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-WF-004").collect();
        assert_eq!(wf4.len(), 3, "{f:#?}");
        let broad = wf4
            .iter()
            .find(|f| f.location.contains("broad.yml"))
            .unwrap();
        assert_eq!(broad.severity, Severity::High);
        let d = broad.detail.as_deref().unwrap();
        assert!(d.contains("AWS_SECRET_ACCESS_KEY"), "{d}");
        assert!(d.contains("GH_PAT"), "{d}");
        assert!(d.contains("whole secrets context"), "{d}");
        assert!(!d.contains("ANTHROPIC_API_KEY"), "{d}");
        let narrow = wf4
            .iter()
            .find(|f| f.location.contains("extra.yml"))
            .unwrap();
        assert_eq!(narrow.severity, Severity::Medium);
        assert!(narrow.detail.as_deref().unwrap().contains("SENTRY_DSN"));
        let copilot = wf4
            .iter()
            .find(|f| f.location.contains("copilot-setup-steps.yml"))
            .unwrap();
        assert!(
            copilot
                .location
                .contains("jobs.copilot-setup-steps (Copilot coding agent setup)")
        );
        assert!(copilot.detail.as_deref().unwrap().contains("NPM_TOKEN"));
        // A step that only gets its model key is fine.
        assert!(
            !wf4.iter()
                .any(|f| f.location.contains("model-key-only.yml"))
        );
    }

    #[test]
    fn unpinned_agent_actions() {
        let f = fixture_findings("unpinned");
        let wf5: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-WF-005").collect();
        assert_eq!(wf5.len(), 2, "{f:#?}");
        assert!(wf5.iter().all(|f| f.severity == Severity::Medium));
        assert!(
            wf5.iter()
                .any(|f| f.location.contains("anthropics/claude-code-action@v1"))
        );
        assert!(
            wf5.iter()
                .any(|f| f.location.contains("openai/codex-action@main"))
        );
        assert_eq!(rules_of(&f), vec!["HK-WF-005"]);
    }

    #[test]
    fn shell_grants_with_write_token() {
        let f = fixture_findings("shell");
        let wf6: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-WF-006").collect();
        assert_eq!(wf6.len(), 4, "{f:#?}");
        assert!(wf6.iter().all(|f| f.severity == Severity::High));
        let claude = wf6
            .iter()
            .find(|f| f.location.contains("claude-skip.yml"))
            .unwrap();
        assert!(
            claude
                .detail
                .as_deref()
                .unwrap()
                .contains("--dangerously-skip-permissions")
        );
        assert!(
            claude
                .detail
                .as_deref()
                .unwrap()
                .contains("Bash allowed without a command filter")
        );
        assert!(wf6.iter().any(|f| f.location.contains("codex-full.yml")
            && f.detail.as_deref().unwrap().contains("danger-full-access")));
        assert!(wf6.iter().any(
            |f| f.location.contains("gemini-yolo.yml") && f.location.contains("(run: gemini)")
        ));
        // A build runner is a shell; a flag named in the prompt is not.
        let runner = wf6
            .iter()
            .find(|f| f.location.contains("runner.yml"))
            .unwrap();
        assert!(
            runner
                .detail
                .as_deref()
                .unwrap()
                .starts_with("Bash(npm run docs:*) runs any code (npm); write token")
        );
        // Read-only token: shell grants alone are not HK-WF-006.
        assert!(!wf6.iter().any(|f| f.location.contains("read-only.yml")));
        // Restricted Bash and --disallowedTools Bash are fine.
        assert!(!wf6.iter().any(|f| f.location.contains("restricted.yml")));
    }

    #[test]
    fn on_shapes_and_reusable_agent_workflows() {
        let f = inline(
            "on: [issues]\njobs:\n  resolve:\n    uses: All-Hands-AI/OpenHands/.github/workflows/openhands-resolver.yml@main\n    secrets: inherit\n",
        );
        let rules = rules_of(&f);
        assert_eq!(
            rules,
            vec!["HK-WF-001", "HK-WF-003", "HK-WF-004", "HK-WF-005"],
            "{f:#?}"
        );
        assert!(
            f[0].location
                .starts_with(".github/workflows/agent.yml:3 jobs.resolve (uses: ")
        );
    }

    #[test]
    fn claude_code_action_checks_the_actor_itself() {
        let yaml = "on: issue_comment\npermissions:\n  contents: write\njobs:\n  c:\n    steps:\n      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567\n        with:\n          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n";
        let f = inline(yaml);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(
            f[0].detail
                .as_deref()
                .unwrap()
                .contains("only runs for users with write access")
        );
        // Codex has no such built-in check: the same workflow is High.
        let f = inline(&yaml.replace("anthropics/claude-code-action", "openai/codex-action"));
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn bedrock_and_vertex_keys_are_expected_but_noted() {
        let yaml = "on: workflow_dispatch\npermissions:\n  contents: read\n  id-token: write\njobs:\n  c:\n    steps:\n      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567\n        with:\n          use_bedrock: \"true\"\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n          DEPLOY_KEY: ${{ secrets.GCP_DEPLOY_KEY }}\n";
        let f = inline(yaml);
        let wf4 = f.iter().find(|f| f.rule == "HK-WF-004").unwrap();
        let d = wf4.detail.as_deref().unwrap();
        assert!(
            d.contains(
                "AWS_SECRET_ACCESS_KEY via env.AWS_SECRET_ACCESS_KEY (expected for Amazon Bedrock"
            ),
            "{d}"
        );
        // A Google key is not Bedrock's: still the High kind.
        assert!(
            d.contains("GCP_DEPLOY_KEY via env.DEPLOY_KEY (cloud or SCM credential)"),
            "{d}"
        );
        assert_eq!(wf4.severity, Severity::High);

        let only_aws =
            inline(&yaml.replace("          DEPLOY_KEY: ${{ secrets.GCP_DEPLOY_KEY }}\n", ""));
        let wf4 = only_aws.iter().find(|f| f.rule == "HK-WF-004").unwrap();
        assert_eq!(wf4.severity, Severity::Medium);

        // Without use_bedrock the same AWS keys are the High kind.
        let anthropic = inline(&yaml.replace(
            "          use_bedrock: \"true\"\n",
            "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n",
        ));
        let wf4 = anthropic.iter().find(|f| f.rule == "HK-WF-004").unwrap();
        assert_eq!(wf4.severity, Severity::High);

        // Vertex through Claude Code's env switch on a CLI step.
        let vertex = inline(
            "on: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  c:\n    steps:\n      - run: claude -p review\n        env:\n          CLAUDE_CODE_USE_VERTEX: 1\n          GOOGLE_APPLICATION_CREDENTIALS_JSON: ${{ secrets.GCP_SA_KEY }}\n",
        );
        let wf4 = vertex.iter().find(|f| f.rule == "HK-WF-004").unwrap();
        assert_eq!(wf4.severity, Severity::Medium);
        assert!(wf4.detail.as_deref().unwrap().contains("Google Vertex AI"));
    }

    #[test]
    fn id_token_wording_follows_the_backend() {
        let yaml = "on: issue_comment\npermissions:\n  contents: read\n  id-token: write\njobs:\n  c:\n    steps:\n      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567\n        with:\n          use_bedrock: true\n";
        let f = inline(yaml);
        let d = f[0].detail.as_deref().unwrap();
        assert!(d.contains("id-token: write, used to reach Amazon Bedrock and exchanged for the Claude GitHub App token"), "{d}");
        let f = inline(&yaml.replace(
            "use_bedrock: true",
            "use_bedrock: true\n          github_token: ${{ github.token }}",
        ));
        let d = f[0].detail.as_deref().unwrap();
        assert!(
            d.contains("used to reach Amazon Bedrock; it can also mint"),
            "{d}"
        );
        assert!(!d.contains("GitHub App"), "{d}");
    }

    #[test]
    fn non_agent_workflows_are_ignored() {
        assert!(inline("on: pull_request_target\npermissions: write-all\njobs:\n  b:\n    steps:\n      - run: make\n").is_empty());
        assert!(inline("# only a comment\n").is_empty());
        assert!(fixture_findings("does-not-exist").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn workflow_symlinks_out_of_the_tree_are_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        write(
            outside.path(),
            "agent.yml",
            "on: issue_comment\npermissions: write-all\njobs:\n  a:\n    steps:\n      - run: claude -p hi\n",
        );
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".github/workflows")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("agent.yml"),
            repo.path().join(".github/workflows/agent.yml"),
        )
        .unwrap();
        let f = WorkflowsCheck.run(&ctx_with_env(repo.path(), &[]));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].rule, "HK-WF-007");
        assert!(
            f[0].detail.as_deref().unwrap().contains("symlink"),
            "{f:#?}"
        );
    }

    #[test]
    fn unparsable_workflows_are_reported_not_skipped() {
        let f = inline("on: [\n");
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].rule, "HK-WF-007");
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].location, ".github/workflows/agent.yml");
        assert!(
            f[0].detail
                .as_deref()
                .unwrap()
                .starts_with("could not analyse .github/workflows/agent.yml: not valid YAML")
        );
        let mut bomb = String::from("on: push\na0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..8 {
            bomb.push_str(&format!(
                "a{i}: &a{i} [{}]\n",
                vec![format!("*a{}", i - 1); 10].join(", ")
            ));
        }
        let f = inline(&bomb);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].rule, "HK-WF-007");
        let big = format!(
            "on: push\n# {}\n",
            "x".repeat(fsutil::MAX_FILE_BYTES as usize)
        );
        let f = inline(&big);
        assert!(
            f[0].detail.as_deref().unwrap().contains("larger than"),
            "{f:#?}"
        );
    }
}
