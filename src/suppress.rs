//! Applies ignore rules (`config`) and a baseline (`baseline`) to a report.
//!
//! Nothing is dropped silently. A finding an ignore rule or the baseline
//! covers moves from `Report::findings` to `Report::suppressed`, with the
//! reason, so every format can count it and list it: the summary line says
//! how many were ignored, text and Markdown list every ignore rule that
//! matched, JSON has a `suppressed` list and SARIF marks the results as
//! suppressed. `--fail-on` and `--strict` only look at `findings`.
//!
//! Ignore rules are applied first; the baseline covers what is left. A
//! finding the baseline has but that got worse since (see `baseline`) stays
//! in the report, with what it was in the baseline added to its detail.

use std::path::Path;

use serde::Serialize;

use crate::baseline::{Baseline, Verdict};
use crate::config::{Date, Ignore};
use crate::finding::Finding;
use crate::report::Report;

/// What left a finding out of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum By {
    Config,
    Baseline,
}

/// A finding left out of the report, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppressed {
    pub finding: Finding,
    pub by: By,
    /// The ignore rule's `reason`, or "in the baseline <file>".
    pub reason: String,
    /// The config or baseline file, as shown to the reader.
    pub source: String,
}

/// An ignore rule that left out at least one finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub ignore: Ignore,
    pub findings: usize,
}

/// What the report says about suppression, beyond the suppressed findings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Suppression {
    /// Every ignore rule that matched, in the order of the config files.
    pub hits: Vec<Hit>,
    /// Ignore rules past their `expires` date, which no longer apply.
    pub expired: Vec<Ignore>,
    /// The baseline file, as shown, when one was applied.
    pub baseline: Option<String>,
    /// Warnings for the reader, such as ignore rules read from the checkout
    /// of a pull request. Already inert text.
    pub notices: Vec<String>,
    /// Set when the ignore rules came from the checkout of a change under
    /// review, which that change controls.
    pub config_from_change: Option<Change>,
    /// The same for the baseline.
    pub baseline_from_change: Option<Change>,
}

/// A change under review whose own files the scan read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// GitHub Actions on `pull_request` or an untrusted trigger.
    PullRequest,
    /// GitLab CI on a merge request pipeline.
    MergeRequest,
}

impl Change {
    pub fn noun(self) -> &'static str {
        match self {
            Change::PullRequest => "pull request",
            Change::MergeRequest => "merge request",
        }
    }
}

/// Moves the findings that `ignores` (unless expired on `today`) or
/// `baseline` cover out of `report.findings` into `report.suppressed`.
pub fn apply(report: &mut Report, ignores: &[Ignore], baseline: Option<&Baseline>, today: Date) {
    let origin = report.origin.clone();
    let active: Vec<&Ignore> = ignores.iter().filter(|i| !i.is_expired(today)).collect();
    let mut counts = vec![0usize; active.len()];
    let mut kept = Vec::new();
    for mut f in std::mem::take(&mut report.findings) {
        let location = normalise_location(&f.location, origin.as_deref());
        let file = finding_file(&f, origin.as_deref());
        if let Some(i) = active
            .iter()
            .position(|ig| ig.matches(f.rule, file.as_deref(), &location))
        {
            counts[i] += 1;
            report.suppressed.push(Suppressed {
                reason: active[i].reason.clone(),
                source: active[i].source.clone(),
                by: By::Config,
                finding: f,
            });
            continue;
        }
        if let Some(b) = baseline {
            match b.check(&f, origin.as_deref()) {
                Verdict::Covered => {
                    report.suppressed.push(Suppressed {
                        reason: format!("in the baseline {}", b.source),
                        source: b.source.clone(),
                        by: By::Baseline,
                        finding: f,
                    });
                    continue;
                }
                Verdict::Worse(was) => {
                    f.detail = Some(match f.detail.take() {
                        Some(detail) => format!("{detail}; {was}"),
                        None => was,
                    });
                }
                Verdict::New => {}
            }
        }
        kept.push(f);
    }
    report.findings = kept;
    // Copies of a secret are counted among the findings still shown.
    crate::report::count_duplicates(&mut report.findings);
    report.suppression.hits = active
        .iter()
        .zip(counts)
        .filter(|(_, n)| *n > 0)
        .map(|(ignore, findings)| Hit {
            ignore: (*ignore).clone(),
            findings,
        })
        .collect();
    report.suppression.expired = ignores
        .iter()
        .filter(|i| i.is_expired(today))
        .cloned()
        .collect();
    report.suppression.baseline = baseline.map(|b| b.source.clone());
}

/// A location as ignore rules and baselines compare it:
///
/// - under the scanned directory (`origin`, such as `~/code`), relative
///   to it (`./app/.env: KEY`), so a baseline written on a laptop matches in
///   CI, where the checkout lives somewhere else;
/// - without a line number after the file (`.github/workflows/a.yml:12 jobs...`
///   becomes `.github/workflows/a.yml jobs...`), so editing a file above a
///   finding does not make it new.
pub fn normalise_location(location: &str, origin: Option<&str>) -> String {
    let mut text = location.to_string();
    if let Some(origin) = origin
        && !matches!(origin, "" | "~" | "/")
        && let Some(rest) = location.strip_prefix(origin)
        && let Some(rest) = rest.strip_prefix('/')
    {
        text = format!("./{rest}");
    }
    let first_end = text.find(' ').unwrap_or(text.len());
    if let Some(colon) = text[..first_end].rfind(':') {
        let digits = &text[colon + 1..first_end];
        if colon > 0 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            text.replace_range(colon..first_end, "");
        }
    }
    text
}

/// The file a finding is in, relative to the scanned directory, without a
/// line number and without a leading `./`: what an ignore rule's `path` is
/// matched against. `None` for findings that are not in a file (an
/// environment variable, the CI job, an endpoint).
///
/// Only the file: the rest of a location is text the scanned repository
/// picks (job ids, `uses:` values, variable names), and must not decide
/// whether a path pattern applies.
pub fn finding_file(f: &Finding, origin: Option<&str>) -> Option<String> {
    let strip = |p: &str| p.strip_prefix("./").unwrap_or(p).to_string();
    // Repo-relative files of CI findings (`src/app.py:3`, `Makefile`), the
    // same as SARIF's physical locations.
    if let Some((file, _)) = crate::report::sarif::file_location(f) {
        return Some(strip(&file));
    }
    let location = normalise_location(&f.location, origin);
    crate::report::digest::split_location(&location)
        .0
        .map(strip)
}

/// Whether this CI run is for a change under review whose checkout the scan
/// reads: GitHub Actions on `pull_request` or one of the untrusted triggers
/// (shared with the workflow rules), or a GitLab merge request pipeline.
/// Returns the change and the run, as warnings name it ("this
/// pull_request_target run").
pub fn untrusted_change<'a>(var: impl Fn(&str) -> Option<&'a str>) -> Option<(Change, String)> {
    if var("GITHUB_ACTIONS") == Some("true")
        && let Some(event) = var("GITHUB_EVENT_NAME")
        && (event == "pull_request"
            || crate::checks::workflows::UNTRUSTED_TRIGGERS.contains(&event))
    {
        let event = crate::sanitize::clip(&crate::sanitize::sanitize(event));
        return Some((Change::PullRequest, format!("this {event} run")));
    }
    if var("GITLAB_CI") == Some("true")
        && matches!(
            var("CI_PIPELINE_SOURCE"),
            Some("merge_request_event" | "external_pull_request_event")
        )
    {
        return Some((
            Change::MergeRequest,
            "this merge request pipeline".to_string(),
        ));
    }
    None
}

/// The warnings shown when ignore rules or the baseline come from the
/// checkout of a change under review: that change can add an ignore rule,
/// or a baseline entry, for the very risk it introduces. heldkeys cannot
/// tell offline whether the file changed against the base branch, so it
/// says so every time. `config` and `baseline` are the files, as shown.
pub fn checkout_notices(
    change: Change,
    run: &str,
    config: Option<&str>,
    baseline: Option<&str>,
) -> Vec<String> {
    let noun = change.noun();
    let mut notices = Vec::new();
    if let Some(file) = config {
        notices.push(format!(
            "Ignore rules were read from {file} in the checkout of {run}, which the {noun} can change. Protect the file with CODEOWNERS, or pass --config with a copy from the default branch."
        ));
    }
    if let Some(file) = baseline {
        notices.push(format!(
            "The baseline {file} was read from the checkout of {run}, which the {noun} can change. Protect the file with CODEOWNERS, or pass --baseline with a copy from the default branch."
        ));
    }
    notices
}

/// Whether `file` belongs to the checkout at `root`: inside it, and not in
/// a nested git checkout below it (such as a copy of the default branch
/// checked out into a subdirectory, which the pull request does not control).
pub fn in_checkout(root: &Path, file: &Path) -> bool {
    let (Ok(root), Ok(file)) = (std::fs::canonicalize(root), std::fs::canonicalize(file)) else {
        return false;
    };
    let mut dir = file.parent();
    while let Some(d) = dir {
        if d == root {
            return true;
        }
        if d.join(".git").exists() {
            return false;
        }
        dir = d.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime, Rule, Severity};
    use crate::report::Mode;

    const WF: Rule = Rule {
        check: "workflows",
        id: "HK-WF-005",
        summary: "x",
    };

    fn finding(location: &str) -> Finding {
        Finding::new(
            WF,
            "Unpinned",
            location,
            Severity::Medium,
            Lifetime::Unknown,
            Access::Unknown,
            "Pin it.",
        )
    }

    fn ignore(rule: &str, path: Option<&str>, expires: Option<&str>) -> Ignore {
        Ignore {
            rule: rule.to_string(),
            path: path.map(str::to_string),
            location: None,
            reason: "accepted".to_string(),
            expires: expires.and_then(Date::parse),
            source: "./.heldkeys.toml".to_string(),
        }
    }

    fn today() -> Date {
        Date::parse("2026-10-16").unwrap()
    }

    #[test]
    fn locations_are_normalised() {
        let n = |l: &str| normalise_location(l, Some("~/work"));
        assert_eq!(n("~/work/app/.env: KEY"), "./app/.env: KEY");
        assert_eq!(n("~/code/app/.env: KEY"), "~/code/app/.env: KEY");
        assert_eq!(
            n(".github/workflows/a.yml:12 jobs.x"),
            ".github/workflows/a.yml jobs.x"
        );
        assert_eq!(n("src/config.py:3"), "src/config.py");
        assert_eq!(n("./.env:7"), "./.env");
        assert_eq!(n("env: GITHUB_TOKEN"), "env: GITHUB_TOKEN");
        assert_eq!(normalise_location("~/.npmrc", Some("~")), "~/.npmrc");
    }

    #[test]
    fn ignores_then_baseline() {
        let mut report = Report::new(
            Mode::Ci,
            vec![
                finding(".github/workflows/a.yml:3 jobs.a"),
                finding(".github/workflows/b.yml:3 jobs.b"),
                finding(".github/workflows/c.yml:3 jobs.c"),
            ],
        );
        let baseline = crate::baseline::parse(
            &format!(
                "{{\"schema\": \"{}\", \"findings\": [{{\"rule\": \"HK-WF-005\", \"location\": \".github/workflows/b.yml:9 jobs.b\", \"severity\": \"medium\", \"access\": \"unknown\", \"lifetime\": \"unknown\"}}]}}",
                crate::JSON_SCHEMA
            ),
            "base.json",
        )
        .unwrap();
        let ignores = [
            ignore("HK-WF-*", Some(".github/workflows/a.yml"), None),
            ignore("HK-WF-005", Some("nothing/*"), None),
            ignore("HK-WF-005", None, Some("2020-01-01")),
        ];
        apply(&mut report, &ignores, Some(&baseline), today());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].location,
            ".github/workflows/c.yml:3 jobs.c"
        );
        let by: Vec<By> = report.suppressed.iter().map(|s| s.by).collect();
        assert_eq!(by, [By::Config, By::Baseline]);
        assert_eq!(report.suppressed[1].reason, "in the baseline base.json");
        assert_eq!(report.suppression.hits.len(), 1);
        assert_eq!(report.suppression.hits[0].findings, 1);
        assert_eq!(report.suppression.expired.len(), 1);
        let s = report.summary();
        assert_eq!((s.ignored, s.in_baseline), (1, 1));
        assert_eq!(
            s.line(),
            "1 AI agent workflow risk, 0 credentials reachable in this job (1 ignored by .heldkeys.toml, 1 in the baseline)."
        );
    }

    #[test]
    fn duplicates_are_recounted() {
        let rule = Rule {
            check: "dotenv",
            id: "HK-DOTENV-001",
            summary: "x",
        };
        let f = |loc: &str| {
            Finding::new(
                rule,
                "Key",
                loc,
                Severity::High,
                Lifetime::LongLived,
                Access::Write,
                "x",
            )
            .with_secret("same-FAKE-value-0001")
        };
        let mut report = Report::new(Mode::Scan, vec![f("./a/.env: K"), f("./b/.env: K")]);
        assert_eq!(report.findings[0].duplicates, Some(1));
        apply(
            &mut report,
            &[ignore("HK-DOTENV-001", Some("a/*"), None)],
            None,
            today(),
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].duplicates, None);
    }

    #[test]
    fn files_in_the_checkout_but_not_in_a_nested_one() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let base = root.join(".heldkeys-base");
        std::fs::create_dir_all(base.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("ci")).unwrap();
        for f in [
            root.join(".heldkeys.toml"),
            root.join("ci/base.json"),
            base.join(".heldkeys.toml"),
        ] {
            std::fs::write(f, "").unwrap();
        }
        let outside = tmp.path().join("outside.toml");
        std::fs::write(&outside, "").unwrap();
        assert!(in_checkout(&root, &root.join(".heldkeys.toml")));
        assert!(in_checkout(&root, &root.join("ci/base.json")));
        assert!(!in_checkout(&root, &base.join(".heldkeys.toml")));
        assert!(!in_checkout(&root, &outside));
        assert!(!in_checkout(&root, &root.join("missing.json")));
    }

    #[test]
    fn untrusted_changes() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
        };
        let gh = |event: &'static str| {
            untrusted_change(move |name: &str| match name {
                "GITHUB_ACTIONS" => Some("true"),
                "GITHUB_EVENT_NAME" => Some(event),
                _ => None,
            })
        };
        assert_eq!(
            gh("pull_request"),
            Some((Change::PullRequest, "this pull_request run".to_string()))
        );
        assert!(gh("pull_request_target").is_some());
        assert!(gh("issue_comment").is_some());
        assert!(gh("push").is_none());
        assert_eq!(
            untrusted_change(env(&[
                ("GITLAB_CI", "true"),
                ("CI_PIPELINE_SOURCE", "merge_request_event")
            ])),
            Some((
                Change::MergeRequest,
                "this merge request pipeline".to_string()
            ))
        );
        assert!(
            untrusted_change(env(&[
                ("GITLAB_CI", "true"),
                ("CI_PIPELINE_SOURCE", "push")
            ]))
            .is_none()
        );
        assert!(untrusted_change(env(&[("GITHUB_EVENT_NAME", "pull_request")])).is_none());
    }

    #[test]
    fn notices_name_the_file_and_what_to_do() {
        let n = checkout_notices(
            Change::PullRequest,
            "this pull_request run",
            Some("./.heldkeys.toml"),
            Some("base.json"),
        );
        assert_eq!(n.len(), 2);
        assert!(n[0].starts_with("Ignore rules were read from ./.heldkeys.toml in the checkout of this pull_request run, which the pull request can change."), "{}", n[0]);
        assert!(
            n[1].starts_with("The baseline base.json was read from the checkout"),
            "{}",
            n[1]
        );
        assert!(n[1].contains("--baseline"));
        assert!(checkout_notices(Change::MergeRequest, "x", None, None).is_empty());
    }

    #[test]
    fn files_of_findings() {
        let wf = Finding::new(
            WF,
            "t",
            ".github/workflows/bot.yml:7 jobs.fixtures-bot.steps[0] (uses: a/b@v1)",
            Severity::High,
            Lifetime::Unknown,
            Access::Unknown,
            "f",
        );
        assert_eq!(
            finding_file(&wf, None).as_deref(),
            Some(".github/workflows/bot.yml")
        );
        let dotenv_rule = Rule {
            check: "dotenv",
            id: "HK-DOTENV-001",
            summary: "x",
        };
        let env = Finding::new(
            dotenv_rule,
            "t",
            "~/work/fixtures/.env: FIXTURES_TOKEN",
            Severity::High,
            Lifetime::Unknown,
            Access::Unknown,
            "f",
        );
        assert_eq!(
            finding_file(&env, Some("~/work")).as_deref(),
            Some("fixtures/.env")
        );
        let ci_rule = Rule {
            check: "ci-runtime",
            id: "HK-CI-001",
            summary: "x",
        };
        let var = Finding::new(
            ci_rule,
            "t",
            "env: FIXTURES_TOKEN",
            Severity::High,
            Lifetime::Unknown,
            Access::Unknown,
            "f",
        );
        assert_eq!(finding_file(&var, None), None);
        let repo_rule = Rule {
            check: "repo-secrets",
            id: "HK-REPO-001",
            summary: "x",
        };
        let tracked = Finding::new(
            repo_rule,
            "t",
            "src/config.py:3",
            Severity::High,
            Lifetime::Unknown,
            Access::Unknown,
            "f",
        );
        assert_eq!(
            finding_file(&tracked, None).as_deref(),
            Some("src/config.py")
        );
    }

    #[test]
    fn a_baselined_finding_that_got_worse_is_reported() {
        let mut report = Report::new(
            Mode::Ci,
            vec![{
                let mut f = finding(".github/workflows/b.yml:3 jobs.b");
                f.severity = Severity::High;
                f
            }],
        );
        let baseline = crate::baseline::parse(
            &format!(
                "{{\"schema\": \"{}\", \"findings\": [{{\"rule\": \"HK-WF-005\", \"location\": \".github/workflows/b.yml:9 jobs.b\", \"severity\": \"medium\", \"access\": \"unknown\", \"lifetime\": \"unknown\"}}]}}",
                crate::JSON_SCHEMA
            ),
            "base.json",
        )
        .unwrap();
        apply(&mut report, &[], Some(&baseline), today());
        assert_eq!(report.findings.len(), 1);
        assert!(report.suppressed.is_empty());
        assert_eq!(
            report.findings[0].detail.as_deref(),
            Some("was medium in the baseline")
        );
    }
}
