//! `ci-runtime`: what the current CI job exposes at runtime.
//!
//! The `workflows` check reads the YAML; this one looks at the job as it
//! actually runs, which is what an agent step in the same job would see:
//!
//! - secrets in the environment (job-level `env:` reaches every step);
//! - `GITHUB_TOKEN` / `GH_TOKEN`, if a step put them in the environment;
//! - OIDC (`ACTIONS_ID_TOKEN_REQUEST_URL` + `_TOKEN`): the job can mint
//!   tokens that cloud providers trade for credentials;
//! - `ACTIONS_RUNTIME_TOKEN`: write access to the Actions cache and artifacts;
//! - the GITHUB_TOKEN that `actions/checkout` leaves in the git config
//!   (`persist-credentials`, on by default);
//! - the runner: on a self-hosted runner state outlives the job, so every
//!   finding is rated one level higher.
//!
//! GitLab CI gets the same treatment for its environment and `CI_JOB_TOKEN`.
//!
//! Only `ctx.env` and files under `ctx.cwd` are read. Effective GITHUB_TOKEN
//! permissions come from the workflow file (see `workflows`), not the token.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::checks::env::EnvCheck;
use crate::checks::workflows::UNTRUSTED_TRIGGERS;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;
use crate::rules;
use crate::sanitize::clip;

pub struct CiRuntimeCheck;

const ID: &str = "ci-runtime";

const ENV_SECRET: Rule = Rule {
    check: ID,
    id: "HK-CI-001",
    summary: "Credential in the CI job's environment",
};

const GITHUB_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-CI-002",
    summary: "GitHub token in the CI job's environment",
};

const OIDC: Rule = Rule {
    check: ID,
    id: "HK-CI-003",
    summary: "OIDC token requests available: the job can mint cloud credentials",
};

const RUNTIME_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-CI-004",
    summary: "Actions runtime token with write access to the cache and artifacts",
};

const PERSISTED_CHECKOUT: Rule = Rule {
    check: ID,
    id: "HK-CI-005",
    summary: "GITHUB_TOKEN persisted in the git config by actions/checkout",
};

const JOB_CONTEXT: Rule = Rule {
    check: ID,
    id: "HK-CI-006",
    summary: "CI job context: platform, workflow, trigger and runner (context)",
};

const GITLAB_JOB_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-CI-007",
    summary: "GitLab CI job token in the job's environment",
};

const RULES: &[Rule] = &[
    ENV_SECRET,
    GITHUB_TOKEN,
    OIDC,
    RUNTIME_TOKEN,
    PERSISTED_CHECKOUT,
    JOB_CONTEXT,
    GITLAB_JOB_TOKEN,
];

/// Variables reported by a dedicated rule here, or that duplicate one
/// (GitLab's registry passwords are the job token).
const HANDLED: &[&str] = &[
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "CI_JOB_TOKEN",
    "CI_REGISTRY_PASSWORD",
    "CI_DEPENDENCY_PROXY_PASSWORD",
];

const ENV_FIX: &str = "Scope secrets to the one step that needs them (step-level env:), never job- or workflow-level env, and never to an agent step.";

/// Which CI we are in, and what that changes for every finding.
struct Job {
    /// Prepended to `env:` locations so SARIF can point at the workflow file,
    /// e.g. ".github/workflows/review.yml ".
    prefix: String,
    self_hosted: bool,
}

impl Check for CiRuntimeCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Inside GitHub Actions or GitLab CI: secrets in the job environment, GITHUB_TOKEN, OIDC, the runtime token, checkout credentials left in .git/config, and the runner type."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let job = job(ctx);
        let mut findings = if ctx.var("GITHUB_ACTIONS") == Some("true") {
            github(ctx, &job)
        } else if ctx.var("GITLAB_CI") == Some("true") {
            gitlab(ctx, &job)
        } else {
            return Vec::new();
        };
        findings.extend(env_secrets(ctx, &job));
        if job.self_hosted {
            for f in findings.iter_mut().filter(|f| f.is_credential()) {
                f.severity = raise(f.severity);
                let note = "self-hosted runner: state can outlive the job";
                f.detail = Some(match f.detail.take() {
                    Some(d) => format!("{d}; {note}"),
                    None => note.to_string(),
                });
            }
        }
        findings
    }
}

fn job(ctx: &Context) -> Job {
    let file = if ctx.var("GITHUB_ACTIONS") == Some("true") {
        ctx.var("GITHUB_WORKFLOW_REF").and_then(workflow_file)
    } else {
        ctx.var("CI_CONFIG_PATH")
            .or(Some(".gitlab-ci.yml"))
            .map(str::to_string)
    };
    Job {
        prefix: file.map(|f| format!("{} ", clip(&f))).unwrap_or_default(),
        self_hosted: ctx.var("RUNNER_ENVIRONMENT") == Some("self-hosted"),
    }
}

/// `owner/repo/.github/workflows/x.yml@refs/heads/main` -> `.github/workflows/x.yml`.
fn workflow_file(reference: &str) -> Option<String> {
    let start = reference.find(".github/workflows/")?;
    let path = &reference[start..];
    Some(path.split('@').next().unwrap_or(path).to_string())
}

fn raise(severity: Severity) -> Severity {
    match severity {
        Severity::Low => Severity::Medium,
        Severity::Medium | Severity::High => Severity::High,
        Severity::Info => Severity::Info,
    }
}

/// GitHub Actions specifics.
fn github(ctx: &Context, job: &Job) -> Vec<Finding> {
    let mut findings = vec![github_context(ctx, job)];

    for name in ["GITHUB_TOKEN", "GH_TOKEN"] {
        let Some(value) = ctx.var(name) else { continue };
        let Some(c) = rules::classify_named_value("GITHUB_TOKEN", value) else {
            continue;
        };
        findings.push(
            Finding::new(
                GITHUB_TOKEN,
                "GitHub token in the job environment",
                format!("{}env: {name}", job.prefix),
                c.severity,
                c.lifetime,
                c.access,
                "Pass the token only to the step that needs it, with a job-level permissions: block that is as narrow as possible.",
            )
            .with_fingerprint(c.fingerprint)
            .with_detail(format!(
                "{}; what it can do is set by the workflow's permissions: block (see the workflows findings)",
                c.title
            )),
        );
    }

    if ctx.var("ACTIONS_ID_TOKEN_REQUEST_URL").is_some()
        && ctx.var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_some()
    {
        findings.push(
            Finding::new(
                OIDC,
                "OIDC: this job can mint cloud credentials",
                format!("{}env: ACTIONS_ID_TOKEN_REQUEST_TOKEN", job.prefix),
                Severity::Medium,
                Lifetime::ShortLived,
                Access::Unknown,
                "Grant id-token: write only to the job that deploys, and pin cloud trust policies to a branch or environment in the sub claim.",
            )
            .with_detail("the job has id-token: write; any cloud role that trusts this repository's OIDC tokens can be assumed from here"),
        );
    }

    if let Some(value) = ctx.var("ACTIONS_RUNTIME_TOKEN") {
        findings.push(
            Finding::new(
                RUNTIME_TOKEN,
                "Actions runtime token (cache and artifacts)",
                format!("{}env: ACTIONS_RUNTIME_TOKEN", job.prefix),
                Severity::Medium,
                Lifetime::ShortLived,
                Access::Write,
                "Keep agent steps out of jobs that save caches or build release artifacts.",
            )
            .with_fingerprint(crate::redact::fingerprint(value))
            .with_detail("can write the Actions cache and artifacts, which later jobs (including release builds) restore"),
        );
    }

    findings.extend(persisted_checkout(ctx));
    findings
}

fn github_context(ctx: &Context, job: &Job) -> Finding {
    let mut facts = Vec::new();
    if let Some(name) = ctx.var("GITHUB_JOB") {
        facts.push(format!("job {}", clip(name)));
    }
    if let Some(event) = ctx.var("GITHUB_EVENT_NAME") {
        if UNTRUSTED_TRIGGERS.contains(&event) {
            facts.push(format!(
                "triggered by {event}, whose text an outsider can write"
            ));
        } else {
            facts.push(format!("triggered by {}", clip(event)));
        }
    }
    facts.push(if job.self_hosted {
        "self-hosted runner: files, caches and processes can outlive the job, so findings are rated one level higher".to_string()
    } else if ctx.var("RUNNER_ENVIRONMENT") == Some("github-hosted") {
        "GitHub-hosted runner (a fresh VM per job)".to_string()
    } else {
        "runner type unknown".to_string()
    });
    facts.push("this scan sees the heldkeys step's environment; agent steps also get their own with: and env:".to_string());
    Finding::new(
        JOB_CONTEXT,
        "GitHub Actions job",
        if job.prefix.is_empty() {
            "GitHub Actions".to_string()
        } else {
            job.prefix.trim_end().to_string()
        },
        Severity::Info,
        Lifetime::Unknown,
        Access::Unknown,
        "No action needed; context for the findings above.",
    )
    .with_detail(facts.join("; "))
}

/// `actions/checkout` (with the default `persist-credentials: true`) stores the
/// job's token as an `http.<url>.extraheader` in `.git/config`, or in a file
/// that `.git/config` includes. Any process in the job can read it back.
fn persisted_checkout(ctx: &Context) -> Option<Finding> {
    let git_dir = ctx.cwd.join(".git");
    let config = git_dir.join("config");
    let text = ctx.read_project_file(&config)?;
    let mut holder: Option<PathBuf> = has_auth_header(&text).then(|| config.clone());
    if holder.is_none() {
        // actions/checkout v5+ keeps the header in a file under RUNNER_TEMP
        // that .git/config includes. Includes are only read from the working
        // tree or RUNNER_TEMP, so a crafted include.path cannot point us at
        // any other file.
        let roots: Vec<PathBuf> = std::iter::once(ctx.cwd.clone())
            .chain(ctx.var("RUNNER_TEMP").map(PathBuf::from))
            .collect();
        // An included file in one of those roots that exists but cannot be
        // read is recorded for `read-errors` (and fails --strict).
        holder = include_paths(&text)
            .into_iter()
            .map(|p| resolve_include(&git_dir, &p))
            .find(|p| {
                roots
                    .iter()
                    .find(|root| fsutil::is_within(root, p))
                    .and_then(|root| ctx.read_file_within(root, p))
                    .is_some_and(|t| has_auth_header(&t))
            });
    }
    let holder = holder?;
    // The file that holds the token, repo-relative when it is in the repo,
    // so SARIF and the reader point at the real file.
    let location = clip(&match holder.strip_prefix(&ctx.cwd) {
        Ok(rest) => rest.display().to_string(),
        Err(_) => holder.display().to_string(),
    });
    Some(
        Finding::new(
            PERSISTED_CHECKOUT,
            "Checkout left GITHUB_TOKEN in git config",
            location,
            Severity::Medium,
            Lifetime::ShortLived,
            Access::Unknown,
            "Set persist-credentials: false on actions/checkout in any job that runs an agent.",
        )
        .with_detail("http extraheader with an AUTHORIZATION value; git config --get-regexp extraheader prints it"),
    )
}

fn has_auth_header(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("extraheader") && l.contains("authorization")
    })
}

/// `path = ...` values in `[include]` and `[includeIf ...]` sections.
fn include_paths(text: &str) -> Vec<String> {
    let mut in_include = false;
    let mut paths = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            let lower = line.to_ascii_lowercase();
            in_include = lower.starts_with("[include");
            continue;
        }
        if in_include
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("path")
        {
            paths.push(rules::trim_value(value).to_string());
        }
    }
    paths
}

fn resolve_include(git_dir: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        git_dir.join(p)
    }
}

/// GitLab CI specifics.
fn gitlab(ctx: &Context, job: &Job) -> Vec<Finding> {
    let mut facts = Vec::new();
    if let Some(project) = ctx.var("CI_PROJECT_PATH") {
        facts.push(format!("project {}", clip(project)));
    }
    if let Some(name) = ctx.var("CI_JOB_NAME") {
        facts.push(format!("job {}", clip(name)));
    }
    if let Some(source) = ctx.var("CI_PIPELINE_SOURCE") {
        facts.push(format!("pipeline source {}", clip(source)));
    }
    let mut findings = vec![
        Finding::new(
            JOB_CONTEXT,
            "GitLab CI job",
            job.prefix.trim_end(),
            Severity::Info,
            Lifetime::Unknown,
            Access::Unknown,
            "No action needed; context for the findings above.",
        )
        .with_detail(if facts.is_empty() {
            "GitLab CI".to_string()
        } else {
            facts.join("; ")
        }),
    ];
    if let Some(value) = ctx.var("CI_JOB_TOKEN") {
        findings.push(
            Finding::new(
                GITLAB_JOB_TOKEN,
                "GitLab CI job token",
                format!("{}env: CI_JOB_TOKEN", job.prefix),
                Severity::Medium,
                Lifetime::ShortLived,
                Access::Unknown,
                "Limit the job token's project allowlist (CI/CD job token settings) and keep agents out of jobs that deploy.",
            )
            .with_fingerprint(crate::redact::fingerprint(value))
            .with_detail("API, registry and package access as the user who started the pipeline, until the job ends"),
        );
    }
    findings
}

/// Credentials in the job environment, classified like the `env` check
/// (same rules, so CI and local scans agree), re-labelled as CI findings.
fn env_secrets(ctx: &Context, job: &Job) -> Vec<Finding> {
    let mut filtered = ctx.clone();
    filtered
        .env
        .retain(|name, _| !HANDLED.contains(&name.as_str()) && !name.starts_with("CI_JOB_JWT"));
    EnvCheck
        .run(&filtered)
        .into_iter()
        .map(|mut f| {
            f.check = ID;
            f.rule = ENV_SECRET.id;
            f.location = format!("{}{}", job.prefix, f.location);
            f.fix = ENV_FIX.to_string();
            f
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, write};

    const WF_REF: &str = "octo/repo/.github/workflows/review.yml@refs/heads/main";

    fn run(env: &[(&str, &str)]) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        CiRuntimeCheck.run(&ctx_with_env(dir.path(), env))
    }

    fn find<'a>(f: &'a [Finding], rule: &str) -> &'a Finding {
        f.iter()
            .find(|f| f.rule == rule)
            .unwrap_or_else(|| panic!("{rule} missing from {f:#?}"))
    }

    #[test]
    fn nothing_outside_ci() {
        assert!(run(&[("GITHUB_TOKEN", "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000301")]).is_empty());
    }

    #[test]
    fn github_actions_job() {
        let f = run(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_WORKFLOW_REF", WF_REF),
            ("GITHUB_JOB", "review"),
            ("GITHUB_EVENT_NAME", "issue_comment"),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
            ("GITHUB_TOKEN", "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000301"),
            (
                "ACTIONS_ID_TOKEN_REQUEST_URL",
                "https://example.invalid/token",
            ),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "FAKEoidcREQUESTtoken0302"),
            ("DEPLOY_API_KEY", "FAKEdeployAPIkey0303xyz"),
            ("GITHUB_REPOSITORY", "octo/repo"),
        ]);
        let context = find(&f, "HK-CI-006");
        assert_eq!(context.severity, Severity::Info);
        assert_eq!(context.location, ".github/workflows/review.yml");
        let d = context.detail.as_deref().unwrap();
        assert!(d.contains("job review"), "{d}");
        assert!(
            d.contains("issue_comment, whose text an outsider can write"),
            "{d}"
        );
        assert!(d.contains("GitHub-hosted"), "{d}");

        let token = find(&f, "HK-CI-002");
        assert_eq!(
            token.location,
            ".github/workflows/review.yml env: GITHUB_TOKEN"
        );
        assert_eq!(token.severity, Severity::Medium);
        assert_eq!(token.fingerprint.as_deref(), Some("ghs_…301"));

        let oidc = find(&f, "HK-CI-003");
        assert!(oidc.title.contains("can mint cloud credentials"));

        let secret = find(&f, "HK-CI-001");
        assert_eq!(secret.check, "ci-runtime");
        assert_eq!(
            secret.location,
            ".github/workflows/review.yml env: DEPLOY_API_KEY"
        );
        assert_eq!(f.len(), 4, "{f:#?}");
    }

    #[test]
    fn long_names_from_the_environment_are_clipped() {
        let long = "x".repeat(10_000);
        let wf_ref = format!("o/r/.github/workflows/{long}.yml@refs/heads/main");
        let f = run(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_WORKFLOW_REF", &wf_ref),
            ("GITHUB_JOB", &long),
            ("GITHUB_EVENT_NAME", &long),
            ("GITHUB_TOKEN", "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000301"),
        ]);
        let context = find(&f, "HK-CI-006");
        assert_eq!(context.location.chars().count(), crate::sanitize::MAX_SHOWN);
        assert!(context.location.ends_with("xxxx.yml"));
        assert!(context.detail.as_deref().unwrap().len() < 1_000);
        assert!(find(&f, "HK-CI-002").location.len() < 300);
    }

    #[test]
    fn self_hosted_raises_severity() {
        let f = run(&[
            ("GITHUB_ACTIONS", "true"),
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("GITHUB_TOKEN", "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000301"),
        ]);
        let token = find(&f, "HK-CI-002");
        assert_eq!(token.severity, Severity::High);
        assert!(token.detail.as_deref().unwrap().contains("self-hosted"));
        assert_eq!(find(&f, "HK-CI-006").location, "GitHub Actions");
    }

    #[test]
    fn persisted_checkout_credentials() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".git/config",
            "[core]\n\tbare = false\n[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic RkFLRWZha2U=\n",
        );
        let f = CiRuntimeCheck.run(&ctx_with_env(
            dir.path(),
            &[("GITHUB_ACTIONS", "true"), ("GITHUB_WORKFLOW_REF", WF_REF)],
        ));
        let p = find(&f, "HK-CI-005");
        // The file that holds the token, not glued to the workflow name.
        assert_eq!(p.location, ".git/config");
        assert_eq!(p.fingerprint, None);
        assert!(p.title.chars().count() <= 44, "{}", p.title);
    }

    #[test]
    fn persisted_checkout_credentials_in_included_file() {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("runner-temp/git-credentials-abc.config");
        write(
            dir.path(),
            "runner-temp/git-credentials-abc.config",
            "[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic RkFLRWZha2U=\n",
        );
        write(
            dir.path(),
            ".git/config",
            &format!(
                "[includeIf \"gitdir:/x/.git\"]\n\tpath = {}\n",
                creds.display()
            ),
        );
        let f = CiRuntimeCheck.run(&ctx_with_env(dir.path(), &[("GITHUB_ACTIONS", "true")]));
        assert_eq!(
            find(&f, "HK-CI-005").location,
            "runner-temp/git-credentials-abc.config"
        );
    }

    #[test]
    fn includes_outside_the_tree_and_runner_temp_are_not_read() {
        let outside = tempfile::tempdir().unwrap();
        write(
            outside.path(),
            "creds.config",
            "[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic RkFLRWZha2U=\n",
        );
        let creds = outside.path().join("creds.config");
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".git/config",
            &format!("[include]\n\tpath = {}\n", creds.display()),
        );
        let f = CiRuntimeCheck.run(&ctx_with_env(dir.path(), &[("GITHUB_ACTIONS", "true")]));
        assert!(f.iter().all(|f| f.rule != "HK-CI-005"), "{f:#?}");
        // Under RUNNER_TEMP it is where actions/checkout puts it: found.
        let temp = outside.path().to_str().unwrap();
        let f = CiRuntimeCheck.run(&ctx_with_env(
            dir.path(),
            &[("GITHUB_ACTIONS", "true"), ("RUNNER_TEMP", temp)],
        ));
        assert!(find(&f, "HK-CI-005").location.ends_with("creds.config"));
    }

    #[cfg(unix)]
    #[test]
    fn an_include_that_cannot_be_read_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("runner-temp/creds.config");
        std::fs::create_dir_all(creds.parent().unwrap()).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&creds)
            .status()
            .unwrap();
        assert!(status.success());
        write(
            dir.path(),
            ".git/config",
            &format!("[include]\n\tpath = {}\n", creds.display()),
        );
        let ctx = ctx_with_env(dir.path(), &[("GITHUB_ACTIONS", "true")]);
        let f = CiRuntimeCheck.run(&ctx);
        assert!(f.iter().all(|f| f.rule != "HK-CI-005"), "{f:#?}");
        let unreadable = ctx.take_unreadable();
        assert_eq!(unreadable.len(), 1, "{unreadable:?}");
        assert!(unreadable[0].0.ends_with("creds.config"));
    }

    #[test]
    fn checkout_without_credentials_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".git/config", "[core]\n\tbare = false\n");
        let f = CiRuntimeCheck.run(&ctx_with_env(dir.path(), &[("GITHUB_ACTIONS", "true")]));
        assert!(f.iter().all(|f| f.rule != "HK-CI-005"));
    }

    #[test]
    fn gitlab_job() {
        let f = run(&[
            ("GITLAB_CI", "true"),
            ("CI_JOB_TOKEN", "glcbt-FAKEFAKEFAKEFAKE0304"),
            ("CI_REGISTRY_PASSWORD", "glcbt-FAKEFAKEFAKEFAKE0304"),
            ("CI_PIPELINE_SOURCE", "merge_request_event"),
            ("OPENAI_API_KEY", "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE0305"),
        ]);
        assert_eq!(
            find(&f, "HK-CI-007").location,
            ".gitlab-ci.yml env: CI_JOB_TOKEN"
        );
        assert_eq!(
            find(&f, "HK-CI-001").location,
            ".gitlab-ci.yml env: OPENAI_API_KEY"
        );
        assert_eq!(f.len(), 3, "{f:#?}");
    }

    #[test]
    fn workflow_file_from_ref() {
        assert_eq!(
            workflow_file(WF_REF).as_deref(),
            Some(".github/workflows/review.yml")
        );
        assert_eq!(workflow_file("nonsense"), None);
    }
}
