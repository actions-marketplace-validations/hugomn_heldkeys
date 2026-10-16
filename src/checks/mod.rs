//! The checks, one per file, and the registry that lists them.
//!
//! Adding a check means: write a file with a struct implementing `Check`,
//! declare the module below, and add it to `local_checks` or `ci_checks`.

use crate::context::Context;
use crate::finding::{Finding, Rule};

pub mod aws;
pub mod azure;
pub mod cargo_credentials;
pub mod ci_runtime;
pub mod cli_logins;
pub mod cloud_metadata;
pub mod display;
pub mod docker;
pub mod docker_socket;
pub mod dotenv;
pub mod env;
pub mod gcloud;
pub mod git_config;
pub mod git_credentials;
pub mod git_helper;
pub mod k8s_service_account;
pub mod kube;
pub mod mcp;
pub mod netrc;
pub mod npmrc;
pub mod pypirc;
pub mod read_errors;
pub mod repo_secrets;
pub mod ssh_agent;
pub mod workflows;

/// One kind of exposure to look for.
///
/// A check only reads: files under `ctx.home` or `ctx.cwd`, and `ctx.env`.
/// It must never put a secret value into a `Finding`; use
/// `redact::fingerprint` for the only allowed trace of it.
pub trait Check {
    /// Stable id, e.g. "aws". Shown in `heldkeys checks` and used as the
    /// `check` field of every finding it produces.
    fn id(&self) -> &'static str;
    /// One line describing what the check looks at.
    fn describe(&self) -> &'static str;
    /// Every rule this check can produce. Each finding's `rule` is one of these.
    fn rules(&self) -> &'static [Rule];
    /// Runs the check. Missing files are not errors: they just mean nothing
    /// is exposed there.
    fn run(&self, ctx: &Context) -> Vec<Finding>;
}

/// Checks for `heldkeys scan`: this machine or container as the agent sees it.
pub fn local_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(env::EnvCheck),
        Box::new(aws::AwsCheck),
        Box::new(gcloud::GcloudCheck),
        Box::new(azure::AzureCheck),
        Box::new(kube::KubeCheck),
        Box::new(docker::DockerCheck),
        Box::new(netrc::NetrcCheck),
        Box::new(git_credentials::GitCredentialsCheck),
        Box::new(npmrc::NpmrcCheck),
        Box::new(pypirc::PypircCheck),
        Box::new(cargo_credentials::CargoCredentialsCheck),
        Box::new(cli_logins::CliLoginsCheck),
        Box::new(dotenv::DotenvCheck),
        Box::new(ssh_agent::SshAgentCheck),
        Box::new(git_helper::GitHelperCheck),
        Box::new(git_config::GitConfigCheck),
        Box::new(mcp::McpCheck),
        Box::new(cli_logins::AiLoginsCheck),
        Box::new(docker_socket::DockerSocketCheck),
        Box::new(k8s_service_account::K8sServiceAccountCheck),
        Box::new(cloud_metadata::CloudMetadataCheck),
        // Listed for `heldkeys checks` and its rule; its findings are added
        // by `run_all` in every mode.
        Box::new(read_errors::ReadErrorsCheck),
    ]
}

/// Checks for `heldkeys ci`: the CI job's runtime plus its workflow files.
pub fn ci_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(ci_runtime::CiRuntimeCheck),
        Box::new(workflows::WorkflowsCheck),
        Box::new(repo_secrets::RepoSecretsCheck),
        // The repository half of `git-config`: a token in the checkout's
        // remote URL is readable by every step of the job.
        Box::new(git_config::RepoGitConfigCheck),
    ]
}

/// Every check of both modes, each id once (`git-config` runs in both, with
/// the same rules). For listings of rules: SARIF, docs.
pub fn all_checks() -> Vec<Box<dyn Check>> {
    let mut seen = std::collections::BTreeSet::new();
    local_checks()
        .into_iter()
        .chain(ci_checks())
        .filter(|c| seen.insert(c.id()))
        .collect()
}

/// Reads a home-level JSON config, recording it for `read-errors` when it
/// exists but cannot be read or is not valid JSON. An empty file holds
/// nothing and is skipped silently; a byte order mark is ignored.
pub fn read_json(ctx: &Context, path: &std::path::Path) -> Option<serde_json::Value> {
    let text = ctx.read_file(path)?;
    let text = crate::jsonc::strip_bom(&text);
    if text.trim().is_empty() {
        return None;
    }
    match serde_json::from_str(text) {
        Ok(value) => Some(value),
        Err(_) => {
            ctx.note_unreadable(path, "not valid JSON");
            None
        }
    }
}

/// Reads a home-level YAML config, recording it for `read-errors` when it
/// exists but cannot be read, is not valid YAML or is over the YAML budget.
pub fn read_yaml(ctx: &Context, path: &std::path::Path) -> Option<crate::yaml::Yaml> {
    let text = ctx.read_file(path)?;
    match crate::yaml::load_checked(&text) {
        Ok(doc) => Some(doc),
        Err(reason) => {
            ctx.note_unreadable(path, reason);
            None
        }
    }
}

/// Runs every check and returns all findings, sorted for stable output.
/// Files the checks could not read or parse are added last, as Info
/// findings of the `read-errors` check.
pub fn run_all(checks: &[Box<dyn Check>], ctx: &Context) -> Vec<Finding> {
    let mut findings: Vec<Finding> = checks.iter().flat_map(|c| c.run(ctx)).collect();
    findings.extend(read_errors::findings(ctx));
    crate::finding::sort_findings(&mut findings);
    findings
}

/// Helpers for the unit tests of individual checks.
#[cfg(test)]
pub(crate) mod testutil {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use crate::context::Context;

    /// `tests/fixtures/<case>`.
    pub fn fixture(case: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(case)
    }

    /// A context whose root, home and cwd are the fixture, with an empty
    /// environment. Root points at the fixture too, so system paths such as
    /// /var/run/docker.sock are looked up inside it, never on this machine.
    pub fn fixture_ctx(case: &str) -> Context {
        let dir = fixture(case);
        Context::new(dir.clone(), dir.clone(), dir, BTreeMap::new())
    }

    /// A context rooted at `dir` with the given environment.
    pub fn ctx_with_env(dir: &Path, env: &[(&str, &str)]) -> Context {
        let env = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Context::new(dir.to_path_buf(), dir.to_path_buf(), dir.to_path_buf(), env)
    }

    /// Writes `contents` to `dir/relative`, creating parent directories.
    pub fn write(dir: &Path, relative: &str, contents: &str) {
        let path = dir.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::testutil::{fixture, fixture_ctx};
    use super::*;
    use crate::context::Context;

    /// A check that runs in both modes has the same rules in both.
    #[test]
    fn checks_in_both_modes_agree() {
        let local = local_checks();
        for ci in ci_checks() {
            if let Some(l) = local.iter().find(|l| l.id() == ci.id()) {
                let ids = |c: &dyn Check| c.rules().iter().map(|r| r.id).collect::<Vec<_>>();
                assert_eq!(ids(l.as_ref()), ids(ci.as_ref()), "{}", ci.id());
            }
        }
    }

    #[test]
    fn check_and_rule_ids_are_unique_and_well_formed() {
        let re = regex::Regex::new(r"^HK-[A-Z0-9]+-[0-9]{3}$").unwrap();
        let mut check_ids = BTreeSet::new();
        let mut rule_ids = BTreeSet::new();
        for check in all_checks() {
            assert!(
                check_ids.insert(check.id()),
                "duplicate check {}",
                check.id()
            );
            for rule in check.rules() {
                assert_eq!(rule.check, check.id(), "{}", rule.id);
                assert!(re.is_match(rule.id), "bad rule id {}", rule.id);
                assert!(rule_ids.insert(rule.id), "duplicate rule {}", rule.id);
                assert!(!rule.summary.is_empty());
            }
        }
    }

    #[test]
    fn every_finding_uses_a_declared_rule() {
        let declared: BTreeMap<&str, Vec<&str>> = all_checks()
            .iter()
            .map(|c| (c.id(), c.rules().iter().map(|r| r.id).collect()))
            .collect();
        let mut contexts: Vec<Context> = ["full", "aws-sso", "gh-keyring"]
            .iter()
            .map(|c| fixture_ctx(c))
            .collect();
        let mut project = fixture_ctx("empty");
        project.cwd = fixture("project");
        project.env.insert(
            "GITHUB_TOKEN".into(),
            "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000101".into(),
        );
        project.env.insert(
            "MY_SERVICE_PASSWORD".into(),
            "FAKEservicePASSWORD0103".into(),
        );
        project.env.insert(
            "AWS_SECRET_ACCESS_KEY".into(),
            "FAKEawsSECRETfromENVfakeFAKE0104".into(),
        );
        contexts.push(project);
        let mut logins = fixture_ctx("logins/home");
        logins.cwd = fixture("logins/project");
        contexts.push(logins);
        let mut seen = 0;
        for ctx in &contexts {
            for f in run_all(&all_checks(), ctx) {
                let rules = &declared[f.check];
                assert!(
                    rules.contains(&f.rule),
                    "{} not declared by {}",
                    f.rule,
                    f.check
                );
                seen += 1;
            }
        }
        assert!(seen > 30, "{seen}");
    }

    #[test]
    fn empty_json_configs_are_skipped_silently() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = testutil::ctx_with_env(dir.path(), &[]);
        let path = dir.path().join("config.json");
        for (text, value) in [
            ("", None),
            (" \n", None),
            ("\u{feff}{}", Some(serde_json::json!({}))),
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(read_json(&ctx, &path), value, "{text:?}");
        }
        assert!(ctx.take_unreadable().is_empty());
        std::fs::write(&path, "{ nope").unwrap();
        assert_eq!(read_json(&ctx, &path), None);
        assert_eq!(ctx.take_unreadable()[0].1, "not valid JSON");
    }

    /// `--strict` fails on these; each must be a rule some check declares.
    #[test]
    fn not_analysed_rules_are_declared() {
        let declared: BTreeSet<&str> = all_checks()
            .iter()
            .flat_map(|c| c.rules().iter().map(|r| r.id))
            .collect();
        for id in read_errors::NOT_ANALYSED_RULES {
            assert!(declared.contains(id), "{id}");
        }
    }

    /// Titles fit the text report's title column (about 44 characters), so
    /// they are never cut mid-phrase. Workflow and CI titles are checked in
    /// their own modules.
    #[test]
    fn local_titles_are_short() {
        let mut contexts: Vec<Context> = ["full", "aws-sso", "gh-keyring", "leaky/home"]
            .iter()
            .map(|c| fixture_ctx(c))
            .collect();
        let mut project = fixture_ctx("empty");
        project.cwd = fixture("project");
        contexts.push(project);
        let mut leaky = fixture_ctx("leaky/home");
        leaky.cwd = fixture("leaky/project");
        contexts.push(leaky);
        let mut logins = fixture_ctx("logins/home");
        logins.cwd = fixture("logins/project");
        contexts.push(logins);
        for ctx in &contexts {
            for f in run_all(&local_checks(), ctx) {
                assert!(
                    f.title.chars().count() <= 44,
                    "{}: {:?} is {} characters",
                    f.rule,
                    f.title,
                    f.title.chars().count()
                );
            }
        }
    }
}
