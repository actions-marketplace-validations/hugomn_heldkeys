//! Local reusable workflows (`jobs.<id>.uses: ./.github/workflows/x.yml`).
//!
//! A called workflow (`on: workflow_call`) runs on its caller's event, with
//! the token its caller job allows and only the secrets the caller passes.
//! run-gemini-cli's recommended setup is exactly this: a dispatcher on
//! `issue_comment` that calls a local review workflow with `secrets: inherit`.
//! Read on its own, the review workflow looks harmless (its only trigger is
//! `workflow_call`); read through its caller, it is an agent on an untrusted
//! trigger with a write token. So the analysis follows each local call and
//! carries the caller's triggers, permissions and secrets into the callee.

use super::secrets::{SecretUse, secrets_in};
use super::triggers::Permissions;
use crate::sanitize::clip;
use crate::yaml::{self, Yaml};

/// How many nested calls are followed. Deeper chains get an Info finding.
pub(super) const MAX_CALL_DEPTH: usize = 3;

/// Secrets a job can reference, as its callers decide.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Available {
    /// Every repository secret: a top-level workflow, or `secrets: inherit`
    /// all the way down.
    All,
    /// Only these names (what the caller passed under `secrets:`).
    Only(Vec<String>),
}

impl Available {
    pub(super) fn allows(&self, u: &SecretUse) -> bool {
        match (self, &u.secret) {
            (Available::All, _) => true,
            // toJSON(secrets) holds whatever was passed.
            (Available::Only(names), None) => !names.is_empty(),
            // `SecretUse` names are clipped for display; compare like with like.
            (Available::Only(names), Some(name)) => {
                let name = clip(name);
                names.iter().any(|n| clip(n).eq_ignore_ascii_case(&name))
            }
        }
    }

    /// What a callee gets from a caller job's `secrets:` value.
    pub(super) fn for_callee(&self, secrets: &Yaml) -> Available {
        if secrets.as_str() == Some("inherit") {
            return self.clone();
        }
        let names = yaml::entries(secrets)
            .into_iter()
            .filter(|(_, value)| {
                let passed = value.as_str().map(secrets_in).unwrap_or_default();
                passed.iter().any(|s| {
                    self.allows(&SecretUse {
                        via: String::new(),
                        key: String::new(),
                        secret: s.clone(),
                    })
                })
            })
            .map(|(name, _)| name.to_string())
            .collect();
        Available::Only(names)
    }
}

/// How a job is reached: from its own workflow's triggers, or through a
/// chain of local reusable-workflow calls.
#[derive(Debug, Clone)]
pub(super) struct Reach {
    /// Untrusted triggers of the workflow at the top of the chain.
    pub untrusted: Vec<String>,
    /// The permissions the caller jobs allow (`None` at the top).
    pub ceiling: Option<Permissions>,
    /// The secrets the callers pass down.
    pub available: Available,
    /// `a.yml:12 jobs.x -> ` for each caller, outermost first; empty at the top.
    pub via: String,
    /// `if:` conditions of the caller jobs, which also decide who can start it.
    pub conditions: Vec<String>,
    /// A caller job only runs when an actor gate on a job it needs let it
    /// through (see `triggers::needs_gated_jobs`).
    pub needs_gate: bool,
    /// The caller job (`a.yml:12 jobs.x`) whose `secrets: inherit` hands this
    /// workflow every repository secret, when every hop inherits.
    pub inherit_from: Option<String>,
    /// Workflow file names on the chain, outermost first, to stop cycles.
    pub chain: Vec<String>,
}

impl Reach {
    /// A workflow started by its own triggers.
    pub(super) fn top(name: &str, untrusted: Vec<String>) -> Reach {
        Reach {
            untrusted,
            ceiling: None,
            available: Available::All,
            via: String::new(),
            conditions: Vec::new(),
            needs_gate: false,
            inherit_from: None,
            chain: vec![name.to_string()],
        }
    }

    pub(super) fn is_called(&self) -> bool {
        self.chain.len() > 1
    }

    /// The reach of `callee`, called by `job` (at `caller`, e.g. `a.yml:12
    /// jobs.x`), whose own permissions block (job or workflow level) is `own`.
    /// `needs_gated`: the caller job only runs past an actor gate on a job it
    /// needs.
    pub(super) fn call(
        &self,
        caller: &str,
        job: &Yaml,
        own: Option<Permissions>,
        callee: &str,
        needs_gated: bool,
    ) -> Reach {
        let inherits = job["secrets"].as_str() == Some("inherit");
        let available = self.available.for_callee(&job["secrets"]);
        let inherit_from = (inherits && available == Available::All).then(|| {
            self.inherit_from
                .clone()
                .unwrap_or_else(|| caller.to_string())
        });
        let mut conditions = self.conditions.clone();
        if let Some(cond) = yaml::str_at(job, "if") {
            conditions.push(cond.to_string());
        }
        let mut chain = self.chain.clone();
        chain.push(callee.to_string());
        Reach {
            untrusted: self.untrusted.clone(),
            ceiling: Some(Permissions::effective(own, self.ceiling.as_ref())),
            available,
            via: format!("{}{caller} -> ", self.via),
            conditions,
            needs_gate: self.needs_gate || needs_gated,
            inherit_from,
            chain,
        }
    }
}

/// What a job's `uses:` calls.
#[derive(Debug, PartialEq)]
pub(super) enum JobCall<'a> {
    /// Nothing local: no `uses:`, or a workflow in another repository.
    None,
    /// A workflow file in `.github/workflows`, by file name.
    Local(&'a str),
    /// A local path heldkeys does not follow: outside `.github/workflows`
    /// (`./x.yml`, `./.github/workflows/../../x.yml`, `/abs/x.yml`), in a
    /// subdirectory, or not a `.yml` file.
    Unfollowed(&'a str),
}

/// What `job` calls. A job-level `uses:` is always a reusable workflow, so
/// any path that starts with `.` or `/` is meant to be a local one.
pub(super) fn job_call(job: &Yaml) -> JobCall<'_> {
    let Some(uses) = yaml::str_at(job, "uses") else {
        return JobCall::None;
    };
    if let Some(name) = local_workflow(uses) {
        return JobCall::Local(name);
    }
    let path = uses.trim();
    if path.starts_with('.') || path.starts_with('/') || path.starts_with('\\') {
        JobCall::Unfollowed(path)
    } else {
        JobCall::None
    }
}

/// The file name of a local reusable workflow: `./.github/workflows/x.yml`
/// gives `x.yml`. Anything else (another repository, a path outside
/// `.github/workflows`) gives `None`.
pub(super) fn local_workflow(uses: &str) -> Option<&str> {
    let name = uses
        .trim()
        .strip_prefix("./")?
        .strip_prefix(".github/workflows/")?;
    let valid = !name.is_empty()
        && !name.contains(['/', '\\', '@'])
        && (name.ends_with(".yml") || name.ends_with(".yaml"));
    valid.then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_workflow_paths() {
        assert_eq!(
            local_workflow("./.github/workflows/review.yml"),
            Some("review.yml")
        );
        assert_eq!(local_workflow("./.github/workflows/../x.yml"), None);
        assert_eq!(
            local_workflow("owner/repo/.github/workflows/x.yml@v1"),
            None
        );
        assert_eq!(local_workflow("./.github/actions/x"), None);
        assert_eq!(local_workflow("./.github/workflows/."), None);
    }

    #[test]
    fn job_calls() {
        let call = |uses: &str| {
            let job = yaml::load(&format!("uses: {uses:?}\n")).unwrap();
            format!("{:?}", job_call(&job))
        };
        assert_eq!(call("./.github/workflows/b.yml"), "Local(\"b.yml\")");
        assert_eq!(call("owner/repo/.github/workflows/x.yml@v1"), "None");
        for unfollowed in [
            "./.github/workflows/../../evil.yml",
            "/etc/passwd.yml",
            "./.github/workflows/.",
            "./ci/agent.yml",
            "../other/.github/workflows/x.yml",
            "./.github/workflows/sub/x.yml",
        ] {
            assert_eq!(call(unfollowed), format!("Unfollowed({unfollowed:?})"));
        }
        assert_eq!(
            job_call(&yaml::load("runs-on: x\n").unwrap()),
            JobCall::None
        );
    }

    #[test]
    fn secrets_the_caller_passes() {
        let job = yaml::load(
            "secrets:\n  GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}\n  LITERAL: not-a-secret\n",
        )
        .unwrap();
        let only = Available::All.for_callee(&job["secrets"]);
        assert_eq!(only, Available::Only(vec!["GEMINI_API_KEY".to_string()]));
        let inherit = yaml::load("secrets: inherit\n").unwrap();
        assert_eq!(only.for_callee(&inherit["secrets"]), only);
        assert_eq!(
            Available::All.for_callee(&Yaml::BadValue),
            Available::Only(Vec::new())
        );
    }
}
