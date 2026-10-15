//! The HK-WF rules: one function per rule, each turning what the analysis
//! found about an agent step into a finding (or nothing).

use super::agents::{action_name, is_sha};
use super::job::AgentStep;
use super::secrets::{Excess, excess_reason};
use super::shell::shell_grants;
use super::triggers::{Permissions, TokenAccess};
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::sanitize::clip;

const ID: &str = super::ID;

pub(super) const UNTRUSTED_TRIGGER: Rule = Rule {
    check: ID,
    id: "HK-WF-001",
    summary: "AI agent step on an untrusted trigger, holding secrets or write permissions",
};

pub(super) const PR_HEAD_CHECKOUT: Rule = Rule {
    check: ID,
    id: "HK-WF-002",
    summary: "AI agent step runs in a checkout of the PR head on an untrusted trigger",
};

pub(super) const BROAD_PERMISSIONS: Rule = Rule {
    check: ID,
    id: "HK-WF-003",
    summary: "AI agent step in a job with write-all or unrestricted default permissions",
};

pub(super) const EXCESS_SECRETS: Rule = Rule {
    check: ID,
    id: "HK-WF-004",
    summary: "AI agent step receives secrets it does not need",
};

pub(super) const UNPINNED_AGENT: Rule = Rule {
    check: ID,
    id: "HK-WF-005",
    summary: "AI agent action pinned to a tag or branch, not a commit SHA",
};

pub(super) const SHELL_WITH_WRITE: Rule = Rule {
    check: ID,
    id: "HK-WF-006",
    summary: "AI agent allowed to run any shell command while holding a write token",
};

pub(super) const NOT_ANALYSED: Rule = Rule {
    check: ID,
    id: "HK-WF-007",
    summary: "Workflow file that could not be analysed (context)",
};

pub(super) const RULES: &[Rule] = &[
    UNTRUSTED_TRIGGER,
    PR_HEAD_CHECKOUT,
    BROAD_PERMISSIONS,
    EXCESS_SECRETS,
    UNPINNED_AGENT,
    SHELL_WITH_WRITE,
    NOT_ANALYSED,
];

fn secret_names(step: &AgentStep) -> Vec<String> {
    let mut names: Vec<String> = step
        .secrets
        .iter()
        .map(|u| match &u.secret {
            Some(s) => clip(s),
            None => "all secrets".to_string(),
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// HK-WF-001.
pub(super) fn untrusted_trigger(
    untrusted: &[String],
    step: &AgentStep,
    access: &TokenAccess,
    gate: Option<&str>,
) -> Option<Finding> {
    if untrusted.is_empty() {
        return None;
    }
    let secrets = secret_names(step);
    let (mut severity, lifetime, access_kind) = match access {
        TokenAccess::Write(_) | TokenAccess::RepoDefault => {
            (Severity::High, Lifetime::ShortLived, Access::Write)
        }
        TokenAccess::ReadOnly if !secrets.is_empty() => {
            (Severity::Medium, Lifetime::LongLived, Access::Unknown)
        }
        TokenAccess::ReadOnly => return None,
    };
    let mut detail = format!(
        "{} on {}; holds a {}",
        step.agent.name,
        untrusted.join(", "),
        access.summary()
    );
    if !secrets.is_empty() {
        detail.push_str(&format!(" and secrets {}", secrets.join(", ")));
    }
    if let Some(gate) = gate {
        // An actor check helps, but the agent still reads text others wrote
        // (the issue body, earlier comments, the PR diff).
        severity = if severity == Severity::High {
            Severity::Medium
        } else {
            Severity::Low
        };
        detail.push_str(&format!(
            "; {gate}, but the agent still reads text others wrote"
        ));
    }
    Some(
        Finding::new(
            UNTRUSTED_TRIGGER,
            "AI agent on an untrusted trigger",
            &step.location,
            severity,
            lifetime,
            access_kind,
            "Give the agent job read-only permissions and only its model key; move write actions to a separate job that does not read untrusted text.",
        )
        .with_detail(detail),
    )
}

/// HK-WF-002.
pub(super) fn pr_head_checkout(untrusted: &[String], step: &AgentStep, how: &str) -> Finding {
    Finding::new(
        PR_HEAD_CHECKOUT,
        "AI agent runs in a checkout of the PR head",
        &step.location,
        Severity::High,
        Lifetime::ShortLived,
        Access::Write,
        "Check out the base branch for the agent (default ref); give it the PR diff as data, never the PR's files as its working tree.",
    )
    .with_detail(format!(
        "{how} on {}; the agent then loads attacker-controlled .mcp.json, CLAUDE.md, AGENTS.md, .claude/ or .cursor/ from the PR (the CVE-2026-47751 pattern)",
        untrusted.join(", ")
    ))
}

/// HK-WF-003.
pub(super) fn broad_permissions(
    step: &AgentStep,
    permissions: &Permissions,
    job_id: &str,
) -> Option<Finding> {
    let job_id = clip(job_id);
    let (severity, detail) = match permissions {
        Permissions::WriteAll => (
            Severity::High,
            format!(
                "jobs.{job_id} runs with permissions: write-all; a hijacked {} can push code, edit issues and PRs, and start workflows",
                step.agent.name
            ),
        ),
        Permissions::Default => (
            Severity::Medium,
            format!(
                "no permissions: block on jobs.{job_id}{}; the token depends on the repository default (write-all on older repos and orgs). Set permissions explicitly",
                if step.called {
                    ", its workflow or its callers"
                } else {
                    " or the workflow"
                }
            ),
        ),
        _ => return None,
    };
    Some(
        Finding::new(
            BROAD_PERMISSIONS,
            "AI agent job with broad token permissions",
            &step.location,
            severity,
            Lifetime::ShortLived,
            if *permissions == Permissions::WriteAll { Access::Write } else { Access::Unknown },
            "Add a job-level permissions: block with only what the agent needs (for example contents: read).",
        )
        .with_detail(detail),
    )
}

/// HK-WF-004.
pub(super) fn excess_secrets(step: &AgentStep, copilot_setup: bool) -> Option<Finding> {
    let mut reasons: Vec<String> = Vec::new();
    let mut severity = Severity::Medium;
    for u in &step.secrets {
        // In Copilot setup, every secret counts: none of them is the agent's own key.
        let excess = if copilot_setup {
            Some(Excess {
                reason: format!(
                    "{} via {}",
                    u.secret.as_deref().unwrap_or("the whole secrets context"),
                    u.via
                ),
                severity: if u.secret.is_none() {
                    Severity::High
                } else {
                    Severity::Medium
                },
            })
        } else {
            excess_reason(step.agent, step.backend, u)
        };
        if let Some(excess) = excess
            && !reasons.contains(&excess.reason)
        {
            reasons.push(excess.reason);
            if excess.severity.rank() > severity.rank() {
                severity = excess.severity;
            }
        }
    }
    if let Some(caller) = &step.inherit_from {
        // Only the secrets the callee names reach the agent today, but every
        // one of them is a single edit (or a hijacked step) away.
        reasons.push(format!(
            "every repository secret through secrets: inherit at {caller}"
        ));
    }
    if reasons.is_empty() {
        return None;
    }
    let mut detail = format!("{} receives {}", step.agent.name, reasons.join("; "));
    if copilot_setup {
        detail.push_str("; setup steps run in the agent's environment, so anything they export or write to disk stays reachable");
    }
    Some(
        Finding::new(
            EXCESS_SECRETS,
            "Agent step gets secrets it does not need",
            &step.location,
            severity,
            Lifetime::LongLived,
            Access::Unknown,
            if step.inherit_from.is_some() {
                "Pass the called workflow only its model key (secrets: { NAME: ${{ secrets.NAME }} }) instead of secrets: inherit, and use OIDC instead of cloud keys."
            } else {
                "Pass the agent only its model key; run steps that need other secrets in a separate job, and use OIDC instead of cloud keys."
            },
        )
        .with_detail(detail),
    )
}

/// HK-WF-005.
pub(super) fn unpinned(step: &AgentStep) -> Option<Finding> {
    let uses = step.uses.as_deref()?;
    if uses.starts_with("./") || uses.starts_with("docker://") {
        return None;
    }
    let reference = uses.split_once('@').map(|(_, r)| r).unwrap_or("");
    if is_sha(reference) {
        return None;
    }
    let what = if reference.is_empty() {
        "no ref".to_string()
    } else {
        format!("ref {}, which can be moved to other code", clip(reference))
    };
    Some(
        Finding::new(
            UNPINNED_AGENT,
            "AI agent action not pinned to a commit SHA",
            &step.location,
            Severity::Medium,
            Lifetime::Unknown,
            Access::Unknown,
            "Pin the action to a full commit SHA with the version in a comment (uses: owner/action@<sha> # v1.2.3).",
        )
        .with_detail(format!(
            "{} at {what}; whoever controls that ref controls an agent holding this job's token and secrets",
            clip(action_name(uses))
        )),
    )
}

/// HK-WF-006.
pub(super) fn shell_with_write(step: &AgentStep, access: &TokenAccess) -> Option<Finding> {
    let grants = shell_grants(step.node);
    if grants.is_empty() {
        return None;
    }
    let severity = match access {
        TokenAccess::Write(_) => Severity::High,
        TokenAccess::RepoDefault => Severity::Medium,
        TokenAccess::ReadOnly => return None,
    };
    Some(
        Finding::new(
            SHELL_WITH_WRITE,
            if severity == Severity::High {
                "Agent runs any shell with write token"
            } else {
                "Agent runs any shell; token may write"
            },
            &step.location,
            severity,
            Lifetime::ShortLived,
            if severity == Severity::High { Access::Write } else { Access::Unknown },
            "Allow only read-only commands that run no repository code (for example Bash(gh pr diff:*)), or make the job's token read-only.",
        )
        .with_detail(format!("{}; {}", grants.join(", "), access.summary())),
    )
}

/// HK-WF-007: a workflow file heldkeys could not read, parse or follow, so
/// its agent steps (if any) went unchecked.
pub(super) fn not_analysed(location: &str, file: &str, reason: &str) -> Finding {
    Finding::new(
        NOT_ANALYSED,
        "Workflow file not analysed",
        location,
        Severity::Info,
        Lifetime::Unknown,
        Access::Unknown,
        "Check this workflow by hand, or fix what kept heldkeys from reading it: its agent steps were not checked.",
    )
    .with_detail(format!("could not analyse {}: {reason}", clip(file)))
}
