//! One job: find its agent steps, work out what each one holds, and apply
//! the rules.

use super::WorkflowFile;
use super::agents::{
    AgentAction, CLI_AGENT, COPILOT_AGENT, COPILOT_SETUP_FILES, COPILOT_SETUP_JOB, CloudBackend,
    agent_command, cloud_backend, known_action, short_uses,
};
use super::checkout::head_checkout;
use super::reusable::Reach;
use super::rules;
use super::secrets::{SecretUse, is_github_token_key, is_pat_name, secrets_in_map, step_secrets};
use super::triggers::{Permissions, TokenAccess, is_actor_gate};
use crate::finding::Finding;
use crate::yaml::{self, Yaml};

/// One agent step (or agent job) found in a workflow.
pub(super) struct AgentStep<'a> {
    pub agent: &'a AgentAction,
    /// e.g. `.github/workflows/x.yml:12 jobs.review.steps[1] (uses: ...)`,
    /// preceded by the callers for a called workflow.
    pub location: String,
    /// The `uses:` value, for pinning checks. `None` for run steps.
    pub uses: Option<String>,
    /// The step node (or the job node for reusable workflows and Copilot setup).
    pub node: &'a Yaml,
    /// Index of the step in the job, `None` for job-level agents.
    pub index: Option<usize>,
    pub secrets: Vec<SecretUse>,
    /// The cloud model backend the step selects, if any.
    pub backend: Option<CloudBackend>,
    /// The caller job whose `secrets: inherit` hands this step's workflow
    /// every repository secret.
    pub inherit_from: Option<String>,
    /// True when the step's workflow is reached through a caller.
    pub called: bool,
}

/// Which rules a pass over a job reports.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Emit {
    /// A workflow on its own triggers: every rule.
    All,
    /// A workflow only ever reached through local callers, read on its own:
    /// only pinning, which does not depend on the caller. The rest is
    /// reported through each caller, with the caller's triggers and token.
    PinningOnly,
    /// A workflow read through a caller: everything but pinning, which its
    /// own pass reports once.
    ThroughCaller,
}

pub(super) fn analyze_job(
    wf: &WorkflowFile,
    reach: &Reach,
    emit: Emit,
    job_id: &str,
    job: &Yaml,
) -> Vec<Finding> {
    let own = Permissions::parse(&job["permissions"])
        .or_else(|| Permissions::parse(&wf.doc["permissions"]));
    let permissions = Permissions::effective(own, reach.ceiling.as_ref());
    // Env set on the workflow and the job reaches every step, agents included.
    let mut inherited = secrets_in_map(&wf.doc["env"], "env");
    inherited.extend(secrets_in_map(&job["env"], &format!("jobs.{job_id}.env")));

    let agents = find_agents(wf, reach, job_id, job, &inherited);
    let steps = yaml::list_at(job, "steps");
    // The first step that checks out the PR head, if any.
    let checkout = steps
        .iter()
        .enumerate()
        .find_map(|(i, s)| head_checkout(s).map(|how| (i, how)));

    let pinning = emit != Emit::ThroughCaller;
    let risks = emit != Emit::PinningOnly;
    let untrusted = &reach.untrusted;
    let mut findings = Vec::new();
    for step in &agents {
        let access = token_access(&permissions, step);
        let copilot_setup = std::ptr::eq(step.agent, &COPILOT_AGENT);
        if pinning && !copilot_setup {
            findings.extend(rules::unpinned(step));
        }
        if !risks {
            continue;
        }
        if !copilot_setup {
            let needs_gated = reach.needs_gate || wf.needs_gated.contains(job_id);
            let gate = actor_gate(job, step, &reach.conditions, needs_gated);
            findings.extend(rules::untrusted_trigger(untrusted, step, &access, gate));
            if let (Some((at, how)), Some(index)) = (&checkout, step.index)
                && *at < index
                && !untrusted.is_empty()
            {
                findings.push(rules::pr_head_checkout(untrusted, step, how));
            }
            findings.extend(rules::broad_permissions(step, &permissions, job_id));
            findings.extend(rules::shell_with_write(step, &access));
        }
        findings.extend(rules::excess_secrets(step, copilot_setup));
    }
    findings
}

/// The agent steps of a job, plus the job itself when it is an agent
/// reusable workflow or the Copilot setup job. Secrets the callers do not
/// pass are left out: the step cannot get them.
fn find_agents<'a>(
    wf: &WorkflowFile,
    reach: &Reach,
    job_id: &str,
    job: &'a Yaml,
    inherited: &[SecretUse],
) -> Vec<AgentStep<'a>> {
    let mut agents = Vec::new();
    let job_path = format!("jobs.{job_id}");
    let location = |path: &str, what: &str| format!("{}{}", reach.via, wf.location(path, what));
    let reachable = |secrets: Vec<SecretUse>| -> Vec<SecretUse> {
        secrets
            .into_iter()
            .filter(|u| reach.available.allows(u))
            .collect()
    };
    let step_for = |agent, location, uses, node, index, secrets, backend| AgentStep {
        agent,
        location,
        uses,
        node,
        index,
        secrets: reachable(secrets),
        backend,
        inherit_from: reach.inherit_from.clone(),
        called: reach.is_called(),
    };

    if COPILOT_SETUP_FILES.contains(&wf.name.as_str()) && job_id == COPILOT_SETUP_JOB {
        // Every step here runs in the environment Copilot later works in.
        let mut secrets = inherited.to_vec();
        for (i, step) in yaml::list_at(job, "steps").iter().enumerate() {
            secrets.extend(step_secrets(step, &format!("{job_path}.steps[{i}]")));
        }
        let at = location(&job_path, "Copilot coding agent setup");
        agents.push(step_for(&COPILOT_AGENT, at, None, job, None, secrets, None));
        return agents;
    }

    if let Some(uses) = yaml::str_at(job, "uses")
        && let Some(agent) = known_action(uses)
    {
        let mut secrets = secrets_in_map(&job["with"], "with");
        match &job["secrets"] {
            Yaml::String(s) if s == "inherit" => secrets.push(SecretUse {
                via: "secrets: inherit".to_string(),
                key: "secrets".to_string(),
                secret: None,
            }),
            node => secrets.extend(secrets_in_map(node, "secrets")),
        }
        let at = location(&job_path, &format!("uses: {}", short_uses(uses)));
        let uses = Some(uses.to_string());
        agents.push(step_for(agent, at, uses, job, None, secrets, None));
    }

    for (i, step) in yaml::list_at(job, "steps").iter().enumerate() {
        let path = format!("{job_path}.steps[{i}]");
        let (agent, what, uses) = if let Some(uses) = yaml::str_at(step, "uses") {
            match known_action(uses) {
                Some(agent) => (
                    agent,
                    format!("uses: {}", short_uses(uses)),
                    Some(uses.to_string()),
                ),
                None => continue,
            }
        } else if let Some(run) = yaml::str_at(step, "run") {
            match agent_command(run) {
                Some(cmd) => (&CLI_AGENT, format!("run: {cmd}"), None),
                None => continue,
            }
        } else {
            continue;
        };
        let mut secrets = inherited.to_vec();
        secrets.extend(step_secrets(step, &path));
        let at = location(&path, &what);
        let backend = cloud_backend(step);
        agents.push(step_for(agent, at, uses, step, Some(i), secrets, backend));
    }
    agents
}

/// What the agent's token can do in this job.
fn token_access(permissions: &Permissions, step: &AgentStep) -> TokenAccess {
    let mut why = permissions.write_scopes();
    if permissions.id_token_write() {
        why.push(id_token_use(step));
    }
    for u in &step.secrets {
        if let Some(secret) = &u.secret
            && (is_pat_name(secret) || is_github_token_key(&u.key))
        {
            why.push(format!("secret {secret} as {}", u.key));
        }
    }
    if !why.is_empty() {
        why.dedup();
        return TokenAccess::Write(why);
    }
    if *permissions == Permissions::Default {
        TokenAccess::RepoDefault
    } else {
        TokenAccess::ReadOnly
    }
}

/// What `id-token: write` lets this agent step do. claude-code-action trades
/// it for its GitHub App token unless a `github_token` input is given; with
/// Bedrock or Vertex selected it is also how the agent reaches its model.
fn id_token_use(step: &AgentStep) -> String {
    let app_token = step.agent.oidc_app_token && !yaml::has(&step.node["with"], "github_token");
    match (step.backend, app_token) {
        (Some(backend), true) => format!(
            "id-token: write, used to reach {} and exchanged for the Claude GitHub App token, which can write",
            backend.name()
        ),
        (Some(backend), false) => format!(
            "id-token: write, used to reach {}; it can also mint credentials for any other cloud role that trusts this repository",
            backend.name()
        ),
        (None, true) => {
            "id-token: write, exchanged for the Claude GitHub App token, which can write"
                .to_string()
        }
        (None, false) => "id-token: write, which can mint cloud credentials over OIDC".to_string(),
    }
}

/// What, if anything, restricts who can start the agent: an `if:` on the
/// actor or a trusted author association (on the step, its job, or a caller
/// job), the same on a job it needs (`needs_gated`, see
/// `triggers::needs_gated_jobs`), or the action's own write-access check.
fn actor_gate(
    job: &Yaml,
    step: &AgentStep,
    caller_conditions: &[String],
    needs_gated: bool,
) -> Option<&'static str> {
    let gated_if = |cond: &Yaml| cond.as_str().is_some_and(is_actor_gate);
    if gated_if(&job["if"])
        || gated_if(&step.node["if"])
        || caller_conditions.iter().any(|c| is_actor_gate(c))
    {
        return Some("gated by an if: on the actor");
    }
    if needs_gated {
        return Some("gated by an if: on the actor in a job it needs");
    }
    if step.agent.checks_actor_write && !yaml::has(&step.node["with"], "allowed_non_write_users") {
        return Some("the action only runs for users with write access");
    }
    None
}
