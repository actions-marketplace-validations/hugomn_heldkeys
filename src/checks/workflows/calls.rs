//! Following local reusable-workflow calls without exponential fan-out.
//!
//! Read naively, a chain `a -> b -> c -> d` in which every workflow has N
//! jobs calling the next one reaches `d` N^3 times, and each visit repeats
//! the same findings with a different caller prefix: with N = 30 that is
//! millions of findings from a few kilobytes of YAML a pull request can add.
//!
//! So calls are followed in two passes. The first builds a graph of called
//! workflows, one node per callee and distinct effective context (the
//! caller's untrusted triggers, token ceiling, the secrets that reach it,
//! whether a caller gates on the actor, whether `secrets: inherit` holds all
//! the way down, and the call depth), and records every caller job of each
//! node. A node already in the graph only gains a caller; it is not walked
//! again. The second pass analyses each node's jobs once. A finding reached
//! through a single chain of callers keeps the full chain in its location;
//! one reached from several callers is reported once, at the callee, with up
//! to `SHOWN_CALLERS` caller locations in its detail.
//!
//! On top of that, at most `MAX_CALLED_JOB_VISITS` jobs are analysed through
//! calls; past that, calls are not followed and one Info finding says so.

use std::collections::HashMap;

use super::job::{Emit, analyze_job};
use super::reusable::{JobCall, MAX_CALL_DEPTH, Reach, job_call};
use super::triggers::{Permissions, is_actor_gate};
use super::{WorkflowFile, Workflows, rules};
use crate::finding::Finding;
use crate::sanitize::clip;
use crate::yaml::{self, Yaml};

/// Most jobs analysed through local reusable-workflow calls, counting each
/// called job once per distinct context it is reached in.
pub(super) const MAX_CALLED_JOB_VISITS: usize = 2_000;
/// How many caller locations a finding reached from several callers lists.
const SHOWN_CALLERS: usize = 3;

/// A called workflow, in one effective context.
struct Node<'a> {
    target: &'a WorkflowFile,
    /// How the first caller reached it. Every caller of this node reaches it
    /// with the same triggers, token, secrets and gates; only the caller
    /// locations differ.
    reach: Reach,
    /// The caller jobs: the node they run in (`None` for a workflow on its
    /// own triggers) and their position, e.g. `.github/workflows/a.yml:12 jobs.x`.
    callers: Vec<(Option<usize>, String)>,
}

pub(super) struct CallGraph<'a> {
    all: &'a Workflows,
    nodes: Vec<Node<'a>>,
    by_context: HashMap<String, usize>,
    visits: usize,
    capped: bool,
    /// HK-WF-007 findings for calls that were not followed.
    findings: Vec<Finding>,
}

impl<'a> CallGraph<'a> {
    pub(super) fn new(all: &'a Workflows) -> CallGraph<'a> {
        CallGraph {
            all,
            nodes: Vec::new(),
            by_context: HashMap::new(),
            visits: 0,
            capped: false,
            findings: Vec::new(),
        }
    }

    /// Follows `wf`'s job `job_id`, a call to a local reusable workflow, made
    /// by a workflow reached as `reach` (running in node `from`).
    pub(super) fn follow(
        &mut self,
        wf: &'a WorkflowFile,
        reach: &Reach,
        from: Option<usize>,
        job_id: &str,
        job: &Yaml,
    ) {
        let caller = wf.position(&format!("jobs.{job_id}"));
        let callee = match job_call(job) {
            JobCall::Local(callee) => callee,
            JobCall::Unfollowed(uses) => {
                let shown: String = uses.chars().take(100).collect();
                self.findings.push(rules::not_analysed(
                    &caller,
                    &shown,
                    "local reusable workflow outside .github/workflows not followed",
                ));
                return;
            }
            JobCall::None => return,
        };
        let callee_file = format!(".github/workflows/{}", clip(callee));
        let chain = || {
            let mut names: Vec<String> = reach.chain.iter().map(|n| clip(n)).collect();
            names.push(clip(callee));
            names.join(" -> ")
        };
        if reach.chain.iter().any(|n| n == callee) {
            let reason = format!("called in a cycle ({})", chain());
            self.findings
                .push(rules::not_analysed(&caller, &callee_file, &reason));
            return;
        }
        if reach.chain.len() > MAX_CALL_DEPTH {
            let reason = format!(
                "more than {MAX_CALL_DEPTH} reusable-workflow calls deep ({}), which heldkeys does not follow",
                chain()
            );
            self.findings
                .push(rules::not_analysed(&caller, &callee_file, &reason));
            return;
        }
        let all = self.all;
        let Some(target) = all.get(callee) else {
            if !all.failed.contains(callee) {
                // (A file that failed to load has its own Info finding.)
                let reason = format!("{caller} calls it, but there is no such file");
                self.findings
                    .push(rules::not_analysed(&caller, &callee_file, &reason));
            }
            return;
        };
        let own = Permissions::parse(&job["permissions"])
            .or_else(|| Permissions::parse(&wf.doc["permissions"]));
        let needs_gated = wf.needs_gated.contains(job_id);
        let inner = reach.call(&caller, job, own, callee, needs_gated);
        let key = context_key(callee, &inner);
        if let Some(&node) = self.by_context.get(&key) {
            self.nodes[node].callers.push((from, caller));
            return;
        }
        let jobs = yaml::entries(&target.doc["jobs"]).len();
        if self.visits + jobs > MAX_CALLED_JOB_VISITS {
            if !self.capped {
                self.capped = true;
                let reason = format!(
                    "local reusable-workflow calls reach more than {MAX_CALLED_JOB_VISITS} jobs; heldkeys stopped following calls here and at every later call"
                );
                self.findings
                    .push(rules::not_analysed(&caller, &callee_file, &reason));
            }
            return;
        }
        self.visits += jobs;
        let node = self.nodes.len();
        self.nodes.push(Node {
            target,
            reach: inner.clone(),
            callers: vec![(from, caller)],
        });
        self.by_context.insert(key, node);
        for (job_id, job) in yaml::entries(&target.doc["jobs"]) {
            self.follow(target, &inner, Some(node), job_id, job);
        }
    }

    /// The findings of every called workflow, each analysed once per
    /// context, plus the Info findings for calls that were not followed.
    pub(super) fn into_findings(self) -> Vec<Finding> {
        let mut findings = self.findings.clone();
        for (i, node) in self.nodes.iter().enumerate() {
            let (via, note) = self.route(i);
            let mut reach = node.reach.clone();
            reach.via = via;
            for (job_id, job) in yaml::entries(&node.target.doc["jobs"]) {
                if !matches!(job_call(job), JobCall::None) {
                    continue; // followed in the first pass
                }
                for mut finding in
                    analyze_job(node.target, &reach, Emit::ThroughCaller, job_id, job)
                {
                    if let Some(note) = &note {
                        let detail = finding.detail.take().unwrap_or_default();
                        finding.detail = Some(format!("{detail}; {note}"));
                    }
                    findings.push(finding);
                }
            }
        }
        findings
    }

    /// The caller prefix for node `i`'s findings (`a.yml:3 jobs.x -> ` for
    /// each caller, outermost first) as far up as the chain has a single
    /// caller, and, where it has several, a note listing them.
    fn route(&self, i: usize) -> (String, Option<String>) {
        let node = &self.nodes[i];
        if let [(from, position)] = node.callers.as_slice() {
            let (via, note) = match from {
                Some(parent) => self.route(*parent),
                None => (String::new(), None),
            };
            return (format!("{via}{position} -> "), note);
        }
        let mut positions: Vec<&str> = Vec::new();
        for (_, position) in &node.callers {
            if !positions.contains(&position.as_str()) {
                positions.push(position);
            }
        }
        let shown = positions
            .iter()
            .take(SHOWN_CALLERS)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        let more = match positions.len().saturating_sub(SHOWN_CALLERS) {
            0 => String::new(),
            n => format!(" +{n} more"),
        };
        let note = format!(
            "{} is reached from {} callers: {shown}{more}",
            clip(&node.target.file),
            positions.len()
        );
        (String::new(), Some(note))
    }
}

/// What makes two calls to `callee` analyse the same: everything in `reach`
/// that a finding depends on, except the caller locations.
fn context_key(callee: &str, reach: &Reach) -> String {
    let gated = reach.needs_gate || reach.conditions.iter().any(|c| is_actor_gate(c));
    format!(
        "{callee}|{:?}|{:?}|{:?}|{gated}|{}|{}",
        reach.untrusted,
        reach.ceiling,
        reach.available,
        reach.inherit_from.is_some(),
        reach.chain.len()
    )
}
