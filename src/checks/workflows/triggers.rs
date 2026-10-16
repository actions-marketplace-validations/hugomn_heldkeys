//! Who can start a workflow, and what the job's token can do once it runs.

use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use regex::Regex;

use crate::sanitize::clip;
use crate::yaml::{self, Yaml};

/// Events an outsider can cause, and whose payload (an issue, a comment, a PR
/// from a fork) is text the attacker wrote, while the workflow runs with the
/// base repository's secrets and a token that can write. `pull_request` is not
/// here: on fork PRs it gets no secrets and a read-only token.
///
/// Shared with `ci_runtime`, which reports the event the running job got.
pub const UNTRUSTED_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "pull_request_review",
    "pull_request_review_comment",
    "workflow_run",
];

/// The event names in `on:`, in whichever of its three shapes.
pub(super) fn triggers(doc: &Yaml) -> Vec<String> {
    let on = &doc["on"];
    if let Some(s) = on.as_str() {
        return vec![s.to_string()];
    }
    if let Some(list) = on.as_vec() {
        return list
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect();
    }
    yaml::entries(on)
        .into_iter()
        .map(|(k, _)| k.to_string())
        .collect()
}

/// The untrusted events among a workflow's triggers.
pub(super) fn untrusted_triggers(doc: &Yaml) -> Vec<String> {
    triggers(doc)
        .into_iter()
        .filter(|t| UNTRUSTED_TRIGGERS.contains(&t.as_str()))
        .collect()
}

/// A `permissions:` block, or its absence.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Permissions {
    /// Not set on the job or the workflow: the repository default applies,
    /// which is write-all on repos created before February 2023 and in orgs
    /// that kept the old default.
    Default,
    WriteAll,
    ReadAll,
    /// Explicit scopes (`{}` is an empty list: no permissions at all).
    Scopes(Vec<(String, String)>),
}

impl Permissions {
    pub(super) fn parse(node: &Yaml) -> Option<Permissions> {
        if let Some(s) = node.as_str() {
            return Some(match s {
                "write-all" => Permissions::WriteAll,
                "read-all" => Permissions::ReadAll,
                _ => Permissions::Scopes(Vec::new()),
            });
        }
        if node.as_hash().is_some() {
            let scopes = yaml::entries(node)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.as_str().unwrap_or("").to_string()))
                .collect();
            return Some(Permissions::Scopes(scopes));
        }
        None
    }

    /// Scopes with write access, other than `id-token` (handled on its own).
    pub(super) fn write_scopes(&self) -> Vec<String> {
        match self {
            Permissions::WriteAll => vec!["write-all".to_string()],
            Permissions::Scopes(scopes) => scopes
                .iter()
                .filter(|(k, v)| v == "write" && k != "id-token")
                .map(|(k, _)| format!("{}: write", clip(k)))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The permissions a job gets from its own block (`own`, from the job or
    /// its workflow) under the ceiling its callers set (`None` when nothing
    /// calls it). A called workflow can keep or lower what its caller job
    /// grants, never raise it, and inherits it when it sets nothing.
    pub(super) fn effective(
        own: Option<Permissions>,
        ceiling: Option<&Permissions>,
    ) -> Permissions {
        match (own, ceiling) {
            (None, None) => Permissions::Default,
            (Some(own), None) => own,
            (None, Some(ceiling)) => ceiling.clone(),
            (Some(own), Some(ceiling)) => own.capped_by(ceiling),
        }
    }

    fn capped_by(self, ceiling: &Permissions) -> Permissions {
        match (self, ceiling) {
            // Unknown or unlimited ceiling: the callee's own block stands.
            (own, Permissions::Default | Permissions::WriteAll) => own,
            (Permissions::Default | Permissions::WriteAll, ceiling) => ceiling.clone(),
            (Permissions::ReadAll, Permissions::ReadAll) => Permissions::ReadAll,
            (Permissions::ReadAll, Permissions::Scopes(scopes)) => Permissions::Scopes(
                scopes
                    .iter()
                    .map(|(k, v)| (k.clone(), lower(v, "read").to_string()))
                    .collect(),
            ),
            (Permissions::Scopes(scopes), ceiling) => Permissions::Scopes(
                scopes
                    .into_iter()
                    .map(|(k, v)| {
                        let allowed = ceiling.level(&k);
                        let level = lower(&v, allowed).to_string();
                        (k, level)
                    })
                    .collect(),
            ),
        }
    }

    /// The access level (`write`, `read` or `none`) this block gives one scope.
    fn level(&self, scope: &str) -> &str {
        match self {
            Permissions::Default | Permissions::WriteAll => "write",
            Permissions::ReadAll if scope == "id-token" => "none",
            Permissions::ReadAll => "read",
            Permissions::Scopes(scopes) => scopes
                .iter()
                .find(|(k, _)| k == scope)
                .map(|(_, v)| v.as_str())
                .unwrap_or("none"),
        }
    }

    pub(super) fn id_token_write(&self) -> bool {
        match self {
            Permissions::WriteAll => true,
            Permissions::Scopes(scopes) => {
                scopes.iter().any(|(k, v)| k == "id-token" && v == "write")
            }
            _ => false,
        }
    }
}

/// The lower of two access levels.
fn lower<'a>(a: &'a str, b: &'a str) -> &'a str {
    let rank = |l: &str| match l {
        "write" => 2,
        "read" => 1,
        _ => 0,
    };
    if rank(a) <= rank(b) { a } else { b }
}

/// What the agent's token can do, as far as the workflow file tells us.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum TokenAccess {
    /// It can write; the strings say why ("contents: write", "secret GH_PAT").
    Write(Vec<String>),
    /// Permissions are not set, so it depends on the repository default.
    RepoDefault,
    ReadOnly,
}

impl TokenAccess {
    pub(super) fn summary(&self) -> String {
        match self {
            TokenAccess::Write(why) => format!("write token ({})", why.join(", ")),
            TokenAccess::RepoDefault => {
                "GITHUB_TOKEN with the repository default permissions (write-all on older repos and orgs)".to_string()
            }
            TokenAccess::ReadOnly => "read-only token".to_string(),
        }
    }
}

/// Comparisons that only let named people (or trusted roles) through. Each
/// is a positive check: `!=` never matches, and a `!` in front of a match is
/// rejected in `has_positive_gate`. Expressions are case-insensitive.
static ACTOR_EQUALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)github\.(?:triggering_)?actor\s*==\s*'[^']*'|'[^']*'\s*==\s*github\.(?:triggering_)?actor\b")
        .expect("valid regex")
});
static ACTOR_IN_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)contains\(\s*fromjson\([^()]*\)\s*,\s*github\.(?:triggering_)?actor\s*\)")
        .expect("valid regex")
});
static ASSOCIATION_EQUALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[\w.]*author_association\s*==\s*'(?:OWNER|MEMBER|COLLABORATOR)'|'(?:OWNER|MEMBER|COLLABORATOR)'\s*==\s*[\w.]*author_association\b")
        .expect("valid regex")
});
/// `contains(fromJSON('["OWNER","MEMBER"]'), x.author_association)` or
/// `contains('OWNER,MEMBER', x.author_association)`; the list is checked apart.
/// The value may pick one of several events' associations
/// (`a.author_association || b.author_association`).
static ASSOCIATION_IN_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)contains\(\s*(?:fromjson\(\s*'([^']*)'\s*\)|'([^']*)')\s*,\s*[\w.]*author_association(?:\s*\|\|\s*[\w.]*author_association)*\s*\)")
        .expect("valid regex")
});

/// A pull request from a branch of this repository, whose author can push
/// to it: `github.event.pull_request.head.repo.full_name == github.repository`.
static SAME_REPO_PR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository\b|github\.repository\s*==\s*github\.event\.pull_request\.head\.repo\.full_name\b")
        .expect("valid regex")
});
/// `github.event.pull_request.head.repo.fork == false`: only a gate next to
/// `PR_EVENT`, because on any other event the PR is null and `null == false`
/// is true in Actions expressions.
static NOT_A_FORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)github\.event\.pull_request\.head\.repo\.fork\s*==\s*false\b|\bfalse\s*==\s*github\.event\.pull_request\.head\.repo\.fork\b")
        .expect("valid regex")
});
static PR_EVENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)github\.event_name\s*==\s*'pull_request(?:_target)?'|'pull_request(?:_target)?'\s*==\s*github\.event_name\b")
        .expect("valid regex")
});

/// Author associations that mean "has write access to the repository".
const TRUSTED_ASSOCIATIONS: &[&str] = &["OWNER", "MEMBER", "COLLABORATOR"];

/// True if an `if:` condition restricts who can start the job: every way the
/// condition can be true goes through a positive check on the actor or on a
/// trusted author association. `github.actor != 'bot'` is not a gate, and
/// neither is `gate || anything`.
pub(super) fn is_actor_gate(cond: &str) -> bool {
    let expr = cond.trim();
    let expr = expr
        .strip_prefix("${{")
        .and_then(|e| e.strip_suffix("}}"))
        .unwrap_or(expr);
    if paren_depth(expr) > MAX_PAREN_DEPTH {
        return false; // not a condition anyone writes; not a gate either
    }
    let branches = disjuncts(expr);
    !branches.is_empty() && branches.iter().all(|b| has_positive_gate(b))
}

/// Deepest parenthesis nesting `is_actor_gate` reads. `disjuncts` recurses
/// once per level of a branch wrapped in parentheses, so a condition made of
/// 100 000 nested pairs would otherwise exhaust the stack.
const MAX_PAREN_DEPTH: usize = 32;

/// How deep parentheses outside quotes nest in `expr`.
fn paren_depth(expr: &str) -> usize {
    let (mut depth, mut max, mut quoted) = (0usize, 0usize, false);
    for c in expr.chars() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => {
                depth += 1;
                max = max.max(depth);
            }
            ')' if !quoted => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

fn has_positive_gate(text: &str) -> bool {
    // A match counts if it is code (an even number of quotes before it, so
    // not inside a string literal) and not negated with `!`. The quotes are
    // found once, so many matches in a long condition stay cheap.
    let quotes: Vec<usize> = text.match_indices('\'').map(|(i, _)| i).collect();
    let not_negated = |start: usize| {
        quotes.partition_point(|&q| q < start).is_multiple_of(2)
            && !text[..start].trim_end().ends_with('!')
    };
    let found = |re: &Regex| re.find_iter(text).any(|m| not_negated(m.start()));
    let simple = [
        &*ACTOR_EQUALS,
        &*ACTOR_IN_LIST,
        &*ASSOCIATION_EQUALS,
        &*SAME_REPO_PR,
    ]
    .iter()
    .any(|re| found(re));
    simple
        || (found(&NOT_A_FORK) && found(&PR_EVENT))
        || ASSOCIATION_IN_LIST.captures_iter(text).any(|c| {
            let whole = c.get(0).expect("match");
            let list = c.get(1).or(c.get(2)).map(|m| m.as_str()).unwrap_or("");
            let roles: Vec<String> = list
                .split(|ch: char| !ch.is_ascii_alphabetic() && ch != '_')
                .filter(|w| !w.is_empty())
                .map(str::to_ascii_uppercase)
                .collect();
            not_negated(whole.start())
                && !roles.is_empty()
                && roles
                    .iter()
                    .all(|r| TRUSTED_ASSOCIATIONS.contains(&r.as_str()))
        })
}

/// Status functions that let a job run although a job it needs was skipped
/// (`always()`, `failure()`, `cancelled()`, `!cancelled()`). Anywhere in the
/// `if:`, even in a string: missing a gate is the safe direction.
static STATUS_OVERRIDE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:always|failure|cancelled)\s*\(").expect("valid regex"));

/// The jobs of a workflow that only run when an actor gate let a job they
/// need through, directly or through other needs: a job is skipped when a
/// job it needs is skipped, unless its `if:` uses `always()`, `failure()`
/// or `cancelled()`, which also stops the gate from passing through it.
///
/// One pass in dependency order, so it stays linear in the number of jobs
/// and needs; jobs in a `needs:` cycle (which GitHub rejects) get no gate.
pub(super) fn needs_gated_jobs(doc: &Yaml) -> BTreeSet<String> {
    let jobs = yaml::entries(&doc["jobs"]);
    let index: HashMap<&str, usize> = jobs
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i))
        .collect();
    let mut needs: Vec<Vec<usize>> = jobs
        .iter()
        .map(|(_, job)| {
            let names: Vec<&str> = match &job["needs"] {
                Yaml::String(s) => vec![s.as_str()],
                Yaml::Array(items) => items.iter().filter_map(Yaml::as_str).collect(),
                _ => Vec::new(),
            };
            names.iter().filter_map(|n| index.get(n).copied()).collect()
        })
        .collect();
    for list in &mut needs {
        list.sort_unstable();
        list.dedup();
    }
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); jobs.len()];
    for (i, list) in needs.iter().enumerate() {
        for &n in list {
            dependents[n].push(i);
        }
    }
    let condition = |i: usize| jobs[i].1["if"].as_str();
    let own_gate: Vec<bool> = (0..jobs.len())
        .map(|i| condition(i).is_some_and(is_actor_gate))
        .collect();
    let overrides: Vec<bool> = (0..jobs.len())
        .map(|i| condition(i).is_some_and(|c| STATUS_OVERRIDE.is_match(c)))
        .collect();
    let mut waiting: Vec<usize> = needs.iter().map(Vec::len).collect();
    let mut ready: Vec<usize> = (0..jobs.len()).filter(|&i| waiting[i] == 0).collect();
    let mut inherited = vec![false; jobs.len()];
    while let Some(i) = ready.pop() {
        inherited[i] = !overrides[i] && needs[i].iter().any(|&n| own_gate[n] || inherited[n]);
        for &d in &dependents[i] {
            waiting[d] -= 1;
            if waiting[d] == 0 {
                ready.push(d);
            }
        }
    }
    jobs.iter()
        .zip(inherited)
        .filter(|(_, gated)| *gated)
        .map(|((id, _), _)| id.to_string())
        .collect()
}

/// The `||` branches of an expression, outside quotes and parentheses. A
/// branch wrapped in one pair of parentheses is split again inside.
fn disjuncts(expr: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut current = String::new();
    let mut chars = expr.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth = depth.saturating_sub(1),
            '|' if !quoted && depth == 0 && chars.peek() == Some(&'|') => {
                chars.next();
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    parts.push(current);
    let mut out = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match unwrap_parens(part) {
            Some(inner) => out.extend(disjuncts(inner)),
            None => out.push(part.to_string()),
        }
    }
    out
}

/// `inner` if `text` is `( inner )` with the outer pair matching each other.
fn unwrap_parens(text: &str) -> Option<&str> {
    let inner = text.strip_prefix('(')?.strip_suffix(')')?;
    let mut depth = 0i32;
    let mut quoted = false;
    for c in inner.chars() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            _ => {}
        }
    }
    (depth == 0).then_some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(pairs: &[(&str, &str)]) -> Permissions {
        Permissions::Scopes(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn callers_cap_callee_permissions() {
        let caller = scopes(&[("contents", "read"), ("issues", "write")]);
        // Nothing set in the callee: it inherits the caller's.
        assert_eq!(Permissions::effective(None, Some(&caller)), caller);
        // The callee cannot raise what the caller grants.
        assert_eq!(
            Permissions::effective(
                Some(scopes(&[
                    ("contents", "write"),
                    ("issues", "write"),
                    ("id-token", "write")
                ])),
                Some(&caller)
            ),
            scopes(&[
                ("contents", "read"),
                ("issues", "write"),
                ("id-token", "none")
            ])
        );
        assert_eq!(
            Permissions::effective(Some(Permissions::WriteAll), Some(&caller)),
            caller
        );
        assert_eq!(
            Permissions::effective(Some(Permissions::WriteAll), Some(&Permissions::ReadAll)),
            Permissions::ReadAll
        );
        assert_eq!(
            Permissions::effective(Some(Permissions::ReadAll), Some(&caller)),
            scopes(&[("contents", "read"), ("issues", "read")])
        );
        // An unset or write-all caller leaves the callee's own block.
        let own = scopes(&[("contents", "read")]);
        assert_eq!(
            Permissions::effective(Some(own.clone()), Some(&Permissions::Default)),
            own
        );
        assert_eq!(
            Permissions::effective(None, Some(&Permissions::Default)),
            Permissions::Default
        );
        assert_eq!(Permissions::effective(None, None), Permissions::Default);
    }

    #[test]
    fn only_positive_actor_checks_are_gates() {
        for gate in [
            "github.event.comment.author_association == 'OWNER'",
            "${{ github.event.comment.author_association == 'MEMBER' }}",
            "github.actor == 'octocat'",
            "'octocat' == github.triggering_actor",
            "contains(fromJSON('[\"alice\",\"bob\"]'), github.actor)",
            "contains(fromJSON(vars.MAINTAINERS), github.actor)",
            "contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association)",
            "contains('OWNER,MEMBER', github.event.issue.author_association) && contains(github.event.comment.body, '@claude')",
            "(github.event_name == 'issues' && github.actor == 'a') || (github.event_name == 'issue_comment' && github.actor == 'a')",
        ] {
            assert!(is_actor_gate(gate), "{gate}");
        }
        for not_gate in [
            "github.actor != 'github-actions[bot]'",
            "github.actor != 'dependabot[bot]' && github.event_name == 'issues'",
            "!contains(fromJSON('[\"bot\"]'), github.actor)",
            "github.event.comment.author_association != 'NONE'",
            "contains(fromJSON('[\"OWNER\",\"CONTRIBUTOR\"]'), github.event.comment.author_association)",
            "contains(github.event.comment.body, '@claude')",
            "github.actor == 'octocat' || github.event_name == 'issues'",
            "(github.actor == 'octocat' || contains(github.event.comment.body, 'x'))",
            "contains(github.event.comment.body, 'github.actor == ''x''')",
            "",
            // `null == false` is true: without the event check, any comment passes.
            "github.event.pull_request.head.repo.fork == false",
            "github.event_name == 'pull_request' || github.event.pull_request.head.repo.fork == false",
            "github.event_name == 'pull_request' && github.event.pull_request.head.repo.fork == true",
            &format!("{}github.actor == 'a'{}", "(".repeat(40), ")".repeat(40)),
        ] {
            assert!(!is_actor_gate(not_gate), "{not_gate}");
        }
    }

    #[test]
    fn same_repository_pull_requests_are_gates() {
        // run-gemini-cli's dispatch job.
        let dispatch = "(github.event_name == 'pull_request' && github.event.pull_request.head.repo.fork == false) ||\n(github.event.sender.type == 'User' && startsWith(github.event.comment.body || github.event.review.body || github.event.issue.body, '@gemini-cli') &&\ncontains(fromJSON('[\"OWNER\", \"MEMBER\", \"COLLABORATOR\"]'), github.event.comment.author_association || github.event.review.author_association || github.event.issue.author_association))";
        for gate in [
            dispatch,
            "github.event.pull_request.head.repo.full_name == github.repository",
            "false == github.event.pull_request.head.repo.fork && 'pull_request_target' == github.event_name",
        ] {
            assert!(is_actor_gate(gate), "{gate}");
        }
    }

    #[test]
    fn many_matches_in_one_condition_stay_linear() {
        // Every match sits inside a string literal, so each one is checked,
        // and no check may count the quotes before it again.
        let cond = format!("'{}", "github.actor == 'a' ".repeat(50_000));
        let started = std::time::Instant::now();
        assert!(!is_actor_gate(&cond));
        // 100 000 nested parentheses must not overflow the stack.
        let nested = format!(
            "{}github.actor == 'a'{}",
            "(".repeat(100_000),
            ")".repeat(100_000)
        );
        assert!(!is_actor_gate(&nested));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    fn gated(workflow: &str) -> Vec<String> {
        let doc = yaml::load(workflow).unwrap();
        needs_gated_jobs(&doc).into_iter().collect()
    }

    #[test]
    fn needs_pass_an_actor_gate_on() {
        let gate = "github.event.comment.author_association == 'OWNER'";
        // Directly and through another job.
        assert_eq!(
            gated(&format!(
                "jobs:\n  a:\n    if: {gate}\n  b:\n    needs: a\n  c:\n    needs: [b]\n  d: {{}}\n"
            )),
            vec!["b", "c"]
        );
        // One gated need is enough: the job waits for all of them.
        assert_eq!(
            gated(&format!(
                "jobs:\n  a:\n    if: {gate}\n  free: {{}}\n  b:\n    needs: [free, a]\n"
            )),
            vec!["b"]
        );
    }

    #[test]
    fn status_functions_stop_the_gate() {
        let gate = "github.event.comment.author_association == 'OWNER'";
        for status in [
            "always()",
            "${{ !cancelled() }}",
            "failure() || success()",
            "${{ always() && needs.a.result == 'success' }}",
        ] {
            // On the job itself: it runs although `a` was skipped.
            assert!(
                gated(&format!(
                    "jobs:\n  a:\n    if: {gate}\n  b:\n    needs: a\n    if: \"{status}\"\n"
                ))
                .is_empty(),
                "{status}"
            );
            // On a job in between: it runs, so what needs it runs too.
            assert!(
                gated(&format!(
                    "jobs:\n  a:\n    if: {gate}\n  b:\n    needs: a\n    if: \"{status}\"\n  c:\n    needs: b\n"
                ))
                .is_empty(),
                "{status}"
            );
        }
        // `success()` is the default: the gate still holds.
        assert_eq!(
            gated(&format!(
                "jobs:\n  a:\n    if: {gate}\n  b:\n    needs: a\n    if: success()\n"
            )),
            vec!["b"]
        );
    }

    #[test]
    fn needs_cycles_and_unknown_jobs_get_no_gate() {
        let gate = "github.actor == 'octocat'";
        assert!(
            gated(&format!(
                "jobs:\n  a:\n    if: {gate}\n    needs: b\n  b:\n    needs: a\n  c:\n    needs: [missing]\n"
            ))
            .is_empty()
        );
        // A long chain is one pass.
        let mut chain = format!("jobs:\n  j0:\n    if: {gate}\n");
        for i in 1..5_000 {
            chain.push_str(&format!("  j{i}:\n    needs: j{}\n", i - 1));
        }
        assert_eq!(gated(&chain).len(), 4_999);
    }
}
