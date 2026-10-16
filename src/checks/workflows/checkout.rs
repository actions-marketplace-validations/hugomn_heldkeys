//! Steps that check out the pull request's head: attacker-controlled files
//! on untrusted triggers.
//!
//! The description of how a step checks out the head is built from fixed
//! labels only, never from the step's text: a `run:` line can carry a token
//! (`git fetch https://x-access-token:<token>@github.com/...`), and nothing
//! from it may reach a finding.

use std::sync::LazyLock;

use regex::Regex;

use super::agents::action_name;
use super::script::shell_code;
use crate::yaml::{self, Yaml};

/// Expressions that name the PR head (attacker-controlled code on untrusted
/// triggers), with the label shown for each.
static HEAD_REFS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (
            r"github\.event\.pull_request\.head\.sha",
            "github.event.pull_request.head.sha",
        ),
        (
            r"github\.event\.pull_request\.head\.ref",
            "github.event.pull_request.head.ref",
        ),
        (
            r"github\.event\.pull_request\.head\.repo",
            "github.event.pull_request.head.repo",
        ),
        (r"github\.head_ref", "github.head_ref"),
        (
            r"github\.event\.workflow_run\.head_(?:sha|branch|repository)",
            "github.event.workflow_run.head_*",
        ),
        (r"refs/pull/", "refs/pull/<n>/..."),
    ]
    .into_iter()
    .map(|(re, label)| (Regex::new(re).expect("valid regex"), label))
    .collect()
});

/// Shell commands that check out a PR head, with the label shown for each.
static HEAD_CHECKOUT_CMDS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r"gh\s+pr\s+checkout", "gh pr checkout"),
        (r"git\s+fetch\b[^\n]*\bpull/", "git fetch ... pull/<n>/head"),
        (
            r"git\s+(?:checkout|switch)\b[^\n]*(?:head_ref|pull_request\.head)",
            "git checkout of the PR head ref",
        ),
    ]
    .into_iter()
    .map(|(re, label)| (Regex::new(re).expect("valid regex"), label))
    .collect()
});

fn first_label(patterns: &[(Regex, &'static str)], text: &str) -> Option<&'static str> {
    patterns
        .iter()
        .find(|(re, _)| re.is_match(text))
        .map(|(_, label)| *label)
}

/// If this step checks out the PR head, a short description of how, made of
/// fixed labels only.
pub(super) fn head_checkout(step: &Yaml) -> Option<String> {
    if let Some(uses) = yaml::str_at(step, "uses")
        && action_name(uses).eq_ignore_ascii_case("actions/checkout")
    {
        for key in ["ref", "repository"] {
            if let Some(v) = yaml::str_at(&step["with"], key)
                && let Some(label) = first_label(&HEAD_REFS, v)
            {
                return Some(format!("actions/checkout with {key}: {label}"));
            }
        }
    }
    if let Some(run) = yaml::str_at(step, "run")
        && let Some(label) = first_label(&HEAD_CHECKOUT_CMDS, &shell_code(run, false))
    {
        return Some(format!("run: {label}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn how(step: &str) -> Option<String> {
        head_checkout(&yaml::load(step).unwrap())
    }

    #[test]
    fn checkout_descriptions_never_quote_the_step() {
        let token = concat!("ghp_", "LEAKwfFAKEFAKEFAKEFAKEFAKE0005");
        let d = how(&format!(
            "run: git fetch https://x-access-token:{token}@github.com/o/r pull/1/head && git checkout FETCH_HEAD\n"
        ))
        .unwrap();
        assert_eq!(d, "run: git fetch ... pull/<n>/head");
        assert!(!d.contains("LEAK"));
        assert_eq!(
            how("run: gh pr checkout ${{ github.event.issue.number }}\n").as_deref(),
            Some("run: gh pr checkout")
        );
        assert_eq!(
            how("uses: actions/checkout@v4\nwith:\n  repository: https://x:secret@example.com/${{ github.event.pull_request.head.repo.full_name }}\n").as_deref(),
            Some("actions/checkout with repository: github.event.pull_request.head.repo")
        );
        assert_eq!(
            how("uses: actions/checkout@v4\nwith:\n  ref: refs/pull/${{ github.event.issue.number }}/head\n").as_deref(),
            Some("actions/checkout with ref: refs/pull/<n>/...")
        );
        assert_eq!(how("run: |\n  # gh pr checkout 1\n  make\n"), None);
        assert_eq!(how("uses: actions/checkout@v4\n"), None);
    }
}
