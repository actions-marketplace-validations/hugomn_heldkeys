//! Which secrets reach an agent step, and which of them it does not need.

use std::sync::LazyLock;

use regex::Regex;

use super::agents::{AgentAction, CloudBackend};
use crate::finding::Severity;
use crate::rules;
use crate::sanitize::clip;
use crate::yaml::{self, Yaml};

/// One secret reaching the agent step.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct SecretUse {
    /// Where it is passed, e.g. "with.anthropic_api_key" or "jobs.x.env.AWS_KEY".
    pub via: String,
    /// The input or env name it lands in ("anthropic_api_key"), or "run".
    pub key: String,
    /// The secret's name, or `None` for the whole secrets context.
    pub secret: Option<String>,
}

impl SecretUse {
    /// The names come from the workflow, and end up in locations and
    /// details, so each is clipped to `sanitize::MAX_SHOWN` characters.
    pub(super) fn new(via: String, key: &str, secret: Option<String>) -> SecretUse {
        SecretUse {
            via: clip(&via),
            key: clip(key),
            secret: secret.map(|s| clip(&s)),
        }
    }
}

static EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{\{(.*?)\}\}").expect("valid regex"));
static WHOLE_SECRETS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)tojson\(\s*secrets\s*\)").expect("valid regex"));
static NAMED_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"secrets(?:\.([A-Za-z_][A-Za-z0-9_-]*)|\[\s*['"]([^'"]+)['"]\s*\])"#)
        .expect("valid regex")
});

/// Environment names and secret names of AI provider credentials: what an
/// agent step legitimately needs to talk to its model.
const MODEL_CREDENTIAL_MARKERS: &[&str] = &[
    "ANTHROPIC",
    "CLAUDE",
    "OPENAI",
    "GEMINI",
    "GOOGLE_API_KEY",
    "GOOGLE_GENERATIVE_AI",
    "OPENROUTER",
    "MISTRAL",
    "DEEPSEEK",
    "GROQ",
    "XAI_",
    "COHERE",
    "TOGETHER",
    "FIREWORKS",
    "LLM_API_KEY",
    "COPILOT",
];

/// Secrets referenced inside `${{ }}` expressions in `text`. `None` stands for
/// the whole secrets context (`toJSON(secrets)`). `GITHUB_TOKEN` is the job
/// token, covered by the permissions rules, so it is not listed here.
pub(super) fn secrets_in(text: &str) -> Vec<Option<String>> {
    let mut found = Vec::new();
    for expr in EXPRESSION.captures_iter(text) {
        let inner = &expr[1];
        if WHOLE_SECRETS.is_match(inner) {
            found.push(None);
        }
        for cap in NAMED_SECRET.captures_iter(inner) {
            let name = cap.get(1).or(cap.get(2)).map(|m| m.as_str()).unwrap_or("");
            if !name.is_empty() && !name.eq_ignore_ascii_case("GITHUB_TOKEN") {
                found.push(Some(name.to_string()));
            }
        }
    }
    found
}

/// Every string under `node` (recursively), with the top-level key it sits under.
pub(super) fn strings_by_key(node: &Yaml) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (key, value) in yaml::entries(node) {
        let mut texts = Vec::new();
        collect_strings(value, &mut texts);
        for t in texts {
            out.push((key.to_string(), t));
        }
    }
    out
}

fn collect_strings(node: &Yaml, out: &mut Vec<String>) {
    match node {
        Yaml::String(s) => out.push(s.clone()),
        Yaml::Array(items) => items.iter().for_each(|i| collect_strings(i, out)),
        Yaml::Hash(map) => map.values().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}

/// Secrets in a mapping such as `with:` or `env:`.
pub(super) fn secrets_in_map(node: &Yaml, via_prefix: &str) -> Vec<SecretUse> {
    let mut uses = Vec::new();
    for (key, text) in strings_by_key(node) {
        for secret in secrets_in(&text) {
            uses.push(SecretUse::new(format!("{via_prefix}.{key}"), &key, secret));
        }
    }
    uses
}

/// Secrets a step references in `with:`, `env:` and its script.
pub(super) fn step_secrets(step: &Yaml, path: &str) -> Vec<SecretUse> {
    let mut secrets = secrets_in_map(&step["with"], "with");
    secrets.extend(secrets_in_map(&step["env"], "env"));
    if let Some(run) = yaml::str_at(step, "run") {
        for secret in secrets_in(run) {
            secrets.push(SecretUse::new(format!("{path}.run"), "run", secret));
        }
    }
    secrets
}

fn is_model_credential(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    MODEL_CREDENTIAL_MARKERS.iter().any(|m| upper.contains(m))
}

/// A personal access token, by its name: `GH_PAT`, `MY_PAT_TOKEN`, `PERSONAL_ACCESS_TOKEN`.
pub(super) fn is_pat_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.contains("PERSONAL_ACCESS") || upper.split(['_', '-']).any(|part| part == "PAT")
}

/// Input or env names that carry a GitHub token to the agent.
pub(super) fn is_github_token_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "github_token" | "gh_token" | "github-token" | "token"
    )
}

/// One secret an agent step gets but does not need, and how bad that is.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Excess {
    /// What and how, e.g. "AWS_SECRET_ACCESS_KEY via env.AWS_SECRET_ACCESS_KEY
    /// (cloud or SCM credential)".
    pub reason: String,
    pub severity: Severity,
}

impl Excess {
    fn new(reason: String, severity: Severity) -> Excess {
        Excess { reason, severity }
    }
}

/// Why a secret is more than the agent step needs, if it is. High for the
/// whole secrets context and long-lived cloud or SCM credentials, Medium for
/// anything else.
pub(super) fn excess_reason(
    agent: &AgentAction,
    backend: Option<CloudBackend>,
    u: &SecretUse,
) -> Option<Excess> {
    let Some(secret) = &u.secret else {
        return Some(Excess::new(
            format!("the whole secrets context ({})", u.via),
            Severity::High,
        ));
    };
    if is_github_token_key(&u.key) || is_pat_name(secret) {
        return Some(Excess::new(
            format!(
                "{secret} via {} (a personal access token or app key; the agent can use github.token or its GitHub App)",
                u.via
            ),
            Severity::High,
        ));
    }
    let expected = agent
        .credential_inputs
        .iter()
        .any(|i| i.eq_ignore_ascii_case(&u.key));
    if expected || is_model_credential(secret) || is_model_credential(&u.key) {
        return None;
    }
    if let Some(backend) = backend
        && backend.owns_secret(secret)
    {
        // The agent needs this to reach its model, so it is not an extra;
        // but it is a long-lived cloud key where OIDC would do.
        return Some(Excess::new(
            format!(
                "{secret} via {} (expected for {}, but a stored cloud key: prefer OIDC with a role limited to the model)",
                u.via,
                backend.name()
            ),
            Severity::Medium,
        ));
    }
    if rules::credential_name_kind(secret) == Some(rules::NameKind::CloudOrScm) {
        return Some(Excess::new(
            format!("{secret} via {} (cloud or SCM credential)", u.via),
            Severity::High,
        ));
    }
    Some(Excess::new(
        format!("{secret} via {}", u.via),
        Severity::Medium,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_in_expressions() {
        assert_eq!(
            secrets_in("${{ secrets.A }} and ${{ secrets['B-C'] }} ${{ secrets.GITHUB_TOKEN }}"),
            vec![Some("A".to_string()), Some("B-C".to_string())]
        );
        assert_eq!(secrets_in("${{ toJSON(secrets) }}"), vec![None]);
        assert!(secrets_in("secrets.A outside an expression").is_empty());
    }
}
