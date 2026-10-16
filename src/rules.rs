//! What a credential looks like.
//!
//! Two kinds of rules live here:
//!
//! - **Value rules** (`TOKEN_RULES`): well-known token formats with a public
//!   prefix, such as `ghp_` or `AKIA`. A match tells us the provider and lets
//!   us show a fingerprint, because the prefix is not secret.
//! - **Name rules** (`credential_name_kind`): variable names that usually hold
//!   a secret, such as `*_TOKEN` or `*_API_KEY`. A name match alone is weaker
//!   evidence, so the value must also look like a real secret (not empty, not
//!   a placeholder, not a file path).
//!
//! `classify_named_value` combines both and is shared by the `env`, `dotenv`
//! and `mcp` checks so they agree on what counts as a credential.

use std::sync::LazyLock;

use regex::Regex;

use crate::finding::{Access, Lifetime, Severity};
use crate::redact;

/// A known token format.
pub struct TokenRule {
    /// Stable id, e.g. "github-pat-classic".
    pub id: &'static str,
    /// Human title used in findings, e.g. "GitHub personal access token (classic)".
    pub title: &'static str,
    /// Regex for the whole token. Matched anchored at the start of a value.
    pub pattern: &'static str,
    pub severity: Severity,
    pub lifetime: Lifetime,
    pub access: Access,
    /// Whether 4 leading + 3 trailing characters are safe and useful to show.
    /// False for formats like PEM blocks or URLs, where the ends carry no identity.
    pub fingerprintable: bool,
}

/// Shorthand so the rule table below stays one line per field and easy to scan.
const fn rule(
    id: &'static str,
    title: &'static str,
    pattern: &'static str,
    severity: Severity,
    lifetime: Lifetime,
    access: Access,
) -> TokenRule {
    TokenRule {
        id,
        title,
        pattern,
        severity,
        lifetime,
        access,
        fingerprintable: true,
    }
}

use Access::{Unknown as AnyAccess, Write};
use Lifetime::{LongLived, ShortLived};
use Severity::{High, Low, Medium};

/// Known token formats. Order matters: more specific prefixes come first
/// (for example `sk-ant-` before the generic OpenAI-style `sk-`).
///
/// Severity follows the spec's rule of thumb. AI provider API keys are marked
/// as write access because they can spend money and create resources on the
/// account. Short-lived credentials with unknown access are Medium.
#[rustfmt::skip]
pub static TOKEN_RULES: &[TokenRule] = &[
    // AWS
    rule("aws-access-key", "Long-lived AWS access key", r"AKIA[0-9A-Z]{16}", High, LongLived, AnyAccess),
    rule("aws-temporary-key", "Temporary AWS credentials", r"ASIA[0-9A-Z]{16}", Medium, ShortLived, AnyAccess),
    // GitHub (https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/)
    rule("github-pat-fine-grained", "GitHub fine-grained personal access token", r"github_pat_[A-Za-z0-9_]{22,}", High, LongLived, AnyAccess),
    rule("github-pat-classic", "GitHub personal access token (classic)", r"ghp_[A-Za-z0-9]{20,}", High, LongLived, AnyAccess),
    rule("github-oauth", "GitHub OAuth token", r"gho_[A-Za-z0-9]{20,}", High, LongLived, AnyAccess),
    rule("github-app-user", "GitHub App user token", r"ghu_[A-Za-z0-9]{20,}", Medium, ShortLived, AnyAccess),
    rule("github-app-installation", "GitHub App installation token", r"ghs_[A-Za-z0-9]{20,}", Medium, ShortLived, AnyAccess),
    rule("github-refresh", "GitHub refresh token", r"ghr_[A-Za-z0-9]{20,}", High, LongLived, AnyAccess),
    // GitLab
    rule("gitlab-pat", "GitLab personal access token", r"glpat-[A-Za-z0-9_\-]{20,}", High, LongLived, AnyAccess),
    // AI providers
    rule("anthropic-api-key", "Anthropic API key", r"sk-ant-[A-Za-z0-9_\-]{20,}", High, LongLived, Write),
    rule("openai-project-key", "OpenAI project API key", r"sk-proj-[A-Za-z0-9_\-]{20,}", High, LongLived, Write),
    rule("openai-service-account-key", "OpenAI service account key", r"sk-svcacct-[A-Za-z0-9_\-]{20,}", High, LongLived, Write),
    rule("openai-api-key", "OpenAI-style API key", r"sk-[A-Za-z0-9]{32,}", High, LongLived, Write),
    rule("huggingface-token", "Hugging Face token", r"hf_[A-Za-z0-9]{30,}", Medium, LongLived, AnyAccess),
    // Payments
    // `sk_live_` and `sk_test_` are Stripe's, but WorkOS, Clerk and others
    // use them too: `vendor_title` names the vendor when the variable does.
    rule("stripe-live-secret", "Live secret key (sk_live_)", r"sk_live_[A-Za-z0-9]{16,}", High, LongLived, Write),
    rule("stripe-live-restricted", "Stripe live restricted key", r"rk_live_[A-Za-z0-9]{16,}", Medium, LongLived, AnyAccess),
    rule("stripe-test-secret", "Test-mode secret key (sk_test_)", r"sk_test_[A-Za-z0-9]{16,}", Low, LongLived, Write),
    rule("stripe-test-restricted", "Stripe test-mode restricted key", r"rk_test_[A-Za-z0-9]{16,}", Low, LongLived, AnyAccess),
    // Chat
    rule("slack-token", "Slack token", r"xox[abposr]-[A-Za-z0-9\-]{10,}", High, LongLived, Write),
    rule("slack-webhook", "Slack incoming webhook URL", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}", Medium, LongLived, Write),
    // Cloud
    rule("google-api-key", "Google API key", r"AIza[0-9A-Za-z_\-]{35}", High, LongLived, AnyAccess),
    rule("digitalocean-token", "DigitalOcean token", r"do[por]_v1_[a-f0-9]{64}", High, LongLived, AnyAccess),
    rule("databricks-token", "Databricks token", r"dapi[a-f0-9]{32}", High, LongLived, AnyAccess),
    // Package registries
    rule("npm-token", "npm access token", r"npm_[A-Za-z0-9]{30,}", High, LongLived, Write),
    rule("pypi-token", "PyPI upload token", r"pypi-[A-Za-z0-9_\-]{16,}", High, LongLived, Write),
    rule("crates-io-token", "crates.io API token", r"cio[A-Za-z0-9]{30,}", High, LongLived, Write),
    rule("docker-hub-pat", "Docker Hub access token", r"dckr_pat_[A-Za-z0-9_\-]{20,}", High, LongLived, Write),
    // Other SaaS
    rule("sendgrid-key", "SendGrid API key", r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", High, LongLived, Write),
    rule("shopify-token", "Shopify access token", r"shp(at|ca|pa|ss)_[a-fA-F0-9]{32}", High, LongLived, Write),
    rule("linear-key", "Linear API key", r"lin_api_[A-Za-z0-9]{30,}", Medium, LongLived, Write),
    rule("jwt", "JSON Web Token", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*", Medium, Lifetime::Unknown, AnyAccess),
    // Formats without a useful fingerprint.
    TokenRule {
        id: "private-key",
        title: "Private key",
        pattern: r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
        severity: High,
        lifetime: LongLived,
        access: AnyAccess,
        fingerprintable: false,
    },
    TokenRule {
        id: "url-with-password",
        title: "Connection string with embedded password",
        // scheme://user:password@host; the password part must be non-empty.
        pattern: r"[A-Za-z][A-Za-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@[^\s]+",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fingerprintable: false,
    },
];

/// The rules compiled once, anchored at the start of the value.
static ANCHORED: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    TOKEN_RULES
        .iter()
        .map(|r| Regex::new(&format!("^(?:{})", r.pattern)).expect("valid token regex"))
        .collect()
});

/// The rules compiled once, for searching inside larger text.
static UNANCHORED: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    TOKEN_RULES
        .iter()
        .map(|r| Regex::new(r.pattern).expect("valid token regex"))
        .collect()
});

/// Which known token format, if any, does this value start with?
///
/// Surrounding whitespace and quotes are ignored, because config files often
/// quote their values.
pub fn match_token(value: &str) -> Option<&'static TokenRule> {
    let value = trim_value(value);
    TOKEN_RULES
        .iter()
        .zip(ANCHORED.iter())
        .find(|(_, re)| re.is_match(value))
        .map(|(rule, _)| rule)
}

/// A token found inside a larger text, as byte offsets into that text.
pub struct TokenMatch {
    pub rule: &'static TokenRule,
    pub start: usize,
    pub end: usize,
}

/// Finds known tokens anywhere inside `text` (for scanning whole files).
///
/// A match only counts if it is not glued to a preceding letter or digit, so
/// `mask-1234...` does not look like an `sk-` key. Overlapping matches from
/// less specific rules are dropped.
pub fn find_tokens(text: &str) -> Vec<TokenMatch> {
    let mut found: Vec<TokenMatch> = Vec::new();
    for (rule, re) in TOKEN_RULES.iter().zip(UNANCHORED.iter()) {
        for m in re.find_iter(text) {
            let glued = text[..m.start()]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric());
            let overlaps = found.iter().any(|f| m.start() < f.end && f.start < m.end());
            if !glued && !overlaps {
                found.push(TokenMatch {
                    rule,
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
    found.sort_by_key(|m| m.start);
    found
}

/// Strips whitespace and one layer of matching quotes.
pub fn trim_value(value: &str) -> &str {
    let v = value.trim();
    for quote in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(quote) && v.ends_with(quote) {
            return v[1..v.len() - 1].trim();
        }
    }
    v
}

/// Why a variable name looks like it holds a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    /// A cloud provider or source-control credential (GitHub, AWS, GCP...).
    /// Only the title differs: a name alone is Medium either way.
    CloudOrScm,
    /// Any other credential-looking name.
    Generic,
}

/// Suffixes that usually mean "this variable holds a secret".
const SECRET_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_SECRET",
    "_SECRET_KEY",
    "_KEY",
    "_API_KEY",
    "_APIKEY",
    "_ACCESS_KEY",
    "_PRIVATE_KEY",
    "_PASSWORD",
    "_PASSWD",
    "_PASS",
    "_PAT",
    "_AUTH",
    "_CREDENTIAL",
    "_CREDENTIALS",
];

/// Exact names that hold secrets but do not match a suffix.
const SECRET_NAMES: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "API_KEY",
    "APIKEY",
    "PGPASSWORD",
    "MYSQL_PWD",
    "SSHPASS",
    "DATABASE_URL",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
];

/// Names that match a suffix but are not secrets.
const NOT_SECRET_SUFFIXES: &[&str] = &["_PUBLIC_KEY", "_PUBLISHABLE_KEY", "_PUB_KEY"];

/// Name fragments that mark a cloud or source-control credential.
const CLOUD_OR_SCM_MARKERS: &[&str] = &[
    "GITHUB",
    "GH_",
    "GITLAB",
    "GL_",
    "BITBUCKET",
    "AWS_",
    "AZURE",
    "ARM_CLIENT",
    "GOOGLE",
    "GCP_",
    "GCLOUD",
    "CLOUDSDK",
    "CLOUDFLARE",
    "CF_API",
    "DIGITALOCEAN",
    "HEROKU",
    "VERCEL",
    "NETLIFY",
    "FLY_",
    "HCLOUD",
    "LINODE",
];

/// Does this variable name look like it holds a credential?
pub fn credential_name_kind(name: &str) -> Option<NameKind> {
    let upper = name.to_ascii_uppercase();
    if NOT_SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s)) {
        return None;
    }
    let by_name = SECRET_NAMES.contains(&upper.as_str())
        || SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s));
    if !by_name {
        return None;
    }
    if CLOUD_OR_SCM_MARKERS
        .iter()
        .any(|m| upper.starts_with(m) || upper.contains(&format!("_{m}")))
    {
        Some(NameKind::CloudOrScm)
    } else {
        Some(NameKind::Generic)
    }
}

/// Is this value clearly not a real secret: empty, a placeholder, a reference
/// to another variable, a boolean, a number or a file path?
///
/// Only used for name-based matches. A value that matches a known token
/// format is always reported, even if it contains words like "EXAMPLE".
pub fn looks_like_placeholder(value: &str) -> bool {
    let v = trim_value(value);
    if v.chars().count() < 8 {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    let references = v.starts_with("${") || v.starts_with("$(") || v.starts_with('$');
    let path = v.starts_with('/') || v.starts_with("./") || v.starts_with("~/");
    let template = v.starts_with('<') || v.starts_with("{{") || v.contains("***");
    let boolean_or_number =
        matches!(lower.as_str(), "true" | "false") || v.chars().all(|c| c.is_ascii_digit());
    let single_char = v.chars().all(|c| c == v.chars().next().unwrap_or(' '));
    let words = [
        "changeme",
        "change_me",
        "change-me",
        "placeholder",
        "your_",
        "your-",
        "example",
        "dummy",
        "redacted",
        "todo",
        "xxxx",
    ];
    references
        || path
        || template
        || boolean_or_number
        || single_char
        || words.iter().any(|w| lower.contains(w))
}

/// The verdict for one name/value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub title: String,
    pub severity: Severity,
    pub lifetime: Lifetime,
    pub access: Access,
    pub fingerprint: Option<String>,
    /// The token rule id when the value matched a known format.
    pub rule_id: Option<&'static str>,
}

/// Decides whether `name=value` is a credential, and how dangerous it is.
///
/// A known token format wins over the name, and is titled after the vendor
/// the name gives when the format is shared (`vendor_title`). Otherwise a
/// credential-looking name with a real-looking value is reported with
/// unknown lifetime and access.
///
/// Names with a public frontend prefix (`NEXT_PUBLIC_`, `VITE_`, ...) are
/// values a build puts in the browser bundle: the ones meant to be public
/// (`frontend_public_name`) are skipped, and one whose name says it is a
/// secret is reported as exposed to the bundle.
pub fn classify_named_value(name: &str, value: &str) -> Option<Classification> {
    let value = trim_value(value);
    if value.is_empty() {
        return None;
    }
    let token = match_token(value);
    // `postgres://postgres:postgres@localhost/app` guards nothing.
    if token.is_some_and(|t| t.id == "url-with-password") && is_local_dev_url(value) {
        return None;
    }
    if is_frontend_name(name) {
        if frontend_secret_name(name) {
            if token.is_none() && looks_like_placeholder(value) {
                return None;
            }
            return Some(Classification {
                title: "Secret exposed to the frontend bundle".to_string(),
                severity: Severity::High,
                lifetime: token.map_or(Lifetime::Unknown, |t| t.lifetime),
                access: token.map_or(Access::Unknown, |t| t.access),
                fingerprint: redact::fingerprint(value),
                rule_id: token.map(|t| t.id),
            });
        }
        if frontend_public_name(name) {
            return None;
        }
    }
    if let Some(rule) = token {
        return Some(Classification {
            title: vendor_title(rule, name).unwrap_or_else(|| rule.title.to_string()),
            severity: rule.severity,
            lifetime: rule.lifetime,
            access: rule.access,
            fingerprint: redact::fingerprint(value),
            rule_id: Some(rule.id),
        });
    }
    let kind = credential_name_kind(name)?;
    if looks_like_placeholder(value) {
        return None;
    }
    // Both Medium: a name is weak evidence, and an unknown value cannot be
    // told apart from a non-secret setting with an unlucky name.
    let title = match kind {
        NameKind::CloudOrScm => "Possible cloud or SCM credential",
        NameKind::Generic => "Possible credential",
    };
    Some(Classification {
        title: title.to_string(),
        severity: Severity::Medium,
        lifetime: Lifetime::Unknown,
        access: Access::Unknown,
        // Unknown format: no fingerprint, because the ends of an arbitrary
        // secret are part of the secret.
        fingerprint: None,
        rule_id: None,
    })
}

/// Prefixes that frontend build tools inline into the code they ship to
/// browsers (Vite, Next.js, SvelteKit/Astro, Create React App, Expo, Nuxt,
/// Gatsby).
const FRONTEND_PREFIXES: &[&str] = &[
    "VITE_",
    "NEXT_PUBLIC_",
    "PUBLIC_",
    "REACT_APP_",
    "EXPO_PUBLIC_",
    "NUXT_PUBLIC_",
    "GATSBY_",
];

/// Does the name carry a frontend prefix?
pub fn is_frontend_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    FRONTEND_PREFIXES.iter().any(|p| upper.starts_with(p))
}

/// A frontend variable whose name says it is a secret: anyone who loads the
/// site can read it.
fn frontend_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ["SECRET", "PRIVATE", "SERVICE_ROLE"]
        .iter()
        .any(|w| upper.contains(w))
}

/// A frontend variable that is public by design: site keys, publishable and
/// anonymous keys, OAuth client ids, analytics keys.
fn frontend_public_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "SITE_KEY",
        "SITEKEY",
        "PUBLISHABLE",
        "ANON_KEY",
        "CLIENT_ID",
        "POSTHOG",
        "AMPLITUDE",
        "MIXPANEL",
        "SEGMENT",
        "ANALYTICS",
        "MEASUREMENT_ID",
        "ALGOLIA_SEARCH",
    ]
    .iter()
    .any(|w| upper.contains(w))
}

/// Vendors that share a token format with another, by a word in the
/// variable name, and the name to show.
const VENDORS: &[(&str, &str)] = &[
    ("WORKOS", "WorkOS"),
    ("CLERK", "Clerk"),
    ("STRIPE", "Stripe"),
    ("DEEPSEEK", "DeepSeek"),
    ("MOONSHOT", "Moonshot"),
    ("KIMI", "Moonshot"),
    ("DASHSCOPE", "DashScope"),
    ("QWEN", "DashScope"),
    ("OPENAI", "OpenAI"),
];

/// A title naming the vendor, for token formats several vendors use
/// (`sk_test_`, `sk_live_`, OpenAI-style `sk-`), when the variable name says
/// which one it is: `WORKOS_API_KEY` holds a "WorkOS test-mode API key".
pub fn vendor_title(rule: &TokenRule, name: &str) -> Option<String> {
    let upper = name.to_ascii_uppercase();
    let vendor = VENDORS
        .iter()
        .find(|(word, _)| upper.contains(word))
        .map(|(_, vendor)| *vendor)?;
    let title = match (rule.id, vendor) {
        ("stripe-test-secret", "Stripe") => "Stripe test-mode secret key".to_string(),
        ("stripe-live-secret", "Stripe") => "Stripe live secret key".to_string(),
        ("stripe-test-secret", _) => format!("{vendor} test-mode API key"),
        ("stripe-live-secret", _) => format!("{vendor} live API key"),
        ("openai-api-key", _) => format!("{vendor} API key"),
        _ => return None,
    };
    Some(title)
}

/// A value in a template file (`.env.example`, ...) that only shows where a
/// real one goes: `your_token_here`, `sk-ant-xxxxxxxx`, `<api key>`,
/// `changeme`, a whole value of `test` or `password`, or a connection
/// string to a local database with a trivial password.
///
/// Stricter than `looks_like_placeholder`: it applies to values of a known
/// token format too, because a template's tokens are often a real prefix
/// followed by filler.
pub fn looks_like_template_placeholder(value: &str) -> bool {
    let v = trim_value(value);
    if looks_like_placeholder(v) || is_local_dev_url(v) {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    // `sk_test_` is a real prefix, not a placeholder word.
    let body = ["sk_test_", "rk_test_"]
        .iter()
        .find_map(|p| lower.strip_prefix(p))
        .unwrap_or(&lower);
    let words = [
        "your",
        "example",
        "changeme",
        "xxx",
        "here",
        "placeholder",
        "dummy",
        "replace",
        "insert",
        "sample",
        "...",
        "<",
        ">",
    ];
    let whole = ["test", "password", "secret", "token", "none", "null"];
    words.iter().any(|w| body.contains(w))
        || whole.contains(&body)
        || body
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|part| matches!(part, "test" | "testing"))
}

/// Passwords that only ever guard a local development database.
const TRIVIAL_PASSWORDS: &[&str] = &[
    "postgres", "password", "secret", "example", "admin", "root", "mysql", "pass", "changeme",
    "test", "dev", "local", "docker", "pw",
];

/// `scheme://user:password@localhost...` with a trivial password (or the
/// user name as password): a local development database, not a credential.
pub fn is_local_dev_url(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let Some(at) = rest.rfind('@') else {
        return false;
    };
    let (userinfo, host) = (&rest[..at], &rest[at + 1..]);
    let Some((user, password)) = userinfo.split_once(':') else {
        return false;
    };
    let host = host
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or("").to_string(),
        None => host
            .rsplit_once(':')
            .map_or(host.clone(), |(h, _)| h.to_string()),
    };
    let local = matches!(
        host.as_str(),
        "localhost" | "127.0.0.1" | "0.0.0.0" | "::1" | "host.docker.internal"
    );
    let password = password.to_ascii_lowercase();
    local
        && (TRIVIAL_PASSWORDS.contains(&password.as_str()) || password == user.to_ascii_lowercase())
}

/// Hosts where a stored password almost certainly grants source-control or
/// cloud access. Used by `netrc` and `git-credentials` to pick the severity.
pub fn is_cloud_or_scm_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    const HOSTS: &[&str] = &[
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "heroku.com",
        "amazonaws.com",
        "azure.com",
        "visualstudio.com",
        "googleapis.com",
        "digitalocean.com",
    ];
    HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_compiles() {
        assert_eq!(ANCHORED.len(), TOKEN_RULES.len());
        assert_eq!(UNANCHORED.len(), TOKEN_RULES.len());
    }

    #[test]
    fn matches_known_prefixes() {
        let cases = [
            ("AKIAIOSFODNN7EXAMPLE", "aws-access-key"),
            ("ASIAIOSFODNN7EXAMPLE", "aws-temporary-key"),
            (
                "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000001",
                "github-pat-classic",
            ),
            ("gho_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000001", "github-oauth"),
            (
                "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000001",
                "github-app-installation",
            ),
            (
                "github_pat_FAKEFAKEFAKEFAKEFAKE_FAKEFAKE01",
                "github-pat-fine-grained",
            ),
            (
                "sk-ant-api03-FAKEFAKEFAKEFAKEFAKE-FAKE",
                "anthropic-api-key",
            ),
            ("sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE", "openai-project-key"),
            ("sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE01", "openai-api-key"),
            ("sk_live_FAKEFAKEFAKEFAKE01", "stripe-live-secret"),
            ("sk_test_FAKEFAKEFAKEFAKE01", "stripe-test-secret"),
            ("xoxb-0000000000-FAKEFAKEFAKE", "slack-token"),
            ("AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0001", "google-api-key"),
            ("glpat-FAKEFAKEFAKEFAKEFAKE", "gitlab-pat"),
            ("npm_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0001", "npm-token"),
            ("pypi-FAKEFAKEFAKEFAKEFAKE", "pypi-token"),
            (
                "postgres://app:fakepass@db.internal/app",
                "url-with-password",
            ),
        ];
        for (value, id) in cases {
            let rule = match_token(value).unwrap_or_else(|| panic!("no match for {id}"));
            assert_eq!(rule.id, id, "value for {id}");
        }
    }

    #[test]
    fn ignores_ordinary_values() {
        for value in [
            "hello",
            "/usr/bin:/bin",
            "https://example.com/path",
            "sk-short",
        ] {
            assert!(match_token(value).is_none(), "{value}");
        }
    }

    #[test]
    fn quoted_values_still_match() {
        assert!(match_token("\"AKIAIOSFODNN7EXAMPLE\"").is_some());
    }

    #[test]
    fn credential_names() {
        assert_eq!(
            credential_name_kind("GITHUB_TOKEN"),
            Some(NameKind::CloudOrScm)
        );
        assert_eq!(credential_name_kind("GH_TOKEN"), Some(NameKind::CloudOrScm));
        assert_eq!(
            credential_name_kind("OPENAI_API_KEY"),
            Some(NameKind::Generic)
        );
        assert_eq!(credential_name_kind("PGPASSWORD"), Some(NameKind::Generic));
        assert_eq!(credential_name_kind("STRIPE_PUBLISHABLE_KEY"), None);
        assert_eq!(credential_name_kind("PATH"), None);
        assert_eq!(credential_name_kind("PWD"), None);
        assert_eq!(credential_name_kind("AWS_REGION"), None);
    }

    #[test]
    fn placeholders_are_skipped_for_name_matches() {
        assert!(classify_named_value("API_TOKEN", "changeme-please").is_none());
        assert!(classify_named_value("API_TOKEN", "${API_TOKEN}").is_none());
        assert!(classify_named_value("API_TOKEN", "true").is_none());
        assert!(classify_named_value("API_TOKEN", "short").is_none());
        let c = classify_named_value("API_TOKEN", "q8Zr1vLx0pTn4Wm2").unwrap();
        assert_eq!(c.severity, Severity::Medium);
        assert_eq!(c.fingerprint, None);
    }

    #[test]
    fn known_format_wins_over_placeholder_words() {
        let c = classify_named_value("ANYTHING", "AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(c.rule_id, Some("aws-access-key"));
        assert_eq!(c.fingerprint.as_deref(), Some("AKIA…PLE"));
    }

    #[test]
    fn cloud_names_alone_are_medium() {
        let c = classify_named_value("GITHUB_TOKEN", "q8Zr1vLx0pTn4Wm2").unwrap();
        assert_eq!(c.title, "Possible cloud or SCM credential");
        assert_eq!(c.severity, Severity::Medium);
    }

    #[test]
    fn shared_formats_are_titled_by_the_variable_name() {
        let title = |name: &str, value: &str| classify_named_value(name, value).unwrap().title;
        assert_eq!(
            title("WORKOS_API_KEY", "sk_test_FAKEFAKEFAKEFAKE01"),
            "WorkOS test-mode API key"
        );
        assert_eq!(
            title("STRIPE_SECRET_KEY", "sk_test_FAKEFAKEFAKEFAKE01"),
            "Stripe test-mode secret key"
        );
        assert_eq!(
            title("STRIPE_SECRET_KEY", "sk_live_FAKEFAKEFAKEFAKE01"),
            "Stripe live secret key"
        );
        assert_eq!(
            title("PAYMENTS_KEY", "sk_test_FAKEFAKEFAKEFAKE01"),
            "Test-mode secret key (sk_test_)"
        );
        assert_eq!(
            title("DEEPSEEK_API_KEY", "sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE01"),
            "DeepSeek API key"
        );
        assert_eq!(
            title("MOONSHOT_API_KEY", "sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE01"),
            "Moonshot API key"
        );
        assert_eq!(
            title("LLM_KEY", "sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE01"),
            "OpenAI-style API key"
        );
        // Formats only one vendor uses keep their own title.
        assert_eq!(
            title("WORKOS_GH", "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000001"),
            "GitHub personal access token (classic)"
        );
    }

    #[test]
    fn frontend_variables() {
        for (name, value) in [
            ("NEXT_PUBLIC_RECAPTCHA_SITE_KEY", "6LcFAKEFAKEFAKEFAKE00001"),
            ("VITE_STRIPE_PUBLISHABLE_KEY", "pk_live_FAKEFAKEFAKEFAKE01"),
            (
                "NEXT_PUBLIC_SUPABASE_ANON_KEY",
                "eyJhbGciOiJGQUtFIn0.eyJzdWIiOiJGQUtFRkFLRUZBS0UifQ.FAKEsig",
            ),
            (
                "REACT_APP_GOOGLE_CLIENT_ID",
                "FAKEclientID0001.apps.example",
            ),
            ("VITE_POSTHOG_KEY", "phc_FAKEFAKEFAKEFAKEFAKE0001"),
            (
                "EXPO_PUBLIC_POSTHOG_API_KEY",
                "phc_FAKEFAKEFAKEFAKEFAKE0002",
            ),
        ] {
            assert_eq!(classify_named_value(name, value), None, "{name}");
        }
        for (name, value) in [
            (
                "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
                "eyJhbGciOiJGQUtFIn0.eyJzdWIiOiJGQUtFRkFLRUZBS0UifQ.FAKEsig",
            ),
            ("VITE_STRIPE_SECRET_KEY", "sk_live_FAKEFAKEFAKEFAKE01"),
            ("PUBLIC_PRIVATE_TOKEN", "q8Zr1vLx0pTn4Wm2"),
        ] {
            let c = classify_named_value(name, value).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(c.title, "Secret exposed to the frontend bundle", "{name}");
            assert_eq!(c.severity, Severity::High, "{name}");
        }
        // A placeholder is still a placeholder.
        assert_eq!(
            classify_named_value("VITE_SECRET", "your_secret_here"),
            None
        );
        // A frontend name that says neither is judged like any other.
        assert!(
            classify_named_value("VITE_OPENAI_API_KEY", "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE")
                .is_some()
        );
    }

    #[test]
    fn template_placeholders() {
        for value in [
            "your_token_here",
            "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "sk-ant-api03-your-key-here-000000000",
            "ghp_REPLACEMEwithYOURtokenPLEASE0001",
            "<your api key>",
            "changeme",
            "test",
            "password",
            "sk_test_your_stripe_key_here",
            "sk_test_FAKE_test_FAKEFAKE0001",
            "postgres://postgres:postgres@localhost:5432/app",
            "postgresql://app:app@127.0.0.1/app",
            "mysql://root:secret@localhost/db",
        ] {
            assert!(looks_like_template_placeholder(value), "{value}");
        }
        for value in [
            "sk_test_FAKEFAKEFAKEFAKE0016",
            "xoxb-0000000000-FAKEFAKEFAKE0017",
            "postgres://app:FAKEdbPASSWORD0015@localhost:5432/app",
            "postgres://postgres:postgres@db.internal:5432/app",
        ] {
            assert!(!looks_like_template_placeholder(value), "{value}");
        }
    }

    #[test]
    fn local_dev_database_urls_are_not_credentials() {
        assert_eq!(
            classify_named_value(
                "DATABASE_URL",
                "postgres://postgres:postgres@localhost:5432/app"
            ),
            None
        );
        assert_eq!(
            classify_named_value("DATABASE_URL", "postgres://u:FAKEpw0001@[::1]:5432/app")
                .map(|c| c.title),
            Some("Connection string with embedded password".to_string())
        );
        assert!(is_local_dev_url(
            "redis://default:password@host.docker.internal:6379"
        ));
        assert!(!is_local_dev_url(
            "redis://default:password@cache.example.com:6379"
        ));
        assert!(!is_local_dev_url("not a url"));
    }

    #[test]
    fn finds_tokens_in_text() {
        let text = "x = 1\ntoken: ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000001\nmask-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE01";
        let found = find_tokens(text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule.id, "github-pat-classic");
    }

    #[test]
    fn scm_hosts() {
        assert!(is_cloud_or_scm_host("github.com"));
        assert!(is_cloud_or_scm_host("api.github.com"));
        assert!(!is_cloud_or_scm_host("notgithub.com"));
    }
}
