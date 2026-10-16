//! `ai-logins` and `cli-logins`: the tokens command-line tools keep on disk
//! after you log in.
//!
//! `codex login`, `vercel login`, `fly auth login` and the like store a token
//! in a file under the home directory so the next command does not ask
//! again. Any process running as you can read that file, so an agent that
//! gets hijacked can use the login without a prompt. Each tool is one row of
//! a table below: where its file is (macOS and Linux variants, the
//! environment variable that moves it), how to read it, which keys hold the
//! token, and how bad the token is.
//!
//! Two checks share the table so that reports can group them sensibly: AI
//! coding tools (`ai-logins`, next to the MCP configs) and developer platform
//! CLIs (`cli-logins`). Files that the tool keeps in the OS keychain instead
//! (Claude Code on macOS, Supabase and Doppler where a keyring is available)
//! are never read: heldkeys does not touch the keychain.
//!
//! Values only leave this file as `redact` fingerprints, and only for known
//! token formats. One login gives one finding, however many tokens it holds
//! (an access token and its refresh token are one login); a file with
//! several logins (`credentials.<host>.token`) gives one per login.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::checks::display;
use crate::checks::{Check, dotenv};
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::ini;
use crate::jsonc;
use crate::redact;
use crate::rules;
use crate::toml_subset;
use crate::yaml::{self, Yaml};

pub struct AiLoginsCheck;
pub struct CliLoginsCheck;

const AI: &str = "ai-logins";
const CLI: &str = "cli-logins";

const CODEX: Rule = Rule {
    check: AI,
    id: "HK-AI-001",
    summary: "OpenAI Codex CLI login or API key in auth.json",
};

const CLAUDE_CREDENTIALS: Rule = Rule {
    check: AI,
    id: "HK-AI-002",
    summary: "Claude Code OAuth login stored in .credentials.json",
};

const CLAUDE_SETTINGS: Rule = Rule {
    check: AI,
    id: "HK-AI-003",
    summary: "Credential or API key helper in Claude Code settings",
};

const GEMINI: Rule = Rule {
    check: AI,
    id: "HK-AI-004",
    summary: "Gemini CLI OAuth login or API key on disk",
};

const COPILOT: Rule = Rule {
    check: AI,
    id: "HK-AI-005",
    summary: "GitHub Copilot OAuth token in apps.json or hosts.json",
};

const HUGGING_FACE: Rule = Rule {
    check: AI,
    id: "HK-AI-006",
    summary: "Hugging Face access token on disk",
};

const AI_RULES: &[Rule] = &[
    CODEX,
    CLAUDE_CREDENTIALS,
    CLAUDE_SETTINGS,
    GEMINI,
    COPILOT,
    HUGGING_FACE,
];

const VAULT: Rule = Rule {
    check: CLI,
    id: "HK-CLI-001",
    summary: "HashiCorp Vault token in ~/.vault-token",
};

const TERRAFORM: Rule = Rule {
    check: CLI,
    id: "HK-CLI-002",
    summary: "Terraform Cloud API token in credentials.tfrc.json",
};

const VERCEL: Rule = Rule {
    check: CLI,
    id: "HK-CLI-003",
    summary: "Vercel CLI login token in auth.json",
};

const NETLIFY: Rule = Rule {
    check: CLI,
    id: "HK-CLI-004",
    summary: "Netlify CLI login token in config.json",
};

const FLY: Rule = Rule {
    check: CLI,
    id: "HK-CLI-005",
    summary: "Fly.io CLI access token in config.yml",
};

const SUPABASE: Rule = Rule {
    check: CLI,
    id: "HK-CLI-006",
    summary: "Supabase CLI access token on disk",
};

const WRANGLER: Rule = Rule {
    check: CLI,
    id: "HK-CLI-007",
    summary: "Cloudflare Wrangler OAuth or API token in its config",
};

const STRIPE: Rule = Rule {
    check: CLI,
    id: "HK-CLI-008",
    summary: "Stripe CLI API key in config.toml",
};

const DOPPLER: Rule = Rule {
    check: CLI,
    id: "HK-CLI-009",
    summary: "Doppler CLI token in .doppler.yaml",
};

const RAILWAY: Rule = Rule {
    check: CLI,
    id: "HK-CLI-010",
    summary: "Railway CLI login token in config.json",
};

const KAGGLE: Rule = Rule {
    check: CLI,
    id: "HK-CLI-011",
    summary: "Kaggle API key in kaggle.json",
};

const CLI_RULES: &[Rule] = &[
    VAULT, TERRAFORM, VERCEL, NETLIFY, FLY, SUPABASE, WRANGLER, STRIPE, DOPPLER, RAILWAY, KAGGLE,
];

/// The directory a login file lives under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// The home directory.
    Home,
    /// `$XDG_CONFIG_HOME`, or `~/.config` (also used on macOS by many CLIs).
    Config,
    /// `$XDG_DATA_HOME`, or `~/.local/share`.
    Data,
    /// `$XDG_CACHE_HOME`, or `~/.cache`.
    Cache,
    /// `~/Library/Application Support` (macOS).
    MacSupport,
    /// `~/Library/Preferences` (macOS).
    MacPreferences,
    /// The working directory: a file that comes with the project.
    Project,
}

/// One place a tool keeps its login: `base/dir/file`, or `$env/file` when
/// the tool's directory was moved with that environment variable.
struct Place {
    env: Option<&'static str>,
    base: Base,
    dir: &'static str,
    file: &'static str,
}

const fn at(base: Base, dir: &'static str, file: &'static str) -> Place {
    Place {
        env: None,
        base,
        dir,
        file,
    }
}

const fn home(dir: &'static str, file: &'static str) -> Place {
    at(Base::Home, dir, file)
}

/// `$env/file`, else `base/dir/file`.
const fn moved_by(env: &'static str, base: Base, dir: &'static str, file: &'static str) -> Place {
    Place {
        env: Some(env),
        base,
        dir,
        file,
    }
}

impl Place {
    fn path(&self, ctx: &Context) -> PathBuf {
        if let Some(dir) = self.env.and_then(|var| ctx.var(var)) {
            return ctx.resolve(dir).join(self.file);
        }
        let base = match self.base {
            Base::Home => ctx.home.clone(),
            Base::Config => ctx.config_dir(),
            Base::Data => ctx.data_dir(),
            Base::Cache => ctx.cache_dir(),
            Base::MacSupport => ctx.home_path("Library/Application Support"),
            Base::MacPreferences => ctx.home_path("Library/Preferences"),
            Base::Project => ctx.cwd.clone(),
        };
        base.join(self.dir).join(self.file)
    }
}

/// How a login file is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Toml,
    Yaml,
    /// `[section]` and `key = value`.
    Ini,
    /// The token alone, on the first line.
    Plain,
    /// `NAME=value` lines.
    Dotenv,
}

/// What to look for in a parsed login file.
enum Look {
    /// The values at these dotted paths are one login's tokens, the most
    /// important first. `*` matches any key, and each key it matches is a
    /// separate login (`credentials.*.token`: one per host). `""` is the
    /// whole file of a `Plain` login.
    Tokens(&'static [&'static str]),
    /// Each `NAME: value` entry of the object at this path (`""` for the
    /// whole file) is judged like an environment variable, by the shared
    /// rules in `rules`.
    EnvMap(&'static str),
    /// A command at this key that prints a credential when it runs.
    Helper(&'static str),
}

/// One kind of login a tool leaves on disk.
struct Login {
    rule: Rule,
    /// The tool, as shown in the finding's detail.
    tool: &'static str,
    places: &'static [Place],
    format: Format,
    look: Look,
    /// Title, severity, lifetime and access of a `Tokens` or `Helper`
    /// finding. `EnvMap` findings take them from the value instead.
    title: &'static str,
    severity: Severity,
    lifetime: Lifetime,
    access: Access,
    fix: &'static str,
}

use Access::{Read, Unknown as AnyAccess, Write};
use Base::{Config, MacPreferences, MacSupport, Project};
use Lifetime::{LongLived, Unknown as AnyLifetime};
use Severity::{High, Low, Medium};

/// AI coding tools.
static AI_LOGINS: &[Login] = &[
    Login {
        rule: CODEX,
        tool: "Codex CLI",
        places: &[moved_by("CODEX_HOME", Base::Home, ".codex", "auth.json")],
        format: Format::Json,
        look: Look::Tokens(&["OPENAI_API_KEY"]),
        title: "OpenAI API key in Codex auth.json",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run codex logout where other agents run, or log Codex in with a project key that has a spending limit.",
    },
    Login {
        rule: CODEX,
        tool: "Codex CLI ChatGPT login",
        places: &[moved_by("CODEX_HOME", Base::Home, ".codex", "auth.json")],
        format: Format::Json,
        look: Look::Tokens(&[
            "tokens.refresh_token",
            "tokens.access_token",
            "tokens.id_token",
        ]),
        title: "Codex CLI ChatGPT login tokens",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run codex logout where other agents run; the refresh token keeps the ChatGPT login alive.",
    },
    // On macOS Claude Code keeps this login in the keychain, which we never read.
    Login {
        rule: CLAUDE_CREDENTIALS,
        tool: "Claude Code",
        places: &[moved_by(
            "CLAUDE_CONFIG_DIR",
            Base::Home,
            ".claude",
            ".credentials.json",
        )],
        format: Format::Json,
        look: Look::Tokens(&["claudeAiOauth.refreshToken", "claudeAiOauth.accessToken"]),
        title: "Claude Code OAuth login tokens",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run /logout in Claude Code where other agents or untrusted code run; on Linux the login is a plain file.",
    },
    Login {
        rule: CLAUDE_SETTINGS,
        tool: "Claude Code settings",
        places: &[
            moved_by("CLAUDE_CONFIG_DIR", Base::Home, ".claude", "settings.json"),
            at(Project, ".claude", "settings.json"),
            at(Project, ".claude", "settings.local.json"),
        ],
        format: Format::Json,
        look: Look::EnvMap("env"),
        title: "",
        severity: High,
        lifetime: AnyLifetime,
        access: AnyAccess,
        fix: "Move the key out of the settings env block (use apiKeyHelper with a secret manager) and rotate it.",
    },
    Login {
        rule: CLAUDE_SETTINGS,
        tool: "Claude Code settings",
        places: &[moved_by(
            "CLAUDE_CONFIG_DIR",
            Base::Home,
            ".claude",
            "settings.json",
        )],
        format: Format::Json,
        look: Look::Helper("apiKeyHelper"),
        title: "Claude Code apiKeyHelper command",
        severity: Medium,
        lifetime: AnyLifetime,
        access: AnyAccess,
        fix: "Make the helper ask for user presence or hand out short-lived keys: any process running as you can run it.",
    },
    Login {
        rule: GEMINI,
        tool: "Gemini CLI",
        places: &[home(".gemini", "oauth_creds.json")],
        format: Format::Json,
        look: Look::Tokens(&["refresh_token", "access_token"]),
        title: "Gemini CLI Google OAuth tokens",
        severity: High,
        lifetime: LongLived,
        access: AnyAccess,
        fix: "Delete ~/.gemini/oauth_creds.json where other agents run, or use an API key with narrow quotas; the login can reach Google Cloud.",
    },
    Login {
        rule: GEMINI,
        tool: "Gemini CLI .env",
        places: &[home(".gemini", ".env")],
        format: Format::Dotenv,
        look: Look::EnvMap(""),
        title: "",
        severity: High,
        lifetime: AnyLifetime,
        access: AnyAccess,
        fix: "Move the key out of ~/.gemini/.env into a secret manager and rotate it.",
    },
    Login {
        rule: COPILOT,
        tool: "GitHub Copilot",
        places: &[
            at(Config, "github-copilot", "apps.json"),
            at(Config, "github-copilot", "hosts.json"),
        ],
        format: Format::Json,
        look: Look::Tokens(&["*.oauth_token"]),
        title: "GitHub Copilot OAuth token",
        severity: Medium,
        lifetime: LongLived,
        access: Read,
        fix: "Sign out of Copilot where agents run, or revoke the GitHub Copilot app in your GitHub settings.",
    },
    Login {
        rule: HUGGING_FACE,
        tool: "Hugging Face",
        places: &[moved_by("HF_HOME", Base::Cache, "huggingface", "token")],
        format: Format::Plain,
        look: Look::Tokens(&[""]),
        title: "Hugging Face token",
        severity: Medium,
        lifetime: LongLived,
        access: AnyAccess,
        fix: "Run hf auth logout where agents run, and give agents a fine-grained, read-only token.",
    },
    Login {
        rule: HUGGING_FACE,
        tool: "Hugging Face stored tokens",
        places: &[moved_by(
            "HF_HOME",
            Base::Cache,
            "huggingface",
            "stored_tokens",
        )],
        format: Format::Ini,
        look: Look::Tokens(&["*.hf_token"]),
        title: "Hugging Face token",
        severity: Medium,
        lifetime: LongLived,
        access: AnyAccess,
        fix: "Run hf auth logout --token-name <name> for tokens agents do not need, and prefer fine-grained, read-only ones.",
    },
];

/// Developer platform CLIs.
static CLI_LOGINS: &[Login] = &[
    Login {
        rule: VAULT,
        tool: "Vault CLI",
        places: &[home("", ".vault-token")],
        format: Format::Plain,
        look: Look::Tokens(&[""]),
        title: "HashiCorp Vault token",
        severity: High,
        lifetime: AnyLifetime,
        access: AnyAccess,
        fix: "Revoke the token when done (vault token revoke -self) and keep token TTLs short where agents run.",
    },
    Login {
        rule: TERRAFORM,
        tool: "Terraform CLI",
        places: &[home(".terraform.d", "credentials.tfrc.json")],
        format: Format::Json,
        look: Look::Tokens(&["credentials.*.token"]),
        title: "Terraform Cloud API token",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run terraform logout where agents run; give automation a team token scoped to the workspaces it needs.",
    },
    Login {
        rule: VERCEL,
        tool: "Vercel CLI",
        places: &[
            at(MacSupport, "com.vercel.cli", "auth.json"),
            at(Base::Data, "com.vercel.cli", "auth.json"),
        ],
        format: Format::Json,
        look: Look::Tokens(&["token"]),
        title: "Vercel CLI login token",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run vercel logout where agents run; pass a scoped token with an expiry only to the deploy command.",
    },
    Login {
        rule: NETLIFY,
        tool: "Netlify CLI",
        places: &[
            home(".netlify", "config.json"),
            at(MacPreferences, "netlify", "config.json"),
            at(Config, "netlify", "config.json"),
        ],
        format: Format::Json,
        look: Look::Tokens(&["users.*.auth.token"]),
        title: "Netlify CLI login token",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run netlify logout where agents run; use a personal access token with an expiry for automation.",
    },
    Login {
        rule: FLY,
        tool: "flyctl",
        places: &[home(".fly", "config.yml")],
        format: Format::Yaml,
        look: Look::Tokens(&["access_token"]),
        title: "Fly.io CLI access token",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run fly auth logout where agents run; give automation a deploy token scoped to one app (fly tokens create deploy).",
    },
    Login {
        rule: SUPABASE,
        tool: "Supabase CLI",
        places: &[home(".supabase", "access-token")],
        format: Format::Plain,
        look: Look::Tokens(&[""]),
        title: "Supabase CLI access token",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run supabase logout where agents run, or let the CLI keep the token in the OS keychain.",
    },
    Login {
        rule: WRANGLER,
        tool: "Wrangler",
        places: &[
            at(MacPreferences, ".wrangler/config", "default.toml"),
            at(Config, ".wrangler/config", "default.toml"),
            home(".wrangler/config", "default.toml"),
        ],
        format: Format::Toml,
        look: Look::Tokens(&["refresh_token", "oauth_token", "api_token"]),
        title: "Cloudflare Wrangler login tokens",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run wrangler logout where agents run; use an API token scoped to one account and the permissions needed.",
    },
    Login {
        rule: STRIPE,
        tool: "Stripe CLI live mode",
        places: &[at(Config, "stripe", "config.toml")],
        format: Format::Toml,
        look: Look::Tokens(&["*.live_mode_api_key"]),
        title: "Stripe CLI live-mode key",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run stripe logout where agents run; the CLI key acts on your live Stripe account until it expires.",
    },
    Login {
        rule: STRIPE,
        tool: "Stripe CLI test mode",
        places: &[at(Config, "stripe", "config.toml")],
        format: Format::Toml,
        look: Look::Tokens(&["*.test_mode_api_key"]),
        title: "Stripe CLI test-mode key",
        severity: Low,
        lifetime: LongLived,
        access: Write,
        fix: "Run stripe logout where agents run if they do not need test-mode access.",
    },
    Login {
        rule: DOPPLER,
        tool: "Doppler CLI",
        places: &[home(".doppler", ".doppler.yaml")],
        format: Format::Yaml,
        look: Look::Tokens(&["scoped.*.token"]),
        title: "Doppler CLI token",
        severity: High,
        lifetime: LongLived,
        access: AnyAccess,
        fix: "Run doppler logout where agents run; give agents a service token scoped to one config.",
    },
    Login {
        rule: RAILWAY,
        tool: "Railway CLI",
        places: &[home(".railway", "config.json")],
        format: Format::Json,
        look: Look::Tokens(&["user.token", "user.refreshToken", "user.accessToken"]),
        title: "Railway CLI login token",
        severity: High,
        lifetime: LongLived,
        access: Write,
        fix: "Run railway logout where agents run; use a project token for automation.",
    },
    Login {
        rule: KAGGLE,
        tool: "Kaggle CLI",
        places: &[
            moved_by("KAGGLE_CONFIG_DIR", Base::Home, ".kaggle", "kaggle.json"),
            at(Config, "kaggle", "kaggle.json"),
        ],
        format: Format::Json,
        look: Look::Tokens(&["key"]),
        title: "Kaggle API key",
        severity: Medium,
        lifetime: LongLived,
        access: AnyAccess,
        fix: "Delete kaggle.json where agents run, or expire the key in your Kaggle account settings.",
    },
];

impl Check for AiLoginsCheck {
    fn id(&self) -> &'static str {
        AI
    }

    fn describe(&self) -> &'static str {
        "Logins AI coding tools keep on disk: Codex auth.json, Claude Code .credentials.json and settings env, Gemini CLI OAuth and .env, GitHub Copilot, Hugging Face tokens."
    }

    fn rules(&self) -> &'static [Rule] {
        AI_RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        run_logins(ctx, AI_LOGINS)
    }
}

impl Check for CliLoginsCheck {
    fn id(&self) -> &'static str {
        CLI
    }

    fn describe(&self) -> &'static str {
        "Logins developer platform CLIs keep on disk: Vault, Terraform, Vercel, Netlify, Fly.io, Supabase, Wrangler, Stripe, Doppler, Railway, Kaggle."
    }

    fn rules(&self) -> &'static [Rule] {
        CLI_RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        run_logins(ctx, CLI_LOGINS)
    }
}

fn run_logins(ctx: &Context, logins: &[Login]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for login in logins {
        // Two places can be one file (XDG_CONFIG_HOME pointing at ~/.config,
        // the working directory being the home directory): read it once.
        let mut seen = BTreeSet::new();
        for place in login.places {
            let path = place.path(ctx);
            if !seen.insert(std::fs::canonicalize(&path).unwrap_or(path.clone())) {
                continue;
            }
            let project = place.base == Base::Project;
            findings.extend(check_file(ctx, login, &path, project));
        }
    }
    findings
}

fn check_file(ctx: &Context, login: &Login, path: &Path, project: bool) -> Vec<Finding> {
    let Some(root) = load(ctx, path, login.format, project) else {
        return Vec::new();
    };
    let file = ctx.display_path(path);
    match login.look {
        Look::Tokens(keys) => token_findings(ctx, login, &file, &root, keys),
        Look::EnvMap(at) => env_findings(login, &file, &root, at),
        Look::Helper(key) => helper_finding(login, &file, &root, key)
            .into_iter()
            .collect(),
    }
}

/// Reads and parses a login file. `None` if it is missing or holds nothing;
/// a file that exists but cannot be read or parsed is recorded for
/// `read-errors`. Every format becomes a JSON tree, so the lookups below
/// are written once.
fn load(ctx: &Context, path: &Path, format: Format, project: bool) -> Option<Value> {
    let text = if project {
        ctx.read_project_file(path)?
    } else {
        ctx.read_file(path)?
    };
    match format {
        Format::Json => {
            if jsonc::is_blank(&text) {
                return None;
            }
            let value = jsonc::parse(&text);
            if value.is_none() {
                ctx.note_unreadable(path, "not valid JSON");
            }
            value
        }
        Format::Toml => Some(toml_subset::parse(&text)),
        Format::Yaml => match yaml::load_checked(&text) {
            Ok(doc) => Some(yaml_to_json(&doc)),
            Err(reason) => {
                ctx.note_unreadable(path, reason);
                None
            }
        },
        Format::Ini => {
            let mut root = Map::new();
            for section in ini::parse(&text) {
                let entries = section
                    .entries
                    .into_iter()
                    .map(|(k, v)| (k, Value::String(v)))
                    .collect();
                root.insert(section.name, Value::Object(entries));
            }
            Some(Value::Object(root))
        }
        Format::Plain => text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(|l| Value::String(l.to_string())),
        Format::Dotenv => {
            let mut root = Map::new();
            for line in text.lines() {
                if let Some((name, value)) = dotenv::entry(line) {
                    root.insert(name.to_string(), Value::String(value.to_string()));
                }
            }
            Some(Value::Object(root))
        }
    }
}

/// A YAML tree as JSON: string-keyed mappings, sequences and strings. Other
/// scalars become null, since tokens are always strings.
fn yaml_to_json(node: &Yaml) -> Value {
    match node {
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Array(items) => Value::Array(items.iter().map(yaml_to_json).collect()),
        Yaml::Hash(_) => Value::Object(
            yaml::entries(node)
                .into_iter()
                .map(|(k, v)| (k.to_string(), yaml_to_json(v)))
                .collect(),
        ),
        _ => Value::Null,
    }
}

/// The values at a dotted path, each with the key `*` matched (if the path
/// has one). `""` is the root itself.
fn lookup<'a>(root: &'a Value, path: &str) -> Vec<(Option<String>, &'a Value)> {
    let mut found = vec![(None, root)];
    if path.is_empty() {
        return found;
    }
    for part in path.split('.') {
        let mut next = Vec::new();
        for (capture, value) in found {
            let Some(object) = value.as_object() else {
                continue;
            };
            if part == "*" {
                for (key, child) in object {
                    next.push((Some(key.clone()), child));
                }
            } else if let Some(child) = object.get(part) {
                next.push((capture, child));
            }
        }
        found = next;
    }
    found
}

/// A value worth reporting: a string that is not empty, not a reference to
/// a variable and long enough to be a token.
fn token_value(value: &Value) -> Option<&str> {
    let v = rules::trim_value(value.as_str()?);
    (v.chars().count() >= 8 && !v.starts_with('$')).then_some(v)
}

/// The tokens found for one login: (key pattern, value), in table order.
type Tokens<'a> = Vec<(&'static str, &'a str)>;

/// One finding per login: per key matched by `*`, or one for the file.
fn token_findings(
    ctx: &Context,
    login: &Login,
    file: &str,
    root: &Value,
    keys: &[&'static str],
) -> Vec<Finding> {
    // Logins in the order they are found, by the key `*` matched.
    let mut logins: Vec<(Option<String>, Tokens)> = Vec::new();
    for &key in keys {
        for (capture, value) in lookup(root, key) {
            let Some(value) = token_value(value) else {
                continue;
            };
            match logins.iter_mut().find(|(c, _)| *c == capture) {
                Some((_, tokens)) => tokens.push((key, value)),
                None => logins.push((capture, vec![(key, value)])),
            }
        }
    }
    logins
        .into_iter()
        .map(|(capture, tokens)| {
            let location = match &capture {
                Some(c) => format!("{file} [{}]", shown_key(ctx, c)),
                None => file.to_string(),
            };
            let held: Vec<&str> = tokens
                .iter()
                .map(|(k, _)| *k)
                .filter(|k| !k.is_empty())
                .collect();
            let detail = if held.is_empty() {
                login.tool.to_string()
            } else {
                format!("{}: {}", login.tool, held.join(", "))
            };
            Finding::new(
                login.rule,
                login.title,
                location,
                login.severity,
                login.lifetime,
                login.access,
                login.fix,
            )
            .with_fingerprint(tokens.iter().find_map(|(_, v)| redact::fingerprint(v)))
            .with_secret(tokens[0].1)
            .with_detail(detail)
        })
        .collect()
}

/// A key from the file shown in a location: a host, a profile, a user id or
/// a directory (Doppler scopes logins by directory, shown like any path).
fn shown_key(ctx: &Context, key: &str) -> String {
    if key.starts_with('/') {
        display::label(&ctx.display_path(Path::new(key)))
    } else {
        display::label(key)
    }
}

/// `NAME: value` entries judged like environment variables.
fn env_findings(login: &Login, file: &str, root: &Value, at: &str) -> Vec<Finding> {
    let Some((_, map)) = lookup(root, at).into_iter().next() else {
        return Vec::new();
    };
    let Some(map) = map.as_object() else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (name, value) in map {
        let Some(value) = value.as_str() else {
            continue;
        };
        let Some(c) = rules::classify_named_value(name, value) else {
            continue;
        };
        let name = display::label(name);
        let location = if at.is_empty() {
            format!("{file}: {name}")
        } else {
            format!("{file} {at}.{name}")
        };
        findings.push(
            Finding::new(
                login.rule, c.title, location, c.severity, c.lifetime, c.access, login.fix,
            )
            .with_fingerprint(c.fingerprint)
            .with_secret(value)
            .with_detail(login.tool),
        );
    }
    findings
}

/// A command that prints a credential: only its program name is shown,
/// because arguments can carry secrets.
fn helper_finding(login: &Login, file: &str, root: &Value, key: &str) -> Option<Finding> {
    let command = root.get(key)?.as_str()?.trim();
    if command.is_empty() {
        return None;
    }
    let program = display::program_name(command).unwrap_or_else(|| "a program".to_string());
    Some(
        Finding::new(
            login.rule,
            login.title,
            format!("{file} {key}"),
            login.severity,
            login.lifetime,
            login.access,
            login.fix,
        )
        .with_detail(format!("{}: runs {program} to get an API key", login.tool)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, fixture, write};
    use std::collections::BTreeMap;

    fn logins_ctx() -> Context {
        let home = fixture("logins/home");
        Context::new(
            home.clone(),
            home,
            fixture("logins/project"),
            BTreeMap::new(),
        )
    }

    fn run_both(ctx: &Context) -> Vec<Finding> {
        let mut f = AiLoginsCheck.run(ctx);
        f.extend(CliLoginsCheck.run(ctx));
        f
    }

    fn find<'a>(f: &'a [Finding], rule: &str, location: &str) -> &'a Finding {
        f.iter()
            .find(|f| f.rule == rule && f.location == location)
            .unwrap_or_else(|| panic!("no {rule} at {location}: {f:#?}"))
    }

    /// Every row of both tables finds its file in the fixture.
    #[test]
    fn every_entry_is_found_in_the_fixture() {
        let f = run_both(&logins_ctx());
        for rule in AI_RULES.iter().chain(CLI_RULES) {
            assert!(f.iter().any(|f| f.rule == rule.id), "{} not found", rule.id);
        }
        for login in AI_LOGINS.iter().chain(CLI_LOGINS) {
            let found = f.iter().any(|f| {
                f.rule == login.rule.id
                    && (login.title.is_empty() || f.title == login.title)
                    && f.detail.as_deref().unwrap_or("").starts_with(login.tool)
            });
            assert!(found, "{} ({}) not found", login.tool, login.rule.id);
        }
        assert!(
            !format!("{f:?}").contains("FAKE"),
            "a value reached a finding"
        );
    }

    #[test]
    fn codex() {
        let f = AiLoginsCheck.run(&logins_ctx());
        let key = find(&f, "HK-AI-001", "~/.codex/auth.json");
        let both: Vec<&str> = f
            .iter()
            .filter(|f| f.rule == "HK-AI-001")
            .map(|f| f.title.as_str())
            .collect();
        assert_eq!(
            both,
            [
                "OpenAI API key in Codex auth.json",
                "Codex CLI ChatGPT login tokens"
            ]
        );
        assert_eq!(key.fingerprint.as_deref(), Some("sk-p…001"));
        assert_eq!(key.severity, Severity::High);
        let chatgpt = &f.iter().filter(|f| f.rule == "HK-AI-001").nth(1).unwrap();
        assert_eq!(
            chatgpt.detail.as_deref(),
            Some(
                "Codex CLI ChatGPT login: tokens.refresh_token, tokens.access_token, tokens.id_token"
            )
        );
        // The access token is a JWT, so the login has a fingerprint.
        assert_eq!(chatgpt.fingerprint.as_deref(), Some("eyJh…002"));
    }

    #[test]
    fn codex_home_moves_the_file() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "elsewhere/auth.json",
            concat!(
                r#"{"OPENAI_API_KEY": "sk-"#,
                r#"proj-FAKEFAKEFAKEFAKEFAKEFAKE1090"}"#
            ),
        );
        write(
            dir.path(),
            ".codex/auth.json",
            r#"{"OPENAI_API_KEY": null}"#,
        );
        let ctx = ctx_with_env(dir.path(), &[("CODEX_HOME", "~/elsewhere")]);
        let f = AiLoginsCheck.run(&ctx);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].location, "~/elsewhere/auth.json");
        // Without CODEX_HOME the default file holds no key.
        assert!(AiLoginsCheck.run(&ctx_with_env(dir.path(), &[])).is_empty());
    }

    #[test]
    fn claude_code() {
        let f = AiLoginsCheck.run(&logins_ctx());
        let login = find(&f, "HK-AI-002", "~/.claude/.credentials.json");
        assert_eq!(login.title, "Claude Code OAuth login tokens");
        assert_eq!(login.fingerprint.as_deref(), Some("sk-a…003"));
        let env = find(
            &f,
            "HK-AI-003",
            "~/.claude/settings.json env.ANTHROPIC_API_KEY",
        );
        assert_eq!(env.title, "Anthropic API key");
        assert_eq!(env.severity, Severity::High);
        let helper = find(&f, "HK-AI-003", "~/.claude/settings.json apiKeyHelper");
        assert_eq!(
            helper.detail.as_deref(),
            Some("Claude Code settings: runs get-claude-key to get an API key")
        );
        assert_eq!(helper.severity, Severity::Medium);
        // Project settings are read too; settings that are not credentials are not.
        find(
            &f,
            "HK-AI-003",
            "./.claude/settings.local.json env.GITHUB_TOKEN",
        );
        assert!(
            !f.iter().any(|f| f.location.ends_with("DISABLE_TELEMETRY")),
            "{f:#?}"
        );
    }

    #[test]
    fn claude_config_dir_moves_the_files() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "cc/.credentials.json",
            r#"{"claudeAiOauth": {"accessToken": "FAKEaccessTOKEN1091", "refreshToken": "FAKErefreshTOKEN1091"}}"#,
        );
        write(
            dir.path(),
            "cc/settings.json",
            r#"{"apiKeyHelper": "FAKEhelper1092:secret --x"}"#,
        );
        let ctx = ctx_with_env(dir.path(), &[("CLAUDE_CONFIG_DIR", "~/cc")]);
        let f = AiLoginsCheck.run(&ctx);
        let locations: Vec<&str> = f.iter().map(|f| f.location.as_str()).collect();
        assert_eq!(
            locations,
            ["~/cc/.credentials.json", "~/cc/settings.json apiKeyHelper"]
        );
        // Unknown formats get no fingerprint, and an odd helper is not echoed.
        assert_eq!(f[0].fingerprint, None);
        assert!(!format!("{f:?}").contains("FAKE"), "{f:#?}");
    }

    #[test]
    fn gemini_copilot_and_hugging_face() {
        let f = AiLoginsCheck.run(&logins_ctx());
        let gemini = find(&f, "HK-AI-004", "~/.gemini/oauth_creds.json");
        assert_eq!(
            gemini.detail.as_deref(),
            Some("Gemini CLI: refresh_token, access_token")
        );
        find(&f, "HK-AI-004", "~/.gemini/.env: GEMINI_API_KEY");
        let apps = find(
            &f,
            "HK-AI-005",
            "~/.config/github-copilot/apps.json [github.com:Iv1.0000fake]",
        );
        assert_eq!(apps.fingerprint.as_deref(), Some("ghu_…005"));
        find(
            &f,
            "HK-AI-005",
            "~/.config/github-copilot/hosts.json [github.com]",
        );
        let token = find(&f, "HK-AI-006", "~/.cache/huggingface/token");
        assert_eq!(token.fingerprint.as_deref(), Some("hf_F…006"));
        let stored = find(
            &f,
            "HK-AI-006",
            "~/.cache/huggingface/stored_tokens [personal]",
        );
        // The same token in both files is one secret.
        assert_eq!(token.secret_key(), stored.secret_key());
    }

    #[test]
    fn hf_home_and_xdg_dirs() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "hf/token",
            "hf_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1093\n",
        );
        write(
            dir.path(),
            "xdg/github-copilot/hosts.json",
            r#"{"github.com": {"oauth_token": "gho_FAKEFAKEFAKEFAKEFAKEFAKEFAKE001094"}}"#,
        );
        write(
            dir.path(),
            "data/com.vercel.cli/auth.json",
            r#"{"token": "FAKEvercelTOKEN1095"}"#,
        );
        let ctx = ctx_with_env(
            dir.path(),
            &[
                ("HF_HOME", "~/hf"),
                ("XDG_CONFIG_HOME", "~/xdg"),
                ("XDG_DATA_HOME", "~/data"),
            ],
        );
        let f = run_both(&ctx);
        let locations: Vec<&str> = f.iter().map(|f| f.location.as_str()).collect();
        assert_eq!(
            locations,
            [
                "~/xdg/github-copilot/hosts.json [github.com]",
                "~/hf/token",
                "~/data/com.vercel.cli/auth.json"
            ]
        );
    }

    #[test]
    fn platform_clis() {
        let f = CliLoginsCheck.run(&logins_ctx());
        find(&f, "HK-CLI-001", "~/.vault-token");
        let tf = find(
            &f,
            "HK-CLI-002",
            "~/.terraform.d/credentials.tfrc.json [app.terraform.io]",
        );
        assert_eq!(
            tf.detail.as_deref(),
            Some("Terraform CLI: credentials.*.token")
        );
        find(
            &f,
            "HK-CLI-003",
            "~/Library/Application Support/com.vercel.cli/auth.json",
        );
        find(&f, "HK-CLI-004", "~/.netlify/config.json [0000fakeuser]");
        find(&f, "HK-CLI-005", "~/.fly/config.yml");
        find(&f, "HK-CLI-006", "~/.supabase/access-token");
        let wrangler = find(&f, "HK-CLI-007", "~/.config/.wrangler/config/default.toml");
        assert_eq!(
            wrangler.detail.as_deref(),
            Some("Wrangler: refresh_token, oauth_token")
        );
        let doppler = find(&f, "HK-CLI-009", "~/.doppler/.doppler.yaml [/]");
        assert_eq!(doppler.severity, Severity::High);
        find(&f, "HK-CLI-010", "~/.railway/config.json");
        find(&f, "HK-CLI-011", "~/.kaggle/kaggle.json");
    }

    #[test]
    fn stripe_test_keys_are_low() {
        let f = CliLoginsCheck.run(&logins_ctx());
        let stripe: Vec<(&str, Severity, Option<&str>)> = f
            .iter()
            .filter(|f| f.rule == "HK-CLI-008")
            .map(|f| (f.title.as_str(), f.severity, f.fingerprint.as_deref()))
            .collect();
        assert_eq!(
            stripe,
            [
                ("Stripe CLI live-mode key", Severity::High, Some("rk_l…008")),
                ("Stripe CLI test-mode key", Severity::Low, Some("rk_t…008")),
            ]
        );
    }

    #[test]
    fn doppler_scopes_are_shown_as_paths() {
        let dir = tempfile::tempdir().unwrap();
        let scope = dir.path().join("code/app");
        write(
            dir.path(),
            ".doppler/.doppler.yaml",
            &format!(
                "scoped:\n    {}:\n        token: dp.ct.FAKEFAKEFAKEFAKE1096\n    /other:\n        token: \"\"\n",
                scope.display()
            ),
        );
        let f = CliLoginsCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].location, "~/.doppler/.doppler.yaml [~/code/app]");
    }

    #[test]
    fn empty_and_placeholder_values_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".vault-token", "\n\n");
        write(dir.path(), ".supabase/access-token", "");
        write(
            dir.path(),
            ".kaggle/kaggle.json",
            r#"{"username": "u", "key": ""}"#,
        );
        write(
            dir.path(),
            ".railway/config.json",
            r#"{"user": {"token": null}}"#,
        );
        write(
            dir.path(),
            ".fly/config.yml",
            "access_token: ${FLY_TOKEN}\n",
        );
        write(
            dir.path(),
            ".claude/settings.json",
            "{\"env\": {\"API_KEY\": \"${KEY}\"}}",
        );
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(run_both(&ctx).is_empty(), "{:#?}", run_both(&ctx));
        assert!(ctx.take_unreadable().is_empty());
    }

    #[test]
    fn broken_files_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".codex/auth.json", "{ not json");
        write(dir.path(), ".fly/config.yml", "access_token: [unclosed\n");
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(run_both(&ctx).is_empty());
        let problems = ctx.take_unreadable();
        let paths: Vec<String> = problems.iter().map(|(p, _)| ctx.display_path(p)).collect();
        assert_eq!(
            paths,
            ["~/.codex/auth.json", "~/.fly/config.yml"],
            "{problems:?}"
        );
    }

    #[test]
    fn titles_are_short() {
        for login in AI_LOGINS.iter().chain(CLI_LOGINS) {
            assert!(login.title.chars().count() <= 44, "{}", login.title);
        }
    }

    #[test]
    fn lookups() {
        let v: Value = serde_json::json!({"a": {"x": {"t": "1"}, "y": {"t": "2"}}, "b": "3"});
        let found: Vec<(Option<String>, &Value)> = lookup(&v, "a.*.t");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0.as_deref(), Some("x"));
        assert_eq!(lookup(&v, "b")[0].1, "3");
        assert!(lookup(&v, "b.c").is_empty());
        assert_eq!(lookup(&v, "").len(), 1);
    }
}
