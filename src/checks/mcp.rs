//! `mcp`: MCP server configs that embed credentials.
//!
//! MCP clients start each configured server with the `env`, `args`, URL and
//! headers written in their config file. People paste tokens straight into
//! those files, where any agent running as the same user can read them (and
//! the agent can also call the server, which acts with the token).
//!
//! We read the configs of Claude Desktop, Claude Code, Cursor, VS Code,
//! Windsurf, Zed, Codex and Gemini CLI, in the user's home and in the working
//! directory. Every string that could carry a credential goes through the
//! shared rules in `rules`, so `mcp` agrees with `env` and `dotenv` on what a
//! credential is. Values only ever leave this file as `redact` fingerprints.
//!
//! Project-level configs (`./.mcp.json`, `./.cursor/mcp.json`, ...) get an
//! extra Info finding even when they hold no secret: the agent starts the
//! commands they list when it opens the directory, so a cloned repo can run
//! code on your machine through them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;
use crate::jsonc;
use crate::rules;
use crate::sanitize::sanitize;
use crate::toml_subset;

pub struct McpCheck;

const ID: &str = "mcp";

const KNOWN_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-MCP-001",
    summary: "Token of a known format in an MCP server config (env, args, URL or headers)",
};

const BY_NAME: Rule = Rule {
    check: ID,
    id: "HK-MCP-002",
    summary: "Credential-named value with a secret-looking value in an MCP server config",
};

const PROJECT_CONFIG: Rule = Rule {
    check: ID,
    id: "HK-MCP-003",
    summary: "Project-level MCP config whose servers start when an agent opens the directory (context)",
};

const RULES: &[Rule] = &[KNOWN_TOKEN, BY_NAME, PROJECT_CONFIG];

const FIX: &str = "Rotate it and remove it from the MCP config: use the client's secret prompt (for example ${input:...} in VS Code) or a credential helper, and give the server its own narrowly scoped token.";

/// Claude Code's `~/.claude.json` also keeps per-project state and can grow
/// past the usual 1 MB file limit, so it gets a larger one.
const CLAUDE_JSON_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Fields that hold a URL. `serverUrl` is Windsurf's, `httpUrl` Gemini CLI's.
const URL_FIELDS: &[&str] = &["url", "serverUrl", "httpUrl"];
/// Fields that hold HTTP headers. `http_headers` is Codex's.
const HEADER_FIELDS: &[&str] = &["headers", "http_headers"];
/// Fields handled by their own code, skipped by the generic field check.
const STRUCTURED_FIELDS: &[&str] = &[
    "env",
    "args",
    "url",
    "serverUrl",
    "httpUrl",
    "headers",
    "http_headers",
    "settings",
    "command",
];

/// Where in a config file the servers live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// `{"mcpServers": {...}}`: Claude Desktop, Cursor, Windsurf, Gemini CLI, `.mcp.json`.
    McpServers,
    /// `~/.claude.json`: `mcpServers` plus `projects.<dir>.mcpServers`.
    ClaudeCodeUser,
    /// `{"servers": {...}}`: VS Code `mcp.json`.
    VsCodeServers,
    /// `{"mcp": {"servers": {...}}}`: VS Code `settings.json`.
    VsCodeSettings,
    /// `{"context_servers": {...}}`: Zed `settings.json`.
    Zed,
    /// `[mcp_servers.<name>]`: Codex `config.toml`.
    Codex,
}

/// One config file that may define MCP servers.
struct Source {
    client: &'static str,
    path: PathBuf,
    layout: Layout,
    /// In the working directory (shared through the repo) rather than the home.
    project: bool,
}

impl Check for McpCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "MCP server configs (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Codex, Gemini CLI) that embed credentials in env, args, URLs or headers, plus project-level configs that start servers."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = BTreeSet::new();
        for source in sources(ctx) {
            // The same file can show up twice, for example when the working
            // directory is the home directory. Report it once, as a user config.
            // Not filtered on "is a regular file": a FIFO or directory where a
            // config should be is recorded by the reader, so --strict sees it.
            let key = std::fs::canonicalize(&source.path).unwrap_or(source.path.clone());
            if !seen.insert(key) {
                continue;
            }
            findings.extend(check_source(ctx, &source));
        }
        findings
    }
}

/// Every config file we know of, user configs first.
fn sources(ctx: &Context) -> Vec<Source> {
    let user = |client, path, layout| Source {
        client,
        path,
        layout,
        project: false,
    };
    let project = |client, relative: &str, layout| Source {
        client,
        path: ctx.cwd.join(relative),
        layout,
        project: true,
    };
    // macOS keeps app configs here; Linux uses $XDG_CONFIG_HOME (~/.config).
    let mac = ctx.home_path("Library/Application Support");
    let xdg = ctx.config_dir();
    let claude_code_dir = ctx.path_from_env("CLAUDE_CONFIG_DIR", ctx.home.clone());
    let codex_home = ctx.path_from_env("CODEX_HOME", ctx.home_path(".codex"));

    let mut list = vec![
        user(
            "Claude Desktop",
            mac.join("Claude/claude_desktop_config.json"),
            Layout::McpServers,
        ),
        user(
            "Claude Desktop",
            xdg.join("Claude/claude_desktop_config.json"),
            Layout::McpServers,
        ),
        user(
            "Claude Code",
            claude_code_dir.join(".claude.json"),
            Layout::ClaudeCodeUser,
        ),
        user(
            "Cursor",
            ctx.home_path(".cursor/mcp.json"),
            Layout::McpServers,
        ),
    ];
    for base in [&mac, &xdg] {
        for app in ["Code", "Code - Insiders"] {
            let dir = base.join(app).join("User");
            list.push(user(
                "VS Code",
                dir.join("settings.json"),
                Layout::VsCodeSettings,
            ));
            list.push(user("VS Code", dir.join("mcp.json"), Layout::VsCodeServers));
        }
    }
    list.extend([
        user(
            "Windsurf",
            ctx.home_path(".codeium/windsurf/mcp_config.json"),
            Layout::McpServers,
        ),
        user("Zed", xdg.join("zed/settings.json"), Layout::Zed),
        user("Codex", codex_home.join("config.toml"), Layout::Codex),
        user(
            "Gemini CLI",
            ctx.home_path(".gemini/settings.json"),
            Layout::McpServers,
        ),
        project("Claude Code", ".mcp.json", Layout::McpServers),
        project("Cursor", ".cursor/mcp.json", Layout::McpServers),
        project("VS Code", ".vscode/mcp.json", Layout::VsCodeServers),
        project("VS Code", ".vscode/settings.json", Layout::VsCodeSettings),
        project("Gemini CLI", ".gemini/settings.json", Layout::McpServers),
        project("Zed", ".zed/settings.json", Layout::Zed),
    ]);
    list
}

fn check_source(ctx: &Context, source: &Source) -> Vec<Finding> {
    // Project configs come with the repo: no symlinks out of the working
    // directory. Files that exist but cannot be read or parsed are recorded
    // for `read-errors`, so a broken config is not a silent pass.
    let text = if source.project {
        ctx.read_project_file(&source.path)
    } else if source.layout == Layout::ClaudeCodeUser {
        ctx.read_file_limited(&source.path, CLAUDE_JSON_MAX_BYTES)
    } else {
        ctx.read_file(&source.path)
    };
    let Some(text) = text else {
        return Vec::new();
    };
    let root = if source.layout == Layout::Codex {
        toml_subset::parse(&text)
    } else if jsonc::is_blank(&text) {
        // An editor created the file and nothing was put in it yet.
        return Vec::new();
    } else {
        match jsonc::parse(&text) {
            Some(v) => v,
            None => {
                ctx.note_unreadable(&source.path, "not valid JSON");
                return Vec::new();
            }
        }
    };

    let file = ctx.display_path(&source.path);
    let scope = if source.project {
        "project config (shared through the repo)"
    } else {
        "user config"
    };
    let mut findings = Vec::new();
    let mut server_names = Vec::new();
    let mut programs = BTreeSet::new();
    for (group, servers) in server_groups(ctx, source.layout, &root) {
        for (name, server) in servers {
            let name = sanitize(name);
            server_names.push(name.clone());
            programs.insert(program(server));
            for candidate in candidates(server) {
                let Some((c, value)) = candidate.options.iter().find_map(|(n, v)| {
                    rules::classify_named_value(n, v).map(|c| (c, v.to_string()))
                }) else {
                    continue;
                };
                let rule = if c.rule_id.is_some() {
                    KNOWN_TOKEN
                } else {
                    BY_NAME
                };
                findings.push(
                    Finding::new(
                        rule,
                        c.title,
                        format!("{file} {group}.{name} {}", candidate.place),
                        c.severity,
                        c.lifetime,
                        c.access,
                        FIX,
                    )
                    .with_fingerprint(c.fingerprint)
                    .with_secret(&value)
                    .with_detail(format!("{} {scope}", source.client)),
                );
            }
        }
    }

    if source.project && !server_names.is_empty() {
        findings.push(project_finding(source, &file, &server_names, &programs));
    }
    findings
}

/// The Info finding for a project-level config: which servers it starts.
fn project_finding(
    source: &Source,
    file: &str,
    names: &[String],
    programs: &BTreeSet<String>,
) -> Finding {
    const SHOWN: usize = 5;
    let mut shown: Vec<&str> = names.iter().take(SHOWN).map(String::as_str).collect();
    let more = names.len().saturating_sub(SHOWN);
    let more_text = format!("and {more} more");
    if more > 0 {
        shown.push(&more_text);
    }
    let programs: Vec<&str> = programs
        .iter()
        .filter(|p| !p.is_empty())
        .map(String::as_str)
        .collect();
    Finding::new(
        PROJECT_CONFIG,
        "Project-level MCP config",
        file,
        Severity::Info,
        Lifetime::Unknown,
        Access::Unknown,
        "Review these servers before an agent opens this directory; a cloned repo can add servers that run commands when the agent starts.",
    )
    .with_detail(format!(
        "{}: {} server(s) ({}); runs {}",
        source.client,
        names.len(),
        shown.join(", "),
        if programs.is_empty() {
            "nothing locally".to_string()
        } else {
            programs.join(", ")
        }
    ))
}

/// The server maps in a parsed config, with the path to each (for the
/// finding's location).
fn server_groups<'a>(
    ctx: &Context,
    layout: Layout,
    root: &'a Value,
) -> Vec<(String, &'a Map<String, Value>)> {
    let mut groups = Vec::new();
    let mut add = |path: String, map: Option<&'a Map<String, Value>>| {
        if let Some(map) = map {
            groups.push((path, map));
        }
    };
    let object = |v: &'a Value, key: &str| v.get(key).and_then(Value::as_object);
    match layout {
        Layout::McpServers => add("mcpServers".into(), object(root, "mcpServers")),
        Layout::ClaudeCodeUser => {
            add("mcpServers".into(), object(root, "mcpServers"));
            // Servers added with `claude mcp add` (local scope) live under the
            // project directory they were added in.
            for (dir, project) in object(root, "projects").into_iter().flatten() {
                let dir = sanitize(&ctx.display_path(Path::new(dir)));
                add(
                    format!("projects[{dir}].mcpServers"),
                    object(project, "mcpServers"),
                );
            }
        }
        Layout::VsCodeServers => add("servers".into(), object(root, "servers")),
        Layout::VsCodeSettings => add(
            "mcp.servers".into(),
            root.get("mcp").and_then(|m| object(m, "servers")),
        ),
        Layout::Zed => add("context_servers".into(), object(root, "context_servers")),
        Layout::Codex => add("mcp_servers".into(), object(root, "mcp_servers")),
    }
    groups
}

/// The program a server runs, for the project-level summary: just the file
/// name (arguments can hold secrets), or "remote" for URL-only servers.
fn program(server: &Value) -> String {
    let command = match server.get("command") {
        Some(Value::String(s)) => Some(s.as_str()),
        // Zed's older format: "command": {"path": ..., "args": [...]}.
        Some(Value::Object(m)) => m.get("path").and_then(Value::as_str),
        _ => None,
    };
    match command {
        Some(c) => sanitize(&fsutil::file_name(Path::new(
            c.split_whitespace().next().unwrap_or(""),
        ))),
        None if URL_FIELDS.iter().any(|f| server.get(f).is_some()) => "remote".to_string(),
        None => String::new(),
    }
}

/// A place in a server definition that may hold a credential, with the
/// `(name, value)` readings to try in order. The first one that classifies
/// as a credential wins, so one place gives at most one finding.
struct Candidate {
    place: String,
    options: Vec<(String, String)>,
}

impl Candidate {
    fn new(place: impl Into<String>, name: impl Into<String>, value: impl Into<String>) -> Self {
        Candidate {
            place: place.into(),
            options: vec![(name.into(), value.into())],
        }
    }
}

/// Every string in a server definition that could be a credential.
fn candidates(server: &Value) -> Vec<Candidate> {
    let mut out = Vec::new();
    // Zed's older format nests args and env inside a "command" object.
    let parts = [Some(server), server.get("command")];
    for part in parts.into_iter().flatten().filter_map(Value::as_object) {
        for (key, value) in strings(part.get("env")) {
            out.push(Candidate::new(format!("env {}", sanitize(key)), key, value));
        }
        if let Some(args) = part.get("args").and_then(Value::as_array) {
            out.extend(arg_candidates(args));
        }
        for field in URL_FIELDS {
            if let Some(url) = part.get(*field).and_then(Value::as_str) {
                out.extend(url_candidates(field, url));
            }
        }
        for field in HEADER_FIELDS {
            for (header, value) in strings(part.get(*field)) {
                let place = format!("{field} {}", sanitize(header));
                out.push(header_candidate(place, header, value));
            }
        }
        // Zed extension settings, e.g. "github_personal_access_token".
        for (key, value) in strings(part.get("settings")) {
            out.push(Candidate::new(
                format!("settings {}", sanitize(key)),
                env_style(key),
                value,
            ));
        }
        // Anything else that is named like a credential, such as Codex's
        // `bearer_token` or an `apiKey` field.
        for (key, value) in part {
            if let Some(value) = value.as_str()
                && !STRUCTURED_FIELDS.contains(&key.as_str())
            {
                out.push(Candidate::new(sanitize(key), env_style(key), value));
            }
        }
    }
    out
}

/// The string entries of a JSON object (non-strings are skipped).
fn strings(value: Option<&Value>) -> Vec<(&str, &str)> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((k.as_str(), v.as_str()?)))
        .collect()
}

/// Command-line arguments. Tokens show up as a whole argument, as
/// `--flag=value` or `NAME=value`, after a flag (`--token value`), inside a
/// header (`--header "Authorization: Bearer ..."`) or in a URL's query.
fn arg_candidates(args: &[Value]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        let Some(arg) = arg.as_str() else {
            continue;
        };
        let place = format!("args[{i}]");
        if arg.contains("://") {
            out.extend(url_candidates(&place, arg));
            continue;
        }
        let mut candidate = Candidate::new(place.clone(), "", arg);
        if let Some((name, value)) = arg.split_once('=')
            && is_name(name)
        {
            candidate.options.push((env_style(name), value.to_string()));
        }
        if let Some((name, value)) = arg.split_once(':')
            && is_name(name)
        {
            candidate
                .options
                .extend(header_candidate(place, name, value.trim()).options);
        }
        let previous = i
            .checked_sub(1)
            .and_then(|p| args[p].as_str())
            .filter(|p| p.starts_with('-') && !p.contains('='));
        if let Some(flag) = previous {
            candidate.options.push((env_style(flag), arg.to_string()));
        }
        out.push(candidate);
    }
    out
}

/// A URL: the whole thing (for `user:password@` and webhook URLs), then each
/// query parameter by its name (`?api_key=...`).
fn url_candidates(place: &str, url: &str) -> Vec<Candidate> {
    let mut out = vec![Candidate::new(place, "", url)];
    let query = url
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(""))
        .unwrap_or("");
    for pair in query.split('&') {
        if let Some((name, value)) = pair.split_once('=') {
            out.push(Candidate::new(
                format!("{place} ?{}", sanitize(name)),
                env_style(name),
                value,
            ));
        }
    }
    out
}

/// A header value, with the auth scheme (`Bearer `, `Basic `...) removed.
/// An `Authorization` header always carries a credential, so it is given a
/// name the name rules recognise; other headers use their own name
/// (`X-API-Key` reads as `X_API_KEY`).
fn header_candidate(place: String, header: &str, value: &str) -> Candidate {
    let value = value.trim();
    let token = ["Bearer ", "bearer ", "Basic ", "basic ", "Token ", "token "]
        .iter()
        .find_map(|scheme| value.strip_prefix(scheme))
        .unwrap_or(value);
    let name = if header.eq_ignore_ascii_case("authorization")
        || header.eq_ignore_ascii_case("proxy-authorization")
    {
        "AUTHORIZATION_TOKEN".to_string()
    } else {
        env_style(header)
    };
    Candidate {
        place,
        options: vec![
            (String::new(), token.to_string()),
            (name, token.to_string()),
        ],
    }
}

/// Is this a plain name such as `--api-key`, `GITHUB_TOKEN` or `X-Api-Key`?
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Turns a flag, field or header name into an environment-variable-style
/// name, so the shared name rules apply: `--api-key` and `apiKey` become
/// `API_KEY`.
fn env_style(name: &str) -> String {
    let mut out = String::new();
    let mut previous_lower = false;
    for c in name.trim_start_matches('-').chars() {
        if c.is_ascii_uppercase() && previous_lower {
            out.push('_');
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{fixture, fixture_ctx, write};
    use std::collections::BTreeMap;

    /// The `mcp/home` fixture as home, `mcp/project` as working directory.
    fn home_and_project() -> Vec<Finding> {
        let home = fixture("mcp/home");
        let ctx = Context::new(home.clone(), home, fixture("mcp/project"), BTreeMap::new());
        McpCheck.run(&ctx)
    }

    fn find<'a>(findings: &'a [Finding], location: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.location == location)
            .unwrap_or_else(|| {
                let all: Vec<&str> = findings.iter().map(|f| f.location.as_str()).collect();
                panic!("{location} not in {all:#?}")
            })
    }

    #[test]
    fn every_client_is_read() {
        let f = home_and_project();
        let clients: BTreeSet<&str> = f
            .iter()
            .filter_map(|f| f.detail.as_deref())
            .map(|d| d.split(" user config").next().unwrap())
            .collect();
        for client in [
            "Claude Desktop",
            "Claude Code",
            "Cursor",
            "VS Code",
            "Windsurf",
            "Zed",
            "Codex",
            "Gemini CLI",
        ] {
            assert!(
                clients.contains(client),
                "{client} missing from {clients:?}"
            );
        }
    }

    #[test]
    fn env_values() {
        let f = home_and_project();
        let gh = find(
            &f,
            "~/Library/Application Support/Claude/claude_desktop_config.json mcpServers.github env GITHUB_PERSONAL_ACCESS_TOKEN",
        );
        assert_eq!(gh.rule, "HK-MCP-001");
        assert_eq!(gh.severity, Severity::High);
        assert_eq!(gh.fingerprint.as_deref(), Some("ghp_…301"));
        assert_eq!(gh.detail.as_deref(), Some("Claude Desktop user config"));
        let slack = find(
            &f,
            "~/.cursor/mcp.json mcpServers.slack env SLACK_BOT_TOKEN",
        );
        assert_eq!(slack.title, "Slack token");
        let npm = find(
            &f,
            "~/Library/Application Support/Code/User/settings.json mcp.servers.npm env NPM_TOKEN",
        );
        assert_eq!(npm.fingerprint.as_deref(), Some("npm_…307"));
        find(
            &f,
            "~/.config/Code/User/mcp.json servers.pypi env PYPI_TOKEN",
        );
        find(
            &f,
            "~/.codex/config.toml mcp_servers.huggingface env HF_TOKEN",
        );
        // Not credentials: an id and a $VAR reference.
        assert!(!f.iter().any(|f| f.location.ends_with("SLACK_TEAM_ID")));
        assert!(!f.iter().any(|f| f.location.contains("mcpServers.safe")));
    }

    #[test]
    fn args() {
        let f = home_and_project();
        let pg = find(
            &f,
            "~/.config/Claude/claude_desktop_config.json mcpServers.postgres args[2]",
        );
        assert_eq!(pg.title, "Connection string with embedded password");
        assert_eq!(pg.fingerprint, None);
        let stripe = find(
            &f,
            "~/.claude.json projects[/work/shop].mcpServers.stripe args[3]",
        );
        assert_eq!(stripe.rule, "HK-MCP-002");
        assert_eq!(stripe.fingerprint, None);
        let header = find(&f, "~/.cursor/mcp.json mcpServers.remote args[3]");
        assert_eq!(header.title, "GitHub OAuth token");
        let zed = find(
            &f,
            "~/.config/zed/settings.json context_servers.custom args[1]",
        );
        assert_eq!(zed.rule, "HK-MCP-002");
        // `--tools=all` and package names are not credentials.
        assert!(!f.iter().any(|f| f.location.ends_with("stripe args[2]")));
    }

    #[test]
    fn urls_headers_and_named_fields() {
        let f = home_and_project();
        let linear = find(&f, "~/.claude.json mcpServers.linear headers Authorization");
        assert_eq!(linear.rule, "HK-MCP-002");
        find(
            &f,
            "~/.codeium/windsurf/mcp_config.json mcpServers.search serverUrl ?api_key",
        );
        let gitlab = find(
            &f,
            "~/.gemini/settings.json mcpServers.gitlab headers PRIVATE-TOKEN",
        );
        assert_eq!(gitlab.title, "GitLab personal access token");
        find(
            &f,
            "~/.config/zed/settings.json context_servers.github settings github_personal_access_token",
        );
        find(&f, "~/.codex/config.toml mcp_servers.internal bearer_token");
        find(
            &f,
            "~/.codex/config.toml mcp_servers.internal http_headers X-Api-Key",
        );
        // VS Code's ${input:...} prompt is the safe pattern.
        assert!(!f.iter().any(|f| f.location.contains("mcp.servers.github")));
    }

    #[test]
    fn project_configs() {
        let f = home_and_project();
        let db = find(&f, "./.mcp.json mcpServers.db env DATABASE_URL");
        assert!(db.detail.as_deref().unwrap().contains("project config"));
        let info: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-MCP-003").collect();
        let locations: Vec<&str> = info.iter().map(|f| f.location.as_str()).collect();
        assert_eq!(
            locations,
            ["./.mcp.json", "./.cursor/mcp.json", "./.vscode/mcp.json"]
        );
        assert!(info.iter().all(|f| f.severity == Severity::Info));
        assert_eq!(
            info[0].detail.as_deref(),
            Some("Claude Code: 2 server(s) (db, docs); runs npx, uvx")
        );
        assert_eq!(
            info[2].detail.as_deref(),
            Some("VS Code: 1 server(s) (api); runs remote")
        );
    }

    #[test]
    fn exact_count() {
        let f = home_and_project();
        let credentials = f.iter().filter(|f| f.is_credential()).count();
        assert_eq!(credentials, 16, "{f:#?}");
    }

    #[test]
    fn placeholders_are_not_reported() {
        let f = McpCheck.run(&fixture_ctx("mcp/placeholders"));
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn empty_home() {
        assert!(McpCheck.run(&fixture_ctx("empty")).is_empty());
    }

    #[test]
    fn home_as_working_directory_is_not_a_project() {
        // fixture_ctx uses the same directory as home and cwd.
        let f = McpCheck.run(&fixture_ctx("mcp/home"));
        assert!(f.iter().all(|f| f.rule != "HK-MCP-003"));
        assert!(f.iter().all(|f| !f.location.starts_with("./")));
    }

    #[test]
    fn env_dirs_and_control_characters() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "elsewhere/.claude.json",
            r#"{"mcpServers": {"bad\u001b[31m": {"env": {"GITHUB_TOKEN": "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000399"}}}}"#,
        );
        let ctx = crate::checks::testutil::ctx_with_env(
            dir.path(),
            &[("CLAUDE_CONFIG_DIR", "~/elsewhere")],
        );
        let f = McpCheck.run(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].location,
            "~/elsewhere/.claude.json mcpServers.bad?[31m env GITHUB_TOKEN"
        );
    }

    #[test]
    fn empty_and_commented_configs_are_not_errors() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".cursor/mcp.json", "");
        write(dir.path(), ".codeium/windsurf/mcp_config.json", "  \n");
        write(
            dir.path(),
            ".config/Code/User/mcp.json",
            "\u{feff}// servers\n{\"servers\": {\"gh\": {\"env\": {\"GITHUB_TOKEN\": \"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000398\"},},},}\n",
        );
        let ctx = crate::checks::testutil::ctx_with_env(dir.path(), &[]);
        let f = McpCheck.run(&ctx);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].fingerprint.as_deref(), Some("ghp_…398"));
        assert!(ctx.take_unreadable().is_empty());
        // Broken JSON is still reported.
        write(dir.path(), ".cursor/mcp.json", "{ broken");
        McpCheck.run(&ctx);
        assert_eq!(ctx.take_unreadable().len(), 1);
    }

    #[test]
    fn names() {
        assert_eq!(env_style("--api-key"), "API_KEY");
        assert_eq!(env_style("apiKey"), "API_KEY");
        assert_eq!(env_style("X-Api-Key"), "X_API_KEY");
        assert_eq!(env_style("bearer_token"), "BEARER_TOKEN");
        assert!(is_name("--token"));
        assert!(!is_name("a b"));
    }
}
