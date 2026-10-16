//! The default text output stays readable on a big machine: a home with
//! the usual logins and a workspace of 30 checkouts and worktrees of one
//! project whose `.env` files share values. Everything is generated in a
//! temporary directory; every value is fake.

mod common;

use std::path::{Path, PathBuf};

use common::{FAKE_SSH_KEY, copy_dir, fixture, run_in};

const WORKTREES: usize = 30;

/// Fake values the big home holds. Listed so the test can check none of
/// them reaches the output.
const ANTHROPIC_SHARED: &str = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKE-0801FAKE1";
const ADMIN_SECRET: &str = "FAKEadminAPIsecret0802";
const DB_URL: &str = "postgres://app:FAKEdbPASSWORD0803@db.internal:5432/app";
const WORKOS_KEY: &str = "sk_test_FAKEFAKEFAKEFAKE0804";
const ENV_GITHUB: &str = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000805";
const AWS_KEY_ID: &str = "AKIAFAKEFAKEFAKE0806";
const AWS_SECRET: &str = "FAKEawsSECRETkeyFAKEawsSECRET0806";
const GIT_GITHUB: &str = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000807";
const GIT_HF: &str = "hf_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0808";
const NPM: &str = "npm_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0809";
const CARGO: &str = "cioFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0810";
const MCP_GITHUB: &str = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000811";
const MCP_LINEAR: &str = "lin_api_FAKEFAKEFAKEFAKEFAKEFAKEFAKE0812";

fn secrets() -> Vec<String> {
    let mut all: Vec<String> = [
        ANTHROPIC_SHARED,
        ADMIN_SECRET,
        "FAKEdbPASSWORD0803",
        WORKOS_KEY,
        ENV_GITHUB,
        AWS_KEY_ID,
        AWS_SECRET,
        GIT_GITHUB,
        GIT_HF,
        NPM,
        CARGO,
        MCP_GITHUB,
        MCP_LINEAR,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for i in 0..WORKTREES {
        all.push(openai_key(i));
    }
    all
}

/// A different OpenAI key for every checkout.
fn openai_key(i: usize) -> String {
    format!("sk-proj-FAKEFAKEFAKEFAKEFAKE{i:04}x0820")
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Builds the home in `root`: returns (home, working directory).
fn big_home(root: &Path) -> (PathBuf, PathBuf) {
    let home = root.join("home");
    write(
        &home.join(".aws/credentials"),
        &format!(
            "[work-users]\naws_access_key_id = {AWS_KEY_ID}\naws_secret_access_key = {AWS_SECRET}\n"
        ),
    );
    write(
        &home.join(".git-credentials"),
        &format!("https://hugo:{GIT_GITHUB}@github.com\nhttps://hugo:{GIT_HF}@huggingface.co\n"),
    );
    write(
        &home.join(".npmrc"),
        &format!("//registry.npmjs.org/:_authToken={NPM}\n"),
    );
    write(
        &home.join(".cargo/credentials.toml"),
        &format!("[registry]\ntoken = \"{CARGO}\"\n"),
    );
    write(
        &home.join(".config/gh/hosts.yml"),
        "github.com:\n    user: hugo\n    git_protocol: https\n",
    );
    write(
        &home.join(".gitconfig"),
        "[credential]\n\thelper = osxkeychain\n",
    );
    write(
        &home.join(".docker/config.json"),
        "{\"auths\": {\"ghcr.io\": {}}, \"credsStore\": \"desktop\"}\n",
    );
    write(&home.join(".ssh/id_ed25519"), FAKE_SSH_KEY);
    write(&home.join(".ssh/id_rsa"), FAKE_SSH_KEY);
    write(
        &home.join(".claude.json"),
        &format!(
            "{{\"mcpServers\": {{\"linear\": {{\"command\": \"npx\", \"env\": {{\"LINEAR_API_KEY\": \"{MCP_LINEAR}\"}}}}}}}}\n"
        ),
    );
    write(
        &home.join(".cursor/mcp.json"),
        &format!(
            "{{\"mcpServers\": {{\"github\": {{\"command\": \"npx\", \"env\": {{\"GITHUB_PERSONAL_ACCESS_TOKEN\": \"{MCP_GITHUB}\"}}}}}}}}\n"
        ),
    );
    // An empty VS Code MCP config: not an error.
    write(&home.join(".config/Code/User/mcp.json"), "");

    let workspace = home.join("workspace");
    for i in 0..WORKTREES {
        let name = if i == 0 {
            "webapp".to_string()
        } else {
            format!("webapp-wt-{i}")
        };
        let repo = workspace.join("acme").join(&name);
        if i == 0 {
            std::fs::create_dir_all(repo.join(".git")).unwrap();
        } else {
            write(&repo.join(".git"), "gitdir: ../webapp/.git/worktrees/x\n");
        }
        // The same Anthropic key in 4 checkouts, a different one elsewhere.
        let anthropic = if i < 4 {
            ANTHROPIC_SHARED.to_string()
        } else {
            format!("sk-ant-api03-FAKEFAKEFAKEFAKE{i:04}-0821")
        };
        write(
            &repo.join("apps/api/.env"),
            &format!(
                "NODE_ENV=development\nANTHROPIC_API_KEY={anthropic}\nADMIN_API_SECRET={ADMIN_SECRET}\nDATABASE_URL={DB_URL}\nOPENAI_API_KEY={}\n",
                openai_key(i)
            ),
        );
        write(
            &repo.join("apps/web/.env.local"),
            &format!(
                "NEXT_PUBLIC_POSTHOG_KEY=phc_FAKEFAKEFAKEFAKE{i:04}\nVITE_RECAPTCHA_SITE_KEY=6LcFAKEFAKEFAKE{i:04}\nWORKOS_API_KEY={WORKOS_KEY}\n"
            ),
        );
        write(
            &repo.join(".env.example"),
            "ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx\nDATABASE_URL=postgres://postgres:postgres@localhost:5432/app\nADMIN_API_SECRET=changeme\n",
        );
    }
    (home, workspace)
}

fn scan(home: &Path, cwd: &Path, args: &[&str]) -> common::Output {
    let env = [
        ("GITHUB_TOKEN", ENV_GITHUB),
        ("COLUMNS", "120"),
        ("PATH", "/usr/bin:/bin"),
    ];
    let out = run_in(home, cwd, args, &env);
    assert!(out.stderr.is_empty(), "{}", out.stderr);
    out
}

fn assert_no_secret(label: &str, output: &str) {
    for secret in secrets() {
        let chars: Vec<char> = secret.chars().collect();
        for window in chars.windows(10) {
            let window: String = window.iter().collect();
            assert!(!output.contains(&window), "{label}: leaks {window:?}");
        }
    }
}

#[test]
fn default_output_fits_a_screen() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, cwd) = big_home(tmp.path());
    let out = scan(&home, &cwd, &["--no-color"]);
    let text = &out.stdout;
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() <= 60, "{} lines:\n{text}", lines.len());
    for line in &lines {
        assert!(
            line.chars().count() <= 120,
            "{} chars: {line}",
            line.chars().count()
        );
    }
    let json: serde_json::Value =
        serde_json::from_str(&scan(&home, &cwd, &["--format", "json"]).stdout).unwrap();
    let total = json["findings"].as_array().unwrap().len();
    let credentials = json["summary"]["credentials"].as_u64().unwrap();
    assert!(credentials > 150, "{credentials}");
    assert!(
        lines[0].starts_with(&format!(
            "heldkeys: {credentials} credentials reachable from ~/workspace ("
        )),
        "{}",
        lines[0]
    );
    for section in [
        "Fix these first",
        "Where they are",
        "Same secret in several places",
        "Next steps",
    ] {
        assert!(
            lines.contains(&section) || text.contains(&format!("\n{section} ")),
            "{section} missing:\n{text}"
        );
    }
    // Copies are collapsed into one line each.
    assert!(
        text.contains(&format!(
            "Possible credential ADMIN_API_SECRET in {WORKTREES} files (./acme/webapp"
        )),
        "{text}"
    );
    assert!(
        text.contains("Anthropic API key sk-a…KE1 in 4 files (./acme/webapp"),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "in {} files across {WORKTREES} repos",
            WORKTREES * 2
        )),
        "{text}"
    );
    // Machine-wide credentials come first.
    let top = text.split("Fix these first\n").nth(1).unwrap();
    let first = top.lines().next().unwrap();
    assert!(first.starts_with("  HIGH"), "{first}");
    assert!(!first.contains("./acme"), "{first}");
    assert!(top.contains("~/.aws/credentials [work-users]"), "{text}");
    // Generic next steps, not one per variable.
    let steps = text.split("Next steps\n").nth(1).unwrap();
    assert!(
        steps.contains(&format!("Move secrets out of {} .env files", WORKTREES * 2)),
        "{steps}"
    );
    assert!(steps.contains("Add passphrases to 2 SSH keys"), "{steps}");
    assert!(!steps.contains("ADMIN_API_SECRET"), "{steps}");
    assert!(text.contains(&format!(
        "Run `heldkeys --details` for all {total} findings"
    )));
    assert!(text.ends_with("it can use all of them.\n"), "{text}");
    // Template placeholders and public frontend keys are not findings.
    let locations: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["location"].as_str().unwrap())
        .collect();
    assert!(
        !locations.iter().any(|l| l.contains(".env.example")),
        "{locations:?}"
    );
    assert!(
        !locations
            .iter()
            .any(|l| l.contains("NEXT_PUBLIC_") || l.contains("VITE_"))
    );
    assert!(
        !locations.iter().any(|l| l.contains("Code/User/mcp.json")),
        "{locations:?}"
    );
    assert_no_secret("default", text);
}

#[test]
fn details_list_every_finding() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, cwd) = big_home(tmp.path());
    let json: serde_json::Value =
        serde_json::from_str(&scan(&home, &cwd, &["--format", "json"]).stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    for flag in ["--details", "-v"] {
        let out = scan(&home, &cwd, &[flag, "--no-color"]);
        let text = &out.stdout;
        let rows: Vec<&str> = text
            .lines()
            .filter(|l| {
                ["    HIGH ", "    MEDIUM ", "    LOW ", "    INFO "]
                    .iter()
                    .any(|t| l.starts_with(t))
            })
            .collect();
        assert_eq!(rows.len(), findings.len(), "{text}");
        for line in text.lines() {
            assert!(line.chars().count() <= 120, "{line}");
        }
        // Each file is a heading once, relative to the scanned directory.
        let heading = "  ./acme/webapp-wt-7/apps/api/.env";
        assert_eq!(text.lines().filter(|l| *l == heading).count(), 1, "{text}");
        assert!(
            text.contains("    LOW     WorkOS test-mode API key  WORKOS_API_KEY  sk_t…804  ×30"),
            "{text}"
        );
        assert_no_secret(flag, text);
    }
}

#[test]
fn json_groups_and_counts_copies() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, cwd) = big_home(tmp.path());
    let out = scan(&home, &cwd, &["--format", "json"]);
    let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    let admin_secret: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| {
            f["location"]
                .as_str()
                .unwrap()
                .ends_with("ADMIN_API_SECRET")
        })
        .collect();
    assert_eq!(admin_secret.len(), WORKTREES);
    assert!(
        admin_secret
            .iter()
            .all(|f| f["duplicates"] == WORKTREES - 1)
    );
    assert!(admin_secret.iter().all(|f| f["category"] == "project-env"));
    // Different OpenAI keys are not copies of each other.
    let openai = findings
        .iter()
        .find(|f| f["location"].as_str().unwrap().ends_with("OPENAI_API_KEY"))
        .unwrap();
    assert!(openai.get("duplicates").is_none(), "{openai}");
    let aws = findings.iter().find(|f| f["check"] == "aws").unwrap();
    assert_eq!(aws["category"], "cloud-cli");
    assert_no_secret("json", &out.stdout);
}

#[test]
fn markdown_leads_with_the_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, cwd) = big_home(tmp.path());
    let md = scan(&home, &cwd, &["--format", "markdown"]).stdout;
    let fix = md.find("### Fix these first").expect("summary section");
    let full = md.find("### High").expect("full tables");
    assert!(fix < full, "{md}");
    assert!(md.contains("### Same secret in several places"), "{md}");
    assert_no_secret("markdown", &md);
}

/// Fake values of the editor history test.
const HISTORY_OPENAI: &str = "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE1040";
const HISTORY_DB: &str = "postgres://app:FAKEhistoryPW1041@db.internal:5432/app";
const HISTORY_COPIES: usize = 20;

/// Writes `count` Local History copies of `text` under `project/.history`.
fn history_copies(project: &Path, name: &str, text: &str, count: usize) {
    for i in 0..count {
        let copy = match name.split_once('.') {
            // `.env.local` is copied as `.env_<stamp>.local`.
            Some(("", rest)) => match rest.split_once('.') {
                Some((base, ext)) => format!(".{base}_202605072301{i:02}.{ext}"),
                None => format!(".{rest}_202605072301{i:02}"),
            },
            _ => format!("{name}_202605072301{i:02}"),
        };
        write(&project.join(".history").join(copy), text);
    }
}

#[test]
fn many_history_copies_of_one_env_file_stay_one_line() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&home).unwrap();
    let env = format!("OPENAI_API_KEY={HISTORY_OPENAI}\nDATABASE_URL={HISTORY_DB}\n");
    write(&project.join(".env"), &env);
    history_copies(&project, ".env", &env, HISTORY_COPIES);
    history_copies(&project, ".env.local", &env, HISTORY_COPIES);

    let json: serde_json::Value =
        serde_json::from_str(&scan(&home, &project, &["--format", "json"]).stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    let copies = findings
        .iter()
        .filter(|f| f["rule"] == "HK-DOTENV-003")
        .count();
    assert_eq!(copies, 2 * 2 * HISTORY_COPIES);

    let text = scan(&home, &project, &["--no-color"]).stdout;
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() <= 30, "{} lines:\n{text}", lines.len());
    // Each secret is one line in "Fix these first", shown at the .env file
    // (the third line is `scan`'s GITHUB_TOKEN).
    let top = text.split("Fix these first\n").nth(1).unwrap();
    let top = top.split("\n\n").next().unwrap();
    assert_eq!(top.lines().count(), 3, "{top}");
    assert_eq!(top.lines().filter(|l| l.contains("./")).count(), 2, "{top}");
    assert!(top.contains("./.env: OPENAI_API_KEY"), "{top}");
    assert!(top.contains("×41"), "{top}");
    assert!(
        text.contains("OpenAI project API key sk-p…040 in 41 files (./.env, +40)"),
        "{text}"
    );
    let steps = text.split("Next steps\n").nth(1).unwrap();
    assert!(
        steps.contains("Delete the editor .history folders holding 40 copies of .env files"),
        "{steps}"
    );
    for secret in [HISTORY_OPENAI, "FAKEhistoryPW1041"] {
        assert!(!text.contains(&secret[..12]), "{text}");
    }
}

#[test]
fn logins_and_history_copies_still_fit_a_screen() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, cwd) = big_home(tmp.path());
    copy_dir(&fixture("logins/home"), &home);
    let env = format!("OPENAI_API_KEY={HISTORY_OPENAI}\nDATABASE_URL={HISTORY_DB}\n");
    history_copies(&cwd.join("acme/webapp"), ".env", &env, HISTORY_COPIES);
    let text = scan(&home, &cwd, &["--no-color"]).stdout;
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() <= 60, "{} lines:\n{text}", lines.len());
    for line in &lines {
        assert!(line.chars().count() <= 120, "{line}");
    }
    assert!(text.contains("  AI tool logins "), "{text}");
    assert!(text.contains("  Developer platform CLIs "), "{text}");
    assert_no_secret("logins", &text);
}
