//! Redaction at the source: secrets pasted into the *names* the checks quote
//! (section names, registry keys, user names, helper commands, host names,
//! bare `.env` lines, git remote URLs) never reach any output.
//!
//! `tests/fixtures/leaky` holds one such case per check. The parts that
//! cannot be committed as files (a `.git/config`, a symlink) are created in a
//! temporary copy of the project.

mod common;

use std::path::Path;

use common::{copy_dir, fixture, run_in};

/// Any 10-character slice of a secret counts as a leak, as in `redaction.rs`.
const WINDOW: usize = 10;

const FORMATS: &[&str] = &["text", "json", "markdown", "sarif"];

/// Secrets in the leaky fixture that do not contain "FAKE" or are split by
/// the tokenizer below.
const EXTRA_SECRETS: &[&str] = &[
    // base64 of "x-access-token:ghp_...000992" in ~/.gitconfig.
    "eC1hY2Nlc3MtdG9rZW46Z2hwX0ZBS0VGQUtFRkFLRUZBS0VGQUtFRkFLRUZBS0UwMDA5OTI=",
    "RkFLRWRvY2tlckFVVEgwMDIx",
    "f(){echo${IFS}password=",
    "FAKEcredproc0019:secret",
    "FAKEnetrcHost0016:FAKEnetrcPW0016",
    "FAKEhelperName0022:secret",
];

/// Every FAKE-containing token in the leaky fixture, plus the extras.
fn secrets() -> Vec<String> {
    let mut files = Vec::new();
    collect_files(&fixture("leaky"), &mut files);
    let mut secrets: Vec<String> = EXTRA_SECRETS.iter().map(|s| s.to_string()).collect();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for token in text.split(|c: char| c.is_whitespace() || "\"'=,:@{}[]/?;".contains(c)) {
            if token.contains("FAKE") && token.len() >= 9 {
                secrets.push(token.to_string());
            }
        }
    }
    secrets.push(REMOTE_TOKEN.to_string());
    secrets.push("FAKEuserH".to_string());
    secrets.sort();
    secrets.dedup();
    secrets
}

const REMOTE_TOKEN: &str = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000993";

fn collect_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn assert_no_leak(label: &str, output: &str, secrets: &[String]) {
    for secret in secrets {
        let chars: Vec<char> = secret.chars().collect();
        let windows: Vec<String> = if chars.len() <= WINDOW {
            vec![secret.clone()]
        } else {
            chars.windows(WINDOW).map(|w| w.iter().collect()).collect()
        };
        for window in windows {
            assert!(
                !output.contains(&window),
                "{label}: output contains {window:?} from a fixture secret\n{output}"
            );
        }
    }
}

/// The leaky project in a temporary directory, with a token in the git
/// remote URL and (on Unix) a `.env` symlinked out of the project.
fn project(tmp: &Path) -> std::path::PathBuf {
    let project = tmp.join("project");
    copy_dir(&fixture("leaky/project"), &project);
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(
        project.join(".git/config"),
        format!(
            "[remote \"origin\"]\n\turl = https://FAKEuserH:{REMOTE_TOKEN}@github.com/o/r.git\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        std::fs::write(
            tmp.join("outside.env"),
            "OUTSIDE_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000994\n",
        )
        .unwrap();
        std::fs::create_dir_all(project.join("apps/web")).unwrap();
        std::os::unix::fs::symlink("../../../outside.env", project.join("apps/web/.env")).unwrap();
    }
    project
}

#[test]
fn secrets_in_names_never_reach_any_output() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = project(tmp.path());
    let home = fixture("leaky/home");
    let mut secrets = secrets();
    secrets.push("ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000994".to_string());
    assert!(secrets.len() > 20, "{secrets:?}");
    for format in FORMATS {
        for mode in ["scan", "preflight"] {
            if mode == "preflight" && !["text", "json"].contains(format) {
                continue;
            }
            let out = run_in(&home, &cwd, &[mode, "--format", format, "--no-color"], &[]);
            let label = format!("{mode} {format}");
            assert_ne!(out.code, 2, "{label}: {}", out.stderr);
            assert_no_leak(&label, &out.stdout, &secrets);
            assert_no_leak(&label, &out.stderr, &secrets);
        }
    }
}

#[test]
fn the_leaky_fixture_is_still_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = project(tmp.path());
    let out = run_in(
        &fixture("leaky/home"),
        &cwd,
        &["scan", "--format", "json"],
        &[],
    );
    let doc: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let locations: Vec<&str> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["location"].as_str().unwrap())
        .collect();
    for expected in [
        "~/.gitconfig [credential https://github.example.com]",
        "~/.gitconfig [credential]",
        "~/.gitconfig [url https://github.com]",
        "~/.gitconfig [http https://github.com]",
        "./.git/config [remote origin]",
        "~/.kube/config user https://k8s.example.com",
        "~/.netrc (machine (not a host name))",
        "~/.npmrc (//registry.example.com/)",
        "~/.docker/config.json (https://registry.example.com)",
        "~/.docker/config.json (unrecognised helper)",
        "./.env:1",
        "./.env:2",
        "./.env: OPENAI_API_KEY",
        "~/.aws/config [profile cp]",
    ] {
        assert!(
            locations.contains(&expected),
            "{expected} not in {locations:?}"
        );
    }
    #[cfg(unix)]
    assert!(
        locations.contains(&"./apps/web/.env"),
        "the out-of-tree symlink is reported as unreadable: {locations:?}"
    );
}

#[test]
fn strict_fails_closed_on_unreadable_files() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(home.join(".kube")).unwrap();
    std::fs::write(home.join(".kube/config"), "users: [\n").unwrap();
    // A file over the 1 MiB limit.
    std::fs::write(home.join(".npmrc"), "x".repeat(1024 * 1024 + 1)).unwrap();

    let lenient = run_in(&home, &home, &["preflight"], &[]);
    assert_eq!(lenient.code, 0, "{}", lenient.stdout);
    assert!(
        lenient.stdout.contains("2 files could not be read"),
        "{}",
        lenient.stdout
    );

    let strict = run_in(&home, &home, &["preflight", "--strict"], &[]);
    assert_eq!(strict.code, 1, "{}", strict.stdout);
    assert!(
        strict
            .stdout
            .starts_with("heldkeys preflight: FAIL, 2 files could not be read (--strict)"),
        "{}",
        strict.stdout
    );

    let scan = run_in(&home, &home, &["scan", "--format", "json"], &[]);
    assert_eq!(scan.code, 0);
    let doc: serde_json::Value = serde_json::from_str(&scan.stdout).unwrap();
    let details: Vec<&str> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "HK-READ-001")
        .map(|f| f["detail"].as_str().unwrap())
        .collect();
    assert_eq!(details.len(), 2, "{details:?}");
    assert!(details.contains(&"could not read ~/.npmrc: larger than 1 MiB"));
    assert!(
        details
            .iter()
            .any(|d| d.starts_with("could not read ~/.kube/config: not valid YAML"))
    );
    assert_eq!(
        run_in(&home, &home, &["scan", "--strict", "--quiet"], &[]).code,
        1
    );
}

#[cfg(unix)]
#[test]
fn a_fifo_where_a_config_should_be_does_not_hang() {
    let tmp = tempfile::tempdir().unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(tmp.path().join(".netrc"))
        .status()
        .unwrap();
    assert!(status.success());
    let out = run_in(tmp.path(), tmp.path(), &["preflight", "--strict"], &[]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(out.stdout.contains("~/.netrc"), "{}", out.stdout);
}
