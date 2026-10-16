//! Shared helpers for the integration tests.
//!
//! Every run of the binary goes through `run`, which clears the environment,
//! disables the metadata probe and points --home, --root and --path at a
//! fixture, so tests never see the real home, environment or filesystem.

#![allow(dead_code)] // each test file uses a different subset

use std::path::{Path, PathBuf};

/// The binary under test. The only place the binary name is spelled out.
pub fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_heldkeys")
}

include!("fixtures.rs");

/// `tests/fixtures/<case>`, from the copy with fake credentials resolved.
pub fn fixture(case: &str) -> PathBuf {
    fixtures_root().join(case)
}

pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

/// Runs the binary with `home` as --home and --root, `cwd` as --path, the
/// given extra args, and an environment made only of `env`.
pub fn run_in(home: &Path, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = assert_cmd::Command::new(bin_path());
    cmd.env_clear()
        .env("HELDKEYS_NO_NET", "1")
        .arg("--home")
        .arg(home)
        .arg("--root")
        .arg(home)
        .arg("--path")
        .arg(cwd)
        .args(args)
        .current_dir(cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("binary runs");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// `run_in` with the fixture as home, root and working directory.
pub fn run(case: &str, args: &[&str]) -> Output {
    let dir = fixture(case);
    run_in(&dir, &dir, args, &[])
}

/// Fake secrets placed in the fixtures, listed explicitly so the redaction
/// test also covers values that do not contain the word FAKE. Here and in
/// the other tests, fake tokens are split with concat! after their public
/// prefix, so secret scanners run on this repository do not flag test data.
pub const FIXTURE_SECRETS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "ASIAFAKEFAKEFAKE0002",
    "FAKEtempSECRETkeyFAKEtempSECRETkey0002",
    "FwoGZXIvYXdzEFAKEFAKEFAKEFAKESESSION0002",
    "FAKEssoACCESStokenFAKEssoACCESStoken0003",
    "FAKEprocARG0023",
    "FAKEclientSECRET0004",
    "1//FAKEFAKErefreshTOKENfakeFAKE0004",
    "FAKEazureACCESStoken0005",
    "FAKEazureREFRESHtoken0005",
    "FAKEazureSPsecret0005XYZ",
    concat!(
        "eyJhbGciOiJGQUtFIn0.",
        "eyJzdWIiOiJGQUtFRkFLRUZBS0UifQ.FAKEkubeSIGNATURE0006"
    ),
    "RkFLRS1DTElFTlQtS0VZLURBVEEtMDAwNg==",
    "ZmFrZXVzZXI6RkFLRWRvY2tlclBBU1MwMDA3",
    "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000008",
    "FAKEftpPASSWORD0008",
    "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000009",
    "FAKEgitPASSWORD0009",
    concat!("npm_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0010"),
    "pypi-FAKEFAKEFAKEFAKEFAKE0011",
    "cioFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12",
    "gho_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000013",
    concat!(
        "eyJhbGciOiJGQUtFIn0.",
        "eyJzdWIiOiJGQUtFU0EwMDE0In0.FAKEsaSIGNATURE0014"
    ),
    concat!("sk-", "proj-FAKEFAKEFAKEFAKEFAKEFAKE0015"),
    "FAKEdbPASSWORD0015",
    concat!("sk_", "test_FAKEFAKEFAKEFAKE0016"),
    concat!("xoxb-", "0000000000-FAKEFAKEFAKE0017"),
    "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000018",
    "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000019",
    "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000020",
];

/// Fake secrets passed through the environment.
pub const ENV_SECRETS: &[(&str, &str)] = &[
    ("GITHUB_TOKEN", "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000101"),
    (
        "ANTHROPIC_API_KEY",
        concat!("sk-", "ant-api03-FAKEFAKEFAKEFAKEFAKE-0102"),
    ),
    ("MY_SERVICE_PASSWORD", "FAKEservicePASSWORD0103"),
    ("AWS_ACCESS_KEY_ID", concat!("AKIA", "FAKEFAKEFAKE0104")),
    ("AWS_SECRET_ACCESS_KEY", "FAKEawsSECRETfromENVfakeFAKE0104"),
    (
        "DATABASE_URL",
        "mysql://root:FAKErootPASS0105@127.0.0.1/app",
    ),
];

/// Unencrypted fake OpenSSH key. Never committed as a file (secret scanners
/// flag the header even on fakes); tests write it to a temporary home.
pub const FAKE_SSH_KEY: &str = concat!(
    "-----BEGIN OPENSSH ",
    "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABFAKEsshKEYbody0201\nFAKEsshKEYbodyFAKEsshKEYbody0201\n-----END OPENSSH PRIVATE KEY-----\n"
);
pub const FAKE_SSH_KEY_BODY: &[&str] = &[
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABFAKEsshKEYbody0201",
    "FAKEsshKEYbodyFAKEsshKEYbody0201",
];

/// Copies a fixture directory tree into `dest`.
pub fn copy_dir(src: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dest.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}
