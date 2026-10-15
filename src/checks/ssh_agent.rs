//! `ssh-agent`: SSH keys the agent can use without a passphrase.
//!
//! Two ways in:
//! - keys loaded in the running ssh-agent (`$SSH_AUTH_SOCK`): any process
//!   with the socket can sign with them, for example to `git push` over SSH;
//! - private key files in `~/.ssh` that have no passphrase.
//!
//! We list loaded keys with `ssh-add -l`, which prints public key
//! fingerprints only. For key files we read just the PEM header and, for the
//! OpenSSH format, the first few bytes of the body that say whether a cipher
//! is used. Key material is never decoded, stored or printed.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;
use crate::redact;

pub struct SshAgentCheck;

const ID: &str = "ssh-agent";

const LOADED_KEY: Rule = Rule {
    check: ID,
    id: "HK-SSH-001",
    summary: "SSH key loaded in the running ssh-agent",
};

const UNENCRYPTED_KEY: Rule = Rule {
    check: ID,
    id: "HK-SSH-002",
    summary: "SSH private key file without a passphrase",
};

const RULES: &[Rule] = &[LOADED_KEY, UNENCRYPTED_KEY];

/// `ssh-add -l` should answer instantly; do not let a stuck agent stall the scan.
const SSH_ADD_TIMEOUT: Duration = Duration::from_secs(2);

/// Base64 of `"openssh-key-v1\0"` + `cipher "none"` + `kdf "non..."`: the
/// first 30 bytes of every unencrypted OpenSSH private key. An encrypted key
/// names a real cipher here (`aes256-ctr`, kdf `bcrypt`), so its body starts
/// differently. Comparing the encoded prefix avoids decoding key material.
const OPENSSH_UNENCRYPTED_PREFIX: &str = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9u";

impl Check for SshAgentCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Keys loaded in the running ssh-agent (ssh-add -l, fingerprints only) and private keys in ~/.ssh without a passphrase."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = loaded_keys(ctx);
        findings.extend(unencrypted_key_files(ctx));
        findings
    }
}

/// Keys in the ssh-agent reachable through `SSH_AUTH_SOCK` from `ctx.env`.
fn loaded_keys(ctx: &Context) -> Vec<Finding> {
    let Some(sock) = ctx.var("SSH_AUTH_SOCK") else {
        return Vec::new();
    };
    let Some(output) = run_ssh_add(ctx, sock) else {
        return Vec::new();
    };
    parse_ssh_add(&output)
        .into_iter()
        .map(|key| {
            Finding::new(
                LOADED_KEY,
                "SSH key loaded in ssh-agent",
                format!("ssh-agent: {}", key.comment),
                Severity::Medium,
                Lifetime::LongLived,
                Access::Unknown,
                "Load keys with ssh-add -c (confirm each use) or -t (time limit), or do not forward the agent socket into the sandbox.",
            )
            .with_fingerprint(redact::shorten(key.hash))
            .with_detail(format!("{} {} bits", key.kind, key.bits))
        })
        .collect()
}

/// Runs `ssh-add -l` against `sock` only, with an otherwise empty environment,
/// so the result depends on the context and not on our own process.
fn run_ssh_add(ctx: &Context, sock: &str) -> Option<String> {
    let mut command = Command::new("ssh-add");
    command
        .arg("-l")
        .env_clear()
        .env("SSH_AUTH_SOCK", sock)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(path) = ctx.var("PATH") {
        command.env("PATH", path);
    }
    let mut child = command.spawn().ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < SSH_ADD_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    Some(out)
}

/// One line of `ssh-add -l`.
#[derive(Debug, PartialEq, Eq)]
struct LoadedKey<'a> {
    bits: &'a str,
    /// The hash without its "SHA256:" label.
    hash: &'a str,
    comment: &'a str,
    kind: &'a str,
}

/// Parses `256 SHA256:abc... user@host (ED25519)` lines. Anything else
/// ("The agent has no identities.", errors) yields nothing.
fn parse_ssh_add(output: &str) -> Vec<LoadedKey<'_>> {
    output
        .lines()
        .filter_map(|line| {
            let (bits, rest) = line.trim().split_once(' ')?;
            if !bits.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let (fingerprint, rest) = rest.split_once(' ').unwrap_or((rest, ""));
            let hash = fingerprint
                .split_once(':')
                .map(|(_, h)| h)
                .unwrap_or(fingerprint);
            let (comment, kind) = match rest.rfind(" (") {
                Some(i) if rest.ends_with(')') => (&rest[..i], &rest[i + 2..rest.len() - 1]),
                _ => (rest, "unknown type"),
            };
            Some(LoadedKey {
                bits,
                hash,
                comment: if comment.is_empty() {
                    "(no comment)"
                } else {
                    comment
                },
                kind,
            })
        })
        .collect()
}

/// Bytes read from the start of a key file. The PEM header is under 40
/// bytes, a legacy key's `Proc-Type` line follows it, and the OpenSSH
/// cipher name sits in the first 60 characters of the body; 256 bytes leave
/// room for a CRLF file without loading the key itself.
const HEAD_BYTES: u64 = 256;

/// The key file names ssh and ssh-keygen use by default.
const DEFAULT_KEYS: &[&str] = &[
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_dsa",
    "identity",
];

/// Private key files in `~/.ssh` with no passphrase.
///
/// A key file that is there but cannot be read (no permission, or a FIFO in
/// place of a default key name) is recorded for `read-errors`, so `--strict`
/// does not pass over it. Other odd entries (ControlMaster sockets,
/// directories) are skipped quietly.
fn unencrypted_key_files(ctx: &Context) -> Vec<Finding> {
    let dir = ctx.home_path(".ssh");
    if let Err(e) = std::fs::read_dir(&dir)
        && e.kind() != std::io::ErrorKind::NotFound
        && dir.is_dir()
    {
        ctx.note_unreadable(&dir, e.kind());
    }
    let mut paths = fsutil::list_dir(&dir);
    paths.extend(DEFAULT_KEYS.iter().map(|name| dir.join(name)));
    paths.sort();
    paths.dedup();
    let mut findings = Vec::new();
    for path in paths.iter().filter(|p| is_candidate(p)) {
        // Only the first HEAD_BYTES: the header line and the start of the
        // body that names the cipher. The rest of the key is never read.
        let head = match ctx.try_read_head(path, HEAD_BYTES) {
            Ok(Some(head)) => head,
            Ok(None) => continue,
            Err(fsutil::Unreadable::NotAFile)
                if !DEFAULT_KEYS.contains(&fsutil::file_name(path).as_str()) =>
            {
                continue;
            }
            Err(reason) => {
                ctx.note_unreadable(path, reason);
                continue;
            }
        };
        if is_unencrypted_private_key(&head) {
            findings.push(Finding::new(
                UNENCRYPTED_KEY,
                "SSH private key without a passphrase",
                ctx.display_path(path),
                Severity::High,
                Lifetime::LongLived,
                Access::Unknown,
                "Add a passphrase (ssh-keygen -p -f <file>) and load it into ssh-agent with a time limit, or use a hardware-backed key.",
            ));
        }
    }
    findings
}

/// Skips files that are never private keys.
fn is_candidate(path: &Path) -> bool {
    let name = fsutil::file_name(path);
    let skip = name.ends_with(".pub")
        || name.starts_with("known_hosts")
        || name.starts_with("authorized_keys")
        || name == "config"
        || name == "environment";
    !skip
}

/// Looks only at the PEM header line and, for OpenSSH keys, the encoded
/// prefix that names the cipher.
fn is_unencrypted_private_key(head: &str) -> bool {
    let mut lines = head.lines().map(str::trim);
    let Some(header) = lines.find(|l| l.starts_with("-----BEGIN ")) else {
        return false;
    };
    match header {
        "-----BEGIN OPENSSH PRIVATE KEY-----" => {
            let body: String = lines
                .take_while(|l| !l.starts_with("-----END"))
                .flat_map(|l| l.chars())
                .take(OPENSSH_UNENCRYPTED_PREFIX.len())
                .collect();
            body == OPENSSH_UNENCRYPTED_PREFIX
        }
        // PKCS#8: encrypted keys use a different header.
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" => false,
        "-----BEGIN PRIVATE KEY-----" => true,
        // Legacy PEM (RSA, DSA, EC): encryption is announced in a header line.
        h if h.ends_with(" PRIVATE KEY-----") => !head.contains("Proc-Type: 4,ENCRYPTED"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, write};

    /// Fake key bodies: only the start matters, the rest is filler.
    pub const FAKE_UNENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABFAKEFAKEFAKE\nFAKEFAKEFAKEFAKEFAKEFAKE\n-----END OPENSSH PRIVATE KEY-----\n";
    pub const FAKE_ENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0FAKEFAKEFAKE\n-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn detects_encryption() {
        assert!(is_unencrypted_private_key(FAKE_UNENCRYPTED));
        assert!(!is_unencrypted_private_key(FAKE_ENCRYPTED));
        assert!(is_unencrypted_private_key(
            "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n"
        ));
        assert!(!is_unencrypted_private_key(
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nFAKE\n"
        ));
        assert!(!is_unencrypted_private_key(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nFAKE\n"
        ));
        assert!(!is_unencrypted_private_key(
            "ssh-ed25519 AAAAC3Nza fake@host\n"
        ));
    }

    #[test]
    fn finds_key_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".ssh/id_ed25519", FAKE_UNENCRYPTED);
        write(
            dir.path(),
            ".ssh/id_ed25519.pub",
            "ssh-ed25519 AAAA fake@host\n",
        );
        write(dir.path(), ".ssh/id_work", FAKE_ENCRYPTED);
        write(dir.path(), ".ssh/config", "Host *\n");
        let f = SshAgentCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].location, "~/.ssh/id_ed25519");
        assert_eq!(f[0].fingerprint, None);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[cfg(unix)]
    #[test]
    fn key_files_that_cannot_be_read_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".ssh/sockets")).unwrap();
        for name in ["id_rsa", "cm-socket"] {
            let status = std::process::Command::new("mkfifo")
                .arg(dir.path().join(".ssh").join(name))
                .status()
                .unwrap();
            assert!(status.success());
        }
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(SshAgentCheck.run(&ctx).is_empty());
        // The default key name is recorded; the other FIFO and the
        // directory are what ~/.ssh normally holds besides keys.
        let unreadable = ctx.take_unreadable();
        assert_eq!(unreadable.len(), 1, "{unreadable:?}");
        assert!(unreadable[0].0.ends_with(".ssh/id_rsa"));
    }

    #[test]
    fn parses_ssh_add_output() {
        let out = "256 SHA256:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE123 me@laptop (ED25519)\n3072 SHA256:OTHERFAKEOTHERFAKEOTHERFAKEOTHERFAKE456 /home/me/.ssh/id_rsa (RSA)\n";
        let keys = parse_ssh_add(out);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].comment, "me@laptop");
        assert_eq!(keys[0].kind, "ED25519");
        assert_eq!(keys[1].bits, "3072");
        assert!(parse_ssh_add("The agent has no identities.\n").is_empty());
    }

    #[test]
    fn no_socket_means_no_agent_lookup() {
        let dir = tempfile::tempdir().unwrap();
        assert!(loaded_keys(&ctx_with_env(dir.path(), &[])).is_empty());
    }
}
