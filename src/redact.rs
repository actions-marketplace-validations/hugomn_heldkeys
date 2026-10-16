//! Turning a secret into something safe to print.
//!
//! This is the only place that decides how much of a value may be shown.
//! The rule: at most the first 4 and the last 3 characters, joined by an
//! ellipsis, and only when
//!
//! - the value matches a known token format, whose prefix is public anyway, and
//! - at least `MIN_HIDDEN` characters stay hidden after the public prefix and
//!   the shown characters, so a fingerprint never gives away a large part of
//!   the random part of a short token.
//!
//! Anything else (passwords, refresh tokens of unknown shape, short values)
//! gets no fingerprint at all, because the ends of an arbitrary secret are
//! part of the secret.
//!
//! `scrub` is the second half: it removes secrets that ended up inside text
//! meant for display (a URL with a password in a location, a token in a
//! command line quoted in a detail). `Report::new` runs it over every finding.

use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::rules;

/// Characters shown at the start of a fingerprint.
const LEADING: usize = 4;
/// Characters shown at the end of a fingerprint.
const TRAILING: usize = 3;
/// Shortest value we will shorten. With 16 characters at least 9 stay hidden,
/// and real tokens are much longer (AWS key ids are 20, GitHub tokens 40).
const MIN_LEN: usize = 16;
/// Fewest characters of a token's non-public part that a fingerprint must
/// leave hidden. A 16-character Slack token (`xoxb-` plus 11) would show 3 of
/// its 11 random characters, so it gets no fingerprint.
const MIN_HIDDEN: usize = 12;
/// The joiner between the leading and trailing parts.
pub const ELLIPSIS: char = '…';
/// What `scrub` puts in place of a secret that has no fingerprint.
pub const MASK: &str = "***";

/// Fingerprint for a secret value, or `None` if it is of an unknown format
/// or too short to keep `MIN_HIDDEN` characters hidden.
pub fn fingerprint(value: &str) -> Option<String> {
    let value = rules::trim_value(value);
    match rules::match_token(value) {
        Some(rule) if rule.fingerprintable => {
            let public = public_prefix_len(rule.pattern).max(LEADING);
            if value.chars().count() < public + TRAILING + MIN_HIDDEN {
                return None;
            }
            shorten(value)
        }
        _ => None,
    }
}

/// How many characters at the start of a token are fixed by its format, read
/// from the rule's pattern: literal characters (`ghp_`, `sk-ant-`, `\.`),
/// one-character classes without a quantifier (the `b` of `xox[abposr]-`)
/// and groups of same-length literal alternatives (`shp(at|ca|pa|ss)_`).
/// It stops at the first repeated or variable part.
fn public_prefix_len(pattern: &str) -> usize {
    let chars: Vec<char> = pattern.chars().collect();
    let literal = |c: char| c.is_ascii_alphanumeric() || "_-:/".contains(c);
    let mut i = 0;
    let mut len = 0;
    while i < chars.len() {
        let (width, next) = match chars[i] {
            '\\' if chars.get(i + 1).is_some_and(|c| c.is_ascii_punctuation()) => (1, i + 2),
            '[' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != ']' {
                    j += if chars[j] == '\\' { 2 } else { 1 };
                }
                if j >= chars.len() {
                    break;
                }
                (1, j + 1)
            }
            '(' => {
                let Some(close) = chars[i..].iter().position(|&c| c == ')') else {
                    break;
                };
                let inner: String = chars[i + 1..i + close].iter().collect();
                let alternatives: Vec<&str> = inner.split('|').collect();
                let width = alternatives[0].chars().count();
                if width == 0
                    || !alternatives
                        .iter()
                        .all(|a| a.chars().count() == width && a.chars().all(literal))
                {
                    break;
                }
                (width, i + close + 1)
            }
            c if literal(c) => (1, i + 1),
            _ => break,
        };
        if chars
            .get(next)
            .is_some_and(|c| matches!(c, '{' | '*' | '+' | '?'))
        {
            break;
        }
        len += width;
        i = next;
    }
    len
}

/// Shortens any value to `first4…last3`. Only for values that are not
/// secrets in themselves but are long (an SSH public key hash, a key id).
/// Returns `None` if the value is too short to shorten meaningfully.
pub fn shorten(value: &str) -> Option<String> {
    let chars: Vec<char> = value.trim().chars().collect();
    if chars.len() < MIN_LEN {
        return None;
    }
    let head: String = chars[..LEADING].iter().collect();
    let tail: String = chars[chars.len() - TRAILING..].iter().collect();
    Some(format!("{head}{ELLIPSIS}{tail}"))
}

/// True if `s` has the fingerprint shape: at most 4 + ellipsis + 3 characters.
/// Used by tests and as a guard in reports.
pub fn is_safe_fingerprint(s: &str) -> bool {
    match s.split_once(ELLIPSIS) {
        Some((head, tail)) => head.chars().count() <= LEADING && tail.chars().count() <= TRAILING,
        None => false,
    }
}

/// Where a URL's user information sits in a text: `start..end`, from just
/// after the `//` to the `@` that closes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Userinfo {
    pub start: usize,
    pub end: usize,
    /// `user:password` (or `user%3Apassword`) rather than a user name alone.
    pub password: bool,
}

/// Every URL user information in `text`, after `scheme://` or a bare `//`
/// (`.npmrc` keys). Passwords are not always percent-encoded, so:
///
/// - with an `@` before the first `/`, `?` or `#`, the user information
///   ends there, unless it has a password, which then runs to the last `@`
///   before whitespace, a quote or the end (`u:p@ss/w@rd@host`);
/// - with no `@` there, a colon that does not start a port means a password
///   holding `/`, `?` or `#` (`user:pa/ss@host`), which also runs to the
///   last `@`.
///
/// `%3A` counts as the colon. Over-reaching into a path that happens to
/// hold an `@` is the safe direction: more is hidden, never less.
///
/// Linear in the length of `text`: every `//` of a run (`a//b//c...`) shares
/// the run's end and its last `@`, which are found once per run, and the
/// authority each `//` reads stops at the next `/`.
pub fn find_userinfo(text: &str) -> Vec<Userinfo> {
    let mut out = Vec::new();
    let mut from = 0;
    // The run the last `//` was in: where it ends, and its last `@`.
    let mut run_end = 0;
    let mut last_at: Option<usize> = None;
    while let Some(found) = text[from..].find("//") {
        let start = from + found + 2;
        if start > run_end {
            run_end = text[start..]
                .find(ends_run)
                .map_or(text.len(), |len| start + len);
            last_at = text[start..run_end].rfind('@').map(|at| start + at);
        }
        let run = &text[start..run_end];
        let last = last_at.filter(|&at| at >= start).map(|at| at - start);
        match userinfo_end(run, last) {
            Some((at, password)) => {
                out.push(Userinfo {
                    start,
                    end: start + at,
                    password,
                });
                from = start + at + 1;
            }
            None => from = start,
        }
    }
    out
}

/// Where a URL ends in running text.
fn ends_run(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>')
}

/// In `run`, what follows a `//`: the index of the `@` that ends the user
/// information, and whether it has a password. `last_at` is the index of
/// the last `@` in `run`, found by the caller once for the whole run.
fn userinfo_end(run: &str, last_at: Option<usize>) -> Option<(usize, bool)> {
    let authority = &run[..run.find(['/', '?', '#']).unwrap_or(run.len())];
    if let Some(at) = authority.rfind('@') {
        if at == 0 {
            return None;
        }
        let password = colon(&authority[..at]).is_some();
        let end = if password { last_at.unwrap_or(at) } else { at };
        return Some((end, password));
    }
    // An IPv6 literal's colons are not a password separator.
    let after_ip = match authority.strip_prefix('[') {
        Some(rest) => &rest[rest.find(']')? + 1..],
        None => authority,
    };
    let (i, width) = colon(after_ip)?;
    let port = &after_ip[i + width..];
    if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((last_at?, true))
}

/// The first `:` or `%3A` in `s`: its index and length.
fn colon(s: &str) -> Option<(usize, usize)> {
    let plain = s.find(':').map(|i| (i, 1));
    let encoded = s.to_ascii_lowercase().find("%3a").map(|i| (i, 3));
    match (plain, encoded) {
        (Some(a), Some(b)) => Some(if a.0 < b.0 { a } else { b }),
        (a, b) => a.or(b),
    }
}

/// `%3A` and `%40` decoded, so `user%3Apassword@host` and
/// `user%40corp:password@host` are seen for what they are. For checking a
/// value, never for text that is shown: `scrub` leaves `%3A` and `%40` alone
/// and reads `%3A` as a colon where it looks for user information.
pub fn decode_separators(text: &str) -> std::borrow::Cow<'_, str> {
    static ENCODED: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"%(?i:3a|40)").expect("valid regex"));
    ENCODED.replace_all(text, |c: &Captures| {
        if c[0].eq_ignore_ascii_case("%3a") {
            ":"
        } else {
            "@"
        }
    })
}

/// A complete image digest (`sha256:<64 hex>`) at the start of `rest`, so a
/// host named `sha256:abc` cannot hide a password in front of it.
fn is_digest(rest: &str) -> bool {
    [("sha256:", 64), ("sha512:", 128)]
        .iter()
        .any(|(algo, len)| {
            rest.strip_prefix(algo).is_some_and(|hex| {
                hex.len() >= *len
                    && hex[..*len].chars().all(|c| c.is_ascii_hexdigit())
                    && !hex[*len..].starts_with(|c: char| c.is_ascii_alphanumeric())
            })
        })
}

/// `//user:password` cut off before its `@` (a quoted command line that was
/// shortened). A port is digits, so a non-digit after the colon (before the
/// first `/`, `?` or `#`) means the URL had user information.
static CUT_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"//[^/\s@:?#\[\]"'<>]*?(?::|%3[Aa])([^\s@"'<>`]*)"#).expect("valid regex")
});

/// `user:password@host` (or `user%3Apassword@host`) without a scheme, only
/// where it cannot be anything else: it starts the text or follows a
/// separator, and the host is a domain name (so `image:tag@sha256:...` is
/// left alone). `mailto:` and the like are a scheme, not a user: see
/// `ADDRESS_SCHEMES`.
static BARE_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(^|[\s"'(<\[{=,;])([A-Za-z0-9._%+~\-]+?)(?::|%3[Aa])[^\s/@:]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})"#,
    )
    .expect("valid regex")
});

/// Schemes followed by `address@host` with no `//`: `mailto:a@b.com` is an
/// address, not a user `mailto` with the password `a`.
const ADDRESS_SCHEMES: &[&str] = &["mailto", "xmpp", "sip", "sips", "im", "pres"];

/// A URL query or fragment parameter: its name and value. `scrub` masks the
/// value when the name says it holds a secret (`is_secret_param`).
static QUERY_PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([?&;#]([A-Za-z0-9_.\-]+)=)[^&\s#]+").expect("valid regex"));

/// Last words of a parameter name that hold a secret.
const SECRET_PARAM_WORDS: &[&str] = &[
    "key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "signature",
    "sig",
    "credential",
    "credentials",
    "code",
];

/// A parameter name that says it holds a secret: one of
/// `SECRET_PARAM_WORDS` on its own (`token`, `code`), or as the last word
/// after `_`, `.` or `-` (`api_key`, `access_token`, `X-Amz-Signature`) or
/// in camelCase (`accessToken`, `apiKey`). `token_count`, `monkey` and
/// `zipcode` are not.
fn is_secret_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_PARAM_WORDS.iter().any(|word| {
        let Some(prefix) = lower.strip_suffix(word) else {
            return false;
        };
        let Some(before) = prefix.chars().last() else {
            return true;
        };
        let camel = name[prefix.len()..].starts_with(|c: char| c.is_ascii_uppercase())
            && !before.is_ascii_uppercase();
        matches!(before, '_' | '.' | '-') || camel
    })
}

/// An `Authorization:` header (or `authorization=`), with or without its
/// scheme.
static AUTH_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(\b(?:proxy-)?authorization\s*[:=]\s*)(?:((?:bearer|basic|token|digest|negotiate|bot)\s+))?([^\s"'<>,;]+)"#,
    )
    .expect("valid regex")
});

/// `Bearer <value>` anywhere.
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(\bbearer\s+)([^\s"'<>,;]+)"#).expect("valid regex"));

/// A command-line flag that takes a secret: `--password x`, `--api-key=x`,
/// `--github-token x`, `--client-secret=x`.
static SECRET_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(--(?:[a-z0-9]+-)*(?:password|passwd|pass|token|api-key|apikey|secret|access-key)(?:=|\s+))([^\s"'<>]+)"#,
    )
    .expect("valid regex")
});

/// A value that only names a secret (`${TOKEN}`, `<token>`, `***`).
fn is_placeholder(value: &str) -> bool {
    value.starts_with(['$', '<', '{', '*', '-']) || value == MASK
}

/// A word that looks like a credential rather than prose: long, or with a
/// digit in it.
fn looks_secret(value: &str) -> bool {
    let n = value.chars().count();
    !is_placeholder(value) && (n >= 20 || (n >= 8 && value.chars().any(|c| c.is_ascii_digit())))
}

/// Removes secrets from text meant for display:
///
/// - the user information of a URL becomes `***@` (see `find_userinfo`), so
///   `https://alice:pw@host/` shows as `https://***@host/`; an image
///   reference with a complete digest (`name:tag@sha256:<64 hex>`) is kept,
///   and a URL cut off inside its password (`https://user:pa`) becomes
///   `https://***`; `%3A` counts as the colon, and the text keeps its
///   `%3A` and `%40` everywhere else;
/// - the value of a query or fragment parameter named like a secret, of an
///   `Authorization` header, of `Bearer`, and of a `--password`, `--token`,
///   `--api-key` or `--secret` flag becomes `***`;
/// - every known token (`rules::find_tokens`) becomes its fingerprint, or
///   `***` when it may not have one.
///
/// This is defence in depth. Checks are expected not to put secrets in their
/// text in the first place; this catches what slips through.
pub fn scrub(text: &str) -> String {
    let mut masked = String::with_capacity(text.len());
    let mut last = 0;
    for u in find_userinfo(text) {
        let user = &text[u.start..u.end];
        let hide = u.password || (user.chars().count() >= 20 && !user.contains(['?', '#']));
        // `name@sha256:...` is an image digest. With a colon in front
        // (`name:tag@sha256:...`) only a complete digest proves it.
        let rest = &text[u.end + 1..];
        let digest = if u.password {
            is_digest(rest)
        } else {
            rest.starts_with("sha256:") || rest.starts_with("sha512:")
        };
        if !hide || digest {
            continue;
        }
        masked.push_str(&text[last..u.start]);
        masked.push_str(MASK);
        last = u.end;
    }
    masked.push_str(&text[last..]);
    let text = masked;
    let text = CUT_USERINFO.replace_all(&text, |c: &Captures| {
        let m = c.get(0).expect("whole match");
        let password = &c[1];
        let port = &password[..password.find(['/', '?', '#']).unwrap_or(password.len())];
        // An `@` here is an image digest kept by the step above.
        if port.chars().all(|ch| ch.is_ascii_digit()) || text[m.end()..].starts_with('@') {
            m.as_str().to_string()
        } else {
            format!("//{MASK}")
        }
    });
    let text = BARE_USERINFO.replace_all(&text, |c: &Captures| {
        if ADDRESS_SCHEMES.iter().any(|s| c[2].eq_ignore_ascii_case(s)) {
            c[0].to_string()
        } else {
            format!("{}{MASK}@{}", &c[1], &c[3])
        }
    });
    let text = QUERY_PARAM.replace_all(&text, |c: &Captures| {
        if is_secret_param(&c[2]) {
            format!("{}{MASK}", &c[1])
        } else {
            c[0].to_string()
        }
    });
    let text = AUTH_HEADER.replace_all(&text, |c: &Captures| {
        let scheme = c.get(2).map_or("", |m| m.as_str());
        let value = &c[3];
        let hide = if scheme.is_empty() {
            looks_secret(value)
        } else {
            !is_placeholder(value)
        };
        if hide {
            format!("{}{scheme}{MASK}", &c[1])
        } else {
            c[0].to_string()
        }
    });
    let text = BEARER.replace_all(&text, |c: &Captures| {
        if looks_secret(&c[2]) {
            format!("{}{MASK}", &c[1])
        } else {
            c[0].to_string()
        }
    });
    let text = SECRET_FLAG.replace_all(&text, |c: &Captures| {
        if is_placeholder(&c[2]) {
            c[0].to_string()
        } else {
            format!("{}{MASK}", &c[1])
        }
    });
    let tokens = rules::find_tokens(&text);
    if tokens.is_empty() {
        return text.into_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    // URLs with a password were handled above; what is left of that rule's
    // matches is an image digest such as `docker://alpine:3@sha256:...`.
    for t in tokens
        .into_iter()
        .filter(|t| t.rule.id != "url-with-password")
    {
        out.push_str(&text[last..t.start]);
        let token = &text[t.start..t.end];
        match fingerprint(token).filter(|fp| is_safe_fingerprint(fp)) {
            Some(fp) => out.push_str(&fp),
            None => out.push_str(MASK),
        }
        last = t.end;
    }
    out.push_str(&text[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_token_gets_4_plus_3() {
        assert_eq!(
            fingerprint("ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000123").as_deref(),
            Some("ghp_…123")
        );
        assert_eq!(
            fingerprint(concat!("AKIA", "IOSFODNN7EXAMPLE")).as_deref(),
            Some("AKIA…PLE")
        );
    }

    #[test]
    fn unknown_format_gets_nothing() {
        assert_eq!(fingerprint(concat!("q8Zr1v", "Lx0pTn4Wm2abcdefgh")), None);
        assert_eq!(fingerprint("hunter2"), None);
        assert_eq!(fingerprint(""), None);
    }

    #[test]
    fn non_fingerprintable_rules_get_nothing() {
        assert_eq!(fingerprint("postgres://app:fakepass@db.internal/app"), None);
    }

    #[test]
    fn short_tokens_get_nothing() {
        // xoxb- plus 11: only 8 characters would stay hidden.
        assert_eq!(fingerprint(concat!("xoxb-", "FAKE1234567")), None);
        // xoxb- plus 20: 12 stay hidden.
        assert_eq!(
            fingerprint(concat!("xoxb-", "FAKEFAKEFAKE12345678")).as_deref(),
            Some("xoxb…678")
        );
        // sk_live_ plus 16 hides 13; sk-ant- plus 20 hides 13.
        assert!(fingerprint(concat!("sk_", "live_FAKEFAKEFAKE1234")).is_some());
        assert!(fingerprint(concat!("sk-", "ant-FAKEFAKEFAKEFAKE1234")).is_some());
        assert_eq!(fingerprint(concat!("sk-", "ant-FAKEFAKEFAKEFAKE123")), None);
    }

    #[test]
    fn public_prefixes() {
        assert_eq!(public_prefix_len(r"AKIA[0-9A-Z]{16}"), 4);
        assert_eq!(public_prefix_len(r"github_pat_[A-Za-z0-9_]{22,}"), 11);
        assert_eq!(public_prefix_len(r"xox[abposr]-[A-Za-z0-9\-]{10,}"), 5);
        assert_eq!(public_prefix_len(r"do[por]_v1_[a-f0-9]{64}"), 7);
        assert_eq!(public_prefix_len(r"shp(at|ca|pa|ss)_[a-fA-F0-9]{32}"), 6);
        assert_eq!(public_prefix_len(r"SG\.[A-Za-z0-9_\-]{16,}"), 3);
        assert_eq!(
            public_prefix_len(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
            33
        );
        // Every fingerprintable rule has a prefix, and its shortest token
        // keeps MIN_HIDDEN characters hidden or gets no fingerprint.
        for rule in rules::TOKEN_RULES.iter().filter(|r| r.fingerprintable) {
            assert!(public_prefix_len(rule.pattern) >= 2, "{}", rule.id);
        }
    }

    #[test]
    fn scrub_removes_url_userinfo() {
        assert_eq!(
            scrub("helper store for https://alice:FAKEpw0001@github.example.com"),
            "helper store for https://***@github.example.com"
        );
        assert_eq!(
            scrub("~/.npmrc (//eve:FAKEpw0017@registry.example.com/)"),
            "~/.npmrc (//***@registry.example.com/)"
        );
        assert_eq!(
            scrub("git fetch x-access-token:FAKEpw@github.com/o/r"),
            "git fetch ***@github.com/o/r"
        );
        assert_eq!(
            scrub("https://FAKEFAKEtokenFAKEFAKE0001@github.com/o/r"),
            "https://***@github.com/o/r"
        );
        // Cut off before the `@`.
        assert_eq!(
            scrub("run: git fetch https://x-access-token:FAKEcutPW00"),
            "run: git fetch https://***"
        );
    }

    #[test]
    fn scrub_keeps_what_is_not_a_secret() {
        for s in [
            "Pin owner/action@0123456789abcdef",
            "uses: docker://alpine:3.19@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "uses: docker://alpine@sha256:0123abcd",
            "git@github.com:org/repo.git",
            "ssh://git@github.com/org/repo",
            "https://registry.npmjs.org:443/@scope/pkg",
            "http://localhost:3000",
            "http://[::1]:8080/x",
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
            "image:tag@sha256:0123",
            "~/.aws/credentials [default]",
            "env: GITHUB_TOKEN",
            "AKIA…PLE",
        ] {
            assert_eq!(scrub(s), s);
        }
    }

    #[test]
    fn scrub_replaces_tokens_and_secret_query_values() {
        assert_eq!(
            scrub("run: curl -H ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000123 x"),
            "run: curl -H ghp_…123 x"
        );
        assert_eq!(
            scrub(concat!("token xoxb-", "FAKE1234567 here")),
            "token *** here"
        );
        assert_eq!(
            scrub("https://api.example.com/v1?api_key=q8Zr1vLx0pTn&x=1"),
            "https://api.example.com/v1?api_key=***&x=1"
        );
    }

    #[test]
    fn scrub_masks_passwords_with_unencoded_separators() {
        for (input, expected) in [
            (
                "https://user:pa/ssFAKEslash01@host.example.com/x",
                "https://***@host.example.com/x",
            ),
            (
                "https://u:p?w#dFAKEq02@host.example.com",
                "https://***@host.example.com",
            ),
            (
                "https://u:p@wFAKEat03@host.example.com/x",
                "https://***@host.example.com/x",
            ),
            (
                "https://user%3AFAKEpct04@host.example.com",
                "https://***@host.example.com",
            ),
            (
                "https://user%40corp:FAKEpct05@host.example.com",
                "https://***@host.example.com",
            ),
            ("x://u:FAKEdigest06@sha256:abc", "x://***@sha256:abc"),
            (
                "//u:pa/ssFAKEnpm07@registry.example.com/",
                "//***@registry.example.com/",
            ),
            (
                "run: git fetch https://u:cut/FAKEcut08",
                "run: git fetch https://***",
            ),
            (
                "https://u:FAKEv6pw09@[2001:db8::1]:8443/x",
                "https://***@[2001:db8::1]:8443/x",
            ),
        ] {
            assert_eq!(scrub(input), expected, "{input}");
        }
        // A port before a path with an `@` is not a password.
        assert_eq!(
            scrub("https://registry.npmjs.org:443/@scope/pkg"),
            "https://registry.npmjs.org:443/@scope/pkg"
        );
    }

    #[test]
    fn scrub_masks_auth_headers_fragments_and_flags() {
        for (input, expected) in [
            (
                "Authorization: Bearer FAKEbearer10abcdef",
                "Authorization: Bearer ***",
            ),
            (
                "-H 'authorization: basic RkFLRWJhc2ljMTE='",
                "-H 'authorization: basic ***'",
            ),
            ("Authorization: Token FAKEtok12", "Authorization: Token ***"),
            ("curl -H Bearer FAKEbare13xyz x", "curl -H Bearer *** x"),
            (
                "https://h.example.com/#access_token=FAKEfrag14&x=1",
                "https://h.example.com/#access_token=***&x=1",
            ),
            (
                "https://h.example.com/#token=FAKEfrag15",
                "https://h.example.com/#token=***",
            ),
            (
                "https://h.example.com/cb#code=FAKEcode16",
                "https://h.example.com/cb#code=***",
            ),
            (
                "https://h.example.com/a?code=FAKEcode17",
                "https://h.example.com/a?code=***",
            ),
            ("tool --password FAKEflag18 -v", "tool --password *** -v"),
            ("tool --token=FAKEflag19", "tool --token=***"),
            ("tool --api-key FAKEflag20", "tool --api-key ***"),
            ("tool --secret=FAKEflag21", "tool --secret=***"),
            ("tool --github-token FAKEflag22", "tool --github-token ***"),
        ] {
            assert_eq!(scrub(input), expected, "{input}");
        }
        // Prose and placeholders stay.
        for s in [
            "Bearer tokens expire",
            "an AUTHORIZATION value in the header",
            "Authorization: Bearer ${{ secrets.TOKEN }}",
            "tool --token \"$TOKEN\"",
            "tool --token-file /run/token",
            "Pass the token only to the step that needs it",
        ] {
            assert_eq!(scrub(s), s);
        }
    }

    #[test]
    fn scrub_leaves_ordinary_text_alone() {
        for s in [
            "mailto:a@b.com",
            "Write to mailto:security@example.com for help",
            "xmpp:alice@chat.example.com",
            "https://api.example.com/v1?token_count=5&max_tokens=10",
            "https://shop.example.com/?zipcode=12345&monkey=1",
            "https://h.example.com/search?q=a%40b%3Ac",
            "user%40example.com",
            "https://h.example.com/a%3Ab/@scope",
        ] {
            assert_eq!(scrub(s), s);
        }
    }

    #[test]
    fn scrub_masks_secret_named_params_only() {
        for (input, expected) in [
            ("?api_key=FAKEp1&x=1", "?api_key=***&x=1"),
            ("?apikey=FAKEp2", "?apikey=***"),
            ("?apiKey=FAKEp3", "?apiKey=***"),
            ("&accessToken=FAKEp4", "&accessToken=***"),
            ("?X-Amz-Signature=FAKEp5", "?X-Amz-Signature=***"),
            ("?sig=FAKEp6&sv=2024", "?sig=***&sv=2024"),
            ("#id_token=FAKEp7", "#id_token=***"),
            ("?client.secret=FAKEp8", "?client.secret=***"),
            ("?PASSWORD=FAKEp9", "?PASSWORD=***"),
        ] {
            assert_eq!(scrub(input), expected, "{input}");
        }
        for name in [
            "token_count",
            "max_tokens",
            "monkey",
            "zipcode",
            "keyboard",
            "tokens",
        ] {
            assert!(!is_secret_param(name), "{name}");
        }
    }

    #[test]
    fn scrub_reads_encoded_colons_without_decoding_the_text() {
        for (input, expected) in [
            // The masked span is the original text, `%3A` included.
            (
                "see https://user%3AFAKEenc1@host.example.com/a%40b",
                "see https://***@host.example.com/a%40b",
            ),
            (
                "run: git fetch https://u%3AFAKEenc2cut",
                "run: git fetch https://***",
            ),
            (
                "url = user%3AFAKEenc3@host.example.com",
                "url = ***@host.example.com",
            ),
        ] {
            assert_eq!(scrub(input), expected, "{input}");
        }
    }

    #[test]
    fn find_userinfo_in_runs_of_slashes() {
        // A later `//` in the same run is still looked at.
        assert_eq!(
            scrub("x=//foo/https://u:FAKEnest23@host.example.com/"),
            "x=//foo/https://***@host.example.com/"
        );
        assert_eq!(
            find_userinfo("a////b c//u:p@h"),
            vec![Userinfo {
                start: 10,
                end: 13,
                password: true,
            }]
        );
        assert!(find_userinfo(&"/".repeat(1_000)).is_empty());
    }

    #[test]
    fn scrub_is_linear_on_hostile_text() {
        // Each of these was quadratic or worse in `find_userinfo`: every
        // `//` rescanned the whole run to its end.
        let n = 200_000;
        let inputs = [
            format!("uses: openai/codex-action@v1{}", "/".repeat(n)),
            "//a".repeat(n / 3),
            "//a:b".repeat(n / 5),
            format!("//{}", "@/".repeat(n / 2)),
            format!("https://u:p{}", "/@".repeat(n / 2)),
            "//a?".repeat(n / 4),
        ];
        for input in &inputs {
            let started = std::time::Instant::now();
            find_userinfo(input);
            scrub(input);
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_secs(2),
                "{took:?} for {}",
                &input[..40]
            );
        }
    }

    #[test]
    fn shorten_rejects_short_values() {
        assert_eq!(shorten("0123456789abcde"), None);
        assert_eq!(shorten("0123456789abcdef").as_deref(), Some("0123…def"));
    }

    #[test]
    fn shorten_is_unicode_safe() {
        let s = "ééééééééééééééééééé";
        assert!(shorten(s).is_some());
    }

    #[test]
    fn safe_fingerprint_shape() {
        assert!(is_safe_fingerprint("AKIA…PLE"));
        assert!(!is_safe_fingerprint("AKIAI…PLE"));
        assert!(!is_safe_fingerprint(concat!("AKIA", "IOSFODNN7EXAMPLE")));
    }
}
