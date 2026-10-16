//! `.heldkeys.toml`: ignore rules, so a team can keep heldkeys in CI and
//! fail only on new risks.
//!
//! The format is deliberately tiny:
//!
//! ```toml
//! [[ignore]]
//! rule = "HK-WF-005"                     # required: a rule id, or a prefix ending in * ("HK-WF-*")
//! path = ".github/workflows/claude.yml"  # optional: glob on the finding's file (* and ?)
//! location = "env: GITHUB_TOKEN"         # optional: the finding's whole location, exactly
//! reason = "pinned via Renovate"         # required, not empty
//! expires = "2027-01-31"                 # optional: after this day the ignore stops applying
//! ```
//!
//! `path` is only ever matched against the file a finding is in (relative
//! to the scanned directory, without a line number), never against the rest
//! of its location. The rest is text the scanned repository chooses (a job
//! id, a `uses:` value, a variable name), and a glob over it would let a pull
//! request name its new job `fixtures-bot` to fall under `path = "*fixtures*"`.
//! Findings without a file (an environment variable) can only be targeted
//! with `location`, compared exactly.
//!
//! Parsing is strict on purpose. A typo in a key (`rule` spelled `rules`)
//! must not turn into an ignore that silently matches nothing, or worse,
//! everything, so unknown keys, wrong types, a missing `reason` and a rule
//! pattern that would hide every finding (`*`, `HK-*`) without a `path`
//! that names something, or a `location`, are errors, and `main` exits 2.
//!
//! The file can come from the repository under review (a pull request can
//! add an ignore), so every string in it is made inert (`sanitize`), scrubbed
//! (`redact::scrub`) and clipped before it is stored, exactly like text read
//! from any other scanned file.
//!
//! We use the `toml` crate rather than `toml_subset`: that reader skips
//! `[[array.tables]]` and lines it does not understand, which is right for
//! classifying someone else's config and wrong for our own, where a skipped
//! line would be a silently dropped (or silently widened) ignore.

use std::path::Path;

use crate::fsutil;
use crate::redact;
use crate::sanitize::{clip, sanitize};

/// The project config, looked up in the scanned directory.
pub const PROJECT_FILE: &str = ".heldkeys.toml";
/// The user config, under `~/.config` (or `$XDG_CONFIG_HOME`), for local scans.
pub const USER_FILE: &str = "heldkeys/config.toml";

/// Keys an `[[ignore]]` table may have.
const IGNORE_KEYS: &[&str] = &["rule", "path", "location", "reason", "expires"];

/// Longest `path` glob accepted, in characters.
const MAX_GLOB: usize = 512;

/// A calendar day, for `expires`. Compared as (year, month, day).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl Date {
    /// `YYYY-MM-DD`, with a real month and a day that exists in it.
    pub fn parse(text: &str) -> Option<Date> {
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }
        let digits = |range: std::ops::Range<usize>| -> Option<u32> {
            let part = &text[range];
            if part.bytes().all(|b| b.is_ascii_digit()) {
                part.parse().ok()
            } else {
                None
            }
        };
        let date = Date {
            year: digits(0..4)? as u16,
            month: digits(5..7)? as u8,
            day: digits(8..10)? as u8,
        };
        date.is_valid().then_some(date)
    }

    fn is_valid(self) -> bool {
        let leap = (self.year.is_multiple_of(4) && !self.year.is_multiple_of(100))
            || self.year.is_multiple_of(400);
        let days = match self.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return false,
        };
        self.year > 0 && self.day >= 1 && self.day <= days
    }

    /// Today in UTC, from the system clock. No time zone database: an ignore
    /// expiring a few hours early or late does not matter.
    pub fn today() -> Date {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Date::from_days_since_epoch((secs / 86_400) as i64)
    }

    /// The civil date `days` after 1970-01-01 (Howard Hinnant's algorithm).
    fn from_days_since_epoch(days: i64) -> Date {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        Date {
            year: year.clamp(1, 9999) as u16,
            month: month as u8,
            day: day as u8,
        }
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// One `[[ignore]]` entry. Every string is already inert and scrubbed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignore {
    /// A rule id (`HK-WF-005`) or a prefix ending in `*` (`HK-WF-*`).
    pub rule: String,
    /// Glob on the finding's file, without a leading `./`.
    pub path: Option<String>,
    /// The finding's whole normalised location, compared exactly, without a
    /// leading `./`.
    pub location: Option<String>,
    pub reason: String,
    pub expires: Option<Date>,
    /// The file it came from, as shown to the reader (`./.heldkeys.toml`).
    pub source: String,
}

impl Ignore {
    /// Whether this ignore covers a finding with this rule id, in this file
    /// (`suppress::finding_file`: relative to the scanned directory, without
    /// a line number; `None` when the finding is not in a file), at this
    /// normalised location (`suppress::normalise_location`).
    pub fn matches(&self, rule: &str, file: Option<&str>, location: &str) -> bool {
        let rule_ok = match self.rule.strip_suffix('*') {
            Some(prefix) => rule.starts_with(prefix),
            None => rule == self.rule,
        };
        if !rule_ok {
            return false;
        }
        if let Some(pattern) = &self.path {
            match file {
                Some(file) if glob_match(pattern, strip_dot_slash(file)) => {}
                _ => return false,
            }
        }
        if let Some(exact) = &self.location
            && strip_dot_slash(location) != exact
        {
            return false;
        }
        true
    }

    /// True once `today` is past `expires`; the ignore then no longer applies.
    pub fn is_expired(&self, today: Date) -> bool {
        self.expires.is_some_and(|day| today > day)
    }
}

/// `./x` as `x`.
fn strip_dot_slash(s: &str) -> &str {
    s.strip_prefix("./").unwrap_or(s)
}

/// Shell-style matching of the whole `text`: `*` is any run of characters
/// (including `/`), `?` is any one character, everything else is literal.
/// Iterative with a single backtrack point, so it takes at most
/// `pattern × text` steps whatever the input.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    // Where the last `*` was, and the text position it is matched up to.
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || (p[pi] != '*' && p[pi] == t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// Reads and parses a config file. `Ok(None)` when it does not exist.
///
/// `within`: for the project file, the scanned directory; a symlink that
/// leads out of it is refused, as for every other project file. Any file
/// that exists but cannot be read is an error, never skipped: a gate that
/// quietly ran without its ignores (or with someone else's) is worse than
/// one that stops.
pub fn load(
    path: &Path,
    shown: &str,
    within: Option<&Path>,
) -> Result<Option<Vec<Ignore>>, String> {
    let read = match within {
        Some(root) => fsutil::try_read_text_within(root, path, fsutil::MAX_FILE_BYTES),
        None => fsutil::try_read_text(path, fsutil::MAX_FILE_BYTES),
    };
    match read {
        Ok(Some(text)) => parse(&text, shown).map(Some),
        Ok(None) => Ok(None),
        Err(reason) => Err(format!("cannot read {shown}: {reason}")),
    }
}

/// Parses the text of a config file. `source` names it in errors and in
/// each `Ignore`.
pub fn parse(text: &str, source: &str) -> Result<Vec<Ignore>, String> {
    let source = clean(source);
    let table: toml::Table = toml::from_str(text).map_err(|e| {
        let line = e
            .span()
            .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1);
        let message = clean(e.message().lines().next().unwrap_or("invalid TOML"));
        match line {
            Some(n) => format!("{source}: line {n}: {message}"),
            None => format!("{source}: {message}"),
        }
    })?;
    let mut ignores = Vec::new();
    for (key, value) in &table {
        if key != "ignore" {
            return Err(format!(
                "{source}: unknown key `{}`; the only top-level key is `ignore` (written [[ignore]])",
                clean(key)
            ));
        }
        let Some(entries) = value.as_array() else {
            return Err(format!(
                "{source}: `ignore` must be a list of tables, written [[ignore]]"
            ));
        };
        for (i, entry) in entries.iter().enumerate() {
            let at = format!("{source}: ignore #{}", i + 1);
            let Some(entry) = entry.as_table() else {
                return Err(format!("{at}: must be a table, written [[ignore]]"));
            };
            ignores.push(ignore(entry, &at, &source)?);
        }
    }
    Ok(ignores)
}

/// One `[[ignore]]` table, validated.
fn ignore(entry: &toml::Table, at: &str, source: &str) -> Result<Ignore, String> {
    if let Some(key) = entry.keys().find(|k| !IGNORE_KEYS.contains(&k.as_str())) {
        return Err(format!(
            "{at}: unknown key `{}`; expected rule, path, location, reason or expires",
            clean(key)
        ));
    }
    let text = |key: &str| -> Result<Option<String>, String> {
        match entry.get(key) {
            None => Ok(None),
            Some(toml::Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("{at}: `{key}` must be a string")),
        }
    };

    let rule = text("rule")?.ok_or_else(|| format!("{at}: `rule` is required"))?;
    let path = match text("path")? {
        Some(p) if p.trim().is_empty() => return Err(format!("{at}: `path` is empty")),
        Some(p) if p.chars().count() > MAX_GLOB => {
            return Err(format!("{at}: `path` is longer than {MAX_GLOB} characters"));
        }
        Some(p) => Some(clean(strip_dot_slash(p.trim()))),
        None => None,
    };
    let location = match text("location")? {
        Some(l) if l.trim().is_empty() => return Err(format!("{at}: `location` is empty")),
        Some(l) if l.chars().count() > MAX_GLOB => {
            return Err(format!(
                "{at}: `location` is longer than {MAX_GLOB} characters"
            ));
        }
        // Pasted from a report: drop a line number, as findings are compared without one.
        Some(l) => Some(clean(strip_dot_slash(
            &crate::suppress::normalise_location(l.trim(), None),
        ))),
        None => None,
    };
    check_rule(&rule, path.as_deref(), location.is_some()).map_err(|e| format!("{at}: {e}"))?;
    let reason = text("reason")?
        .filter(|r| !r.trim().is_empty())
        .ok_or_else(|| {
            format!("{at}: `reason` is required and must not be empty; say why this is accepted")
        })?;
    let expires = match entry.get("expires") {
        None => None,
        Some(toml::Value::String(s)) => Some(Date::parse(s.trim()).ok_or_else(|| {
            format!("{at}: `expires` must be a date written YYYY-MM-DD, such as \"2027-01-31\"")
        })?),
        // `expires = 2027-01-31` without quotes is a TOML local date.
        Some(toml::Value::Datetime(dt)) if dt.time.is_none() && dt.offset.is_none() => {
            let d = dt.date.expect("a datetime without time has a date");
            let date = Date {
                year: d.year,
                month: d.month,
                day: d.day,
            };
            Some(date)
        }
        Some(_) => {
            return Err(format!(
                "{at}: `expires` must be a date written YYYY-MM-DD, such as \"2027-01-31\""
            ));
        }
    };
    Ok(Ignore {
        rule,
        path,
        location,
        reason: clean(reason.trim()),
        expires,
        source: source.to_string(),
    })
}

/// A rule pattern: an id made of `[A-Za-z0-9._-]`, optionally ending in one
/// `*`. A pattern that matches every rule (`*`, `H*`, `HK*`, `HK-*`) is only
/// allowed together with a `location`, or a `path` that names something
/// (not only `*`, `?` and `/`), so a single entry cannot switch heldkeys off
/// for a whole repository.
fn check_rule(rule: &str, path: Option<&str>, has_location: bool) -> Result<(), String> {
    let prefix = rule.strip_suffix('*').unwrap_or(rule);
    let valid = !rule.is_empty()
        && rule.len() <= 64
        && prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid {
        return Err(format!(
            "`rule` must be a rule id such as \"HK-WF-005\" or a prefix ending in * such as \"HK-WF-*\", not \"{}\"",
            clean(rule)
        ));
    }
    let matches_everything = rule.ends_with('*')
        && matches!(
            prefix.to_ascii_uppercase().as_str(),
            "" | "H" | "HK" | "HK-"
        );
    let path_names_something =
        path.is_some_and(|p| p.chars().any(|c| !matches!(c, '*' | '?' | '/')));
    if matches_everything && !path_names_something && !has_location {
        return Err(format!(
            "`rule = \"{rule}\"` would ignore every finding; name a rule or a prefix such as \"HK-WF-*\", or add a `path` that names files (not only * and ?) or a `location`"
        ));
    }
    Ok(())
}

/// Text from a config file as it may be shown: one inert line, no secrets,
/// at most `clip`'s length.
fn clean(s: &str) -> String {
    clip(&redact::scrub(&sanitize(s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str) -> Result<Ignore, String> {
        let mut all = parse(text, ".heldkeys.toml")?;
        assert_eq!(all.len(), 1);
        Ok(all.remove(0))
    }

    #[test]
    fn a_full_entry() {
        let i = one(
            "# comment\n[[ignore]]\nrule = \"HK-WF-005\"\npath = \"./.github/workflows/claude.yml\"\nreason = \"pinned via Renovate\"\nexpires = \"2027-01-31\"\n",
        )
        .unwrap();
        assert_eq!(i.rule, "HK-WF-005");
        assert_eq!(i.path.as_deref(), Some(".github/workflows/claude.yml"));
        assert_eq!(i.reason, "pinned via Renovate");
        assert_eq!(i.expires, Date::parse("2027-01-31"));
        assert_eq!(i.source, ".heldkeys.toml");
    }

    #[test]
    fn an_empty_file_has_no_ignores() {
        assert_eq!(parse("", "x").unwrap(), vec![]);
        assert_eq!(parse("# nothing yet\n", "x").unwrap(), vec![]);
    }

    #[test]
    fn unquoted_dates_are_accepted() {
        let i = one("[[ignore]]\nrule = \"HK-WF-005\"\nreason = \"r\"\nexpires = 2027-01-31\n")
            .unwrap();
        assert_eq!(i.expires.unwrap().to_string(), "2027-01-31");
    }

    #[test]
    fn errors_are_clear() {
        let err = |text: &str| one(text).unwrap_err();
        assert_eq!(
            err("[[ignore]]\nrule = \"HK-WF-005\"\nreasn = \"typo\"\n"),
            ".heldkeys.toml: ignore #1: unknown key `reasn`; expected rule, path, location, reason or expires"
        );
        assert_eq!(
            err("[[ignores]]\nrule = \"HK-WF-005\"\nreason = \"r\"\n"),
            ".heldkeys.toml: unknown key `ignores`; the only top-level key is `ignore` (written [[ignore]])"
        );
        assert!(err("[[ignore]]\nrule = \"HK-WF-005\"\n").contains("`reason` is required"));
        assert!(
            err("[[ignore]]\nrule = \"HK-WF-005\"\nreason = \"  \"\n")
                .contains("`reason` is required")
        );
        assert!(err("[[ignore]]\nreason = \"r\"\n").contains("`rule` is required"));
        assert!(err("[[ignore]]\nrule = 5\nreason = \"r\"\n").contains("`rule` must be a string"));
        assert!(
            err("[[ignore]]\nrule = \"HK-WF-005\"\nreason = \"r\"\nexpires = \"next year\"\n")
                .contains("YYYY-MM-DD")
        );
        assert!(
            err("[[ignore]]\nrule = \"HK-WF-005\"\nreason = \"r\"\nexpires = \"2027-02-30\"\n")
                .contains("YYYY-MM-DD")
        );
        assert!(err("[ignore]\nrule = \"HK-WF-005\"\nreason = \"r\"\n").contains("list of tables"));
        let syntax = err("[[ignore]]\nrule = \"HK-WF-005\nreason = \"r\"\n");
        assert!(syntax.starts_with(".heldkeys.toml: line 2: "), "{syntax}");
    }

    #[test]
    fn broad_patterns_need_a_path_that_names_something() {
        for rule in ["*", "HK-*", "hk-*", "HK*", "H*"] {
            let text = format!("[[ignore]]\nrule = \"{rule}\"\nreason = \"r\"\n");
            let e = one(&text).unwrap_err();
            assert!(e.contains("would ignore every finding"), "{rule}: {e}");
            // A path made only of wildcards is no narrower.
            for path in ["*", "**", "*/*", "?*", "/*/"] {
                let wide = format!("{text}path = \"{path}\"\n");
                let e = one(&wide).unwrap_err();
                assert!(
                    e.contains("would ignore every finding"),
                    "{rule} {path}: {e}"
                );
            }
            assert!(
                one(&format!("{text}path = \"vendor/*\"\n")).is_ok(),
                "{rule}"
            );
            assert!(
                one(&format!("{text}location = \"env: X\"\n")).is_ok(),
                "{rule}"
            );
        }
        assert!(one("[[ignore]]\nrule = \"HK-WF-*\"\nreason = \"r\"\n").is_ok());
        assert!(one("[[ignore]]\nrule = \"HK-WF-*\"\npath = \"*\"\nreason = \"r\"\n").is_ok());
        for rule in ["HK-WF-*-x", "HK WF", "HK-*-*", "**", "HK-[WF]"] {
            let text = format!("[[ignore]]\nrule = \"{rule}\"\nreason = \"r\"\npath = \"x\"\n");
            assert!(
                one(&text).unwrap_err().contains("must be a rule id"),
                "{rule}"
            );
        }
    }

    #[test]
    fn location_is_normalised_and_checked() {
        let i = one("[[ignore]]\nrule = \"HK-WF-005\"\nlocation = \"./.github/workflows/a.yml:12 jobs.a\"\nreason = \"r\"\n").unwrap();
        assert_eq!(
            i.location.as_deref(),
            Some(".github/workflows/a.yml jobs.a")
        );
        assert!(
            one("[[ignore]]\nrule = \"HK-WF-005\"\nlocation = \" \"\nreason = \"r\"\n")
                .unwrap_err()
                .contains("`location` is empty")
        );
    }

    #[test]
    fn hostile_strings_are_made_inert() {
        let i = one(
            "[[ignore]]\nrule = \"HK-WF-005\"\npath = \"a\\u001b[2Jb\"\nreason = \"ok\\r\\n::error::boom https://u:FAKEpw0001@example.com ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000123\"\n",
        )
        .unwrap();
        assert_eq!(i.path.as_deref(), Some("a?[2Jb"));
        assert!(!i.reason.contains('\r') && !i.reason.contains('\n'));
        assert!(!i.reason.contains("FAKEpw0001"), "{}", i.reason);
        assert!(!i.reason.contains("FAKEFAKEFAKEFAKEFAKE"), "{}", i.reason);
        let e =
            one("[[ignore]]\nrule = \"HK-WF-005\"\n\"bad\\u001b]0;x\\u0007\" = 1\n").unwrap_err();
        assert!(!e.contains('\u{1b}') && !e.contains('\u{7}'), "{e:?}");
    }

    fn ignore(rule: &str, path: Option<&str>, location: Option<&str>) -> Ignore {
        Ignore {
            rule: rule.to_string(),
            path: path.map(str::to_string),
            location: location.map(str::to_string),
            reason: "r".to_string(),
            expires: None,
            source: "x".to_string(),
        }
    }

    #[test]
    fn matching() {
        let wf = ".github/workflows/claude.yml jobs.x.steps[0] (uses: a/b@v1)";
        let file = Some(".github/workflows/claude.yml");
        assert!(ignore("HK-WF-005", None, None).matches("HK-WF-005", file, wf));
        assert!(!ignore("HK-WF-005", None, None).matches("HK-WF-0050", file, wf));
        assert!(ignore("HK-WF-*", None, None).matches("HK-WF-001", file, wf));
        assert!(!ignore("HK-WF-*", None, None).matches("HK-ENV-001", file, wf));
        let path = |p: &str| ignore("HK-WF-*", Some(p), None);
        assert!(path(".github/workflows/claude.yml").matches("HK-WF-001", file, wf));
        assert!(path(".github/workflows/*.yml").matches("HK-WF-001", file, wf));
        assert!(!path(".github/workflows/other.yml").matches("HK-WF-001", file, wf));
        let dotenv = |p: &str| ignore("HK-DOTENV-*", Some(p), None);
        assert!(dotenv("tests/fixtures/*").matches(
            "HK-DOTENV-001",
            Some("./tests/fixtures/a/.env"),
            "./tests/fixtures/a/.env: KEY"
        ));
        assert!(dotenv(".env").matches("HK-DOTENV-001", Some(".env"), ".env: KEY"));
        assert!(!dotenv(".env").matches("HK-DOTENV-001", Some("a/.env"), "a/.env: KEY"));
        assert!(ignore("HK-REPO-001", Some("src/config.?y"), None).matches(
            "HK-REPO-001",
            Some("src/config.py"),
            "src/config.py"
        ));
        // A finding without a file never matches a path.
        assert!(!ignore("HK-CI-*", Some("*"), None).matches(
            "HK-CI-002",
            None,
            "env: GITHUB_TOKEN"
        ));
        let env = ignore("HK-CI-*", None, Some("env: GITHUB_TOKEN"));
        assert!(env.matches("HK-CI-002", None, "env: GITHUB_TOKEN"));
        assert!(!env.matches("HK-CI-002", None, "env: GITHUB_TOKEN_2"));
    }

    /// `path` sees the file name only: text the repository picks, such as a
    /// job id, cannot make a finding fall under a path pattern.
    #[test]
    fn path_never_matches_the_rest_of_the_location() {
        let fixtures = ignore("HK-*", Some("*fixtures*"), None);
        let loc =
            ".github/workflows/bot.yml jobs.fixtures-bot.steps[0] (uses: openai/codex-action@v1)";
        assert!(!fixtures.matches("HK-WF-001", Some(".github/workflows/bot.yml"), loc));
        assert!(fixtures.matches(
            "HK-DOTENV-001",
            Some("tests/fixtures/.env"),
            "tests/fixtures/.env: K"
        ));
        assert!(!fixtures.matches("HK-DOTENV-001", Some(".env"), ".env: FIXTURES_TOKEN"));
    }

    #[test]
    fn glob() {
        assert!(glob_match("*", ""));
        assert!(glob_match("a*c", "abbbc"));
        assert!(glob_match("a*b*c", "a/x/b/y/c"));
        assert!(!glob_match("a*c", "abcd"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("**", "anything/at/all"));
        // No exponential blow-up on patterns made of stars.
        let text = "a".repeat(5000);
        assert!(!glob_match(&format!("{}b", "*a".repeat(200)), &text));
    }

    #[test]
    fn expiry() {
        let mut i =
            one("[[ignore]]\nrule = \"HK-WF-005\"\nreason = \"r\"\nexpires = \"2027-01-31\"\n")
                .unwrap();
        assert!(!i.is_expired(Date::parse("2027-01-31").unwrap()));
        assert!(i.is_expired(Date::parse("2027-02-01").unwrap()));
        i.expires = None;
        assert!(!i.is_expired(Date::parse("9999-12-31").unwrap()));
    }

    #[test]
    fn dates() {
        assert_eq!(Date::from_days_since_epoch(0).to_string(), "1970-01-01");
        assert_eq!(
            Date::from_days_since_epoch(19_782).to_string(),
            "2024-02-29"
        );
        assert_eq!(
            Date::from_days_since_epoch(20_742).to_string(),
            "2026-10-16"
        );
        assert!(Date::parse("2024-02-29").is_some());
        assert!(Date::parse("2023-02-29").is_none());
        assert!(Date::parse("2027-1-31").is_none());
        assert!(Date::parse("2027-13-01").is_none());
        assert!(Date::parse("+027-01-01").is_none());
        assert!(Date::today() > Date::parse("2026-01-01").unwrap());
    }
}
