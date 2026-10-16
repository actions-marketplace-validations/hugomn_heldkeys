//! Markdown output, for PR comments and `$GITHUB_STEP_SUMMARY`.
//!
//! Layout: a heading with the verdict; the summary the text output leads
//! with (credentials to fix first, where they are, secrets found in several
//! places, next steps); then every finding: a count per severity, one table
//! per severity, and the details of each finding (with its own fix) folded
//! in a `<details>` block. Only `Finding` fields are used; they are already
//! single lines without control characters or secrets (see `Report::new`).
//!
//! The text itself can still come from a pull request (a workflow's job id
//! or `uses:` value), so every value is written as inert Markdown: plain text
//! through `escape`, which leaves no link, image, HTML or @mention syntax,
//! and paths and commands through `code`, a code span that is copied as is.
//!
//! Findings an ignore rule or the baseline left out get an "Ignored"
//! section: the counts, every ignore rule that matched with its reason and
//! file (so a reviewer sees an ignore a pull request added), warnings about
//! where the rules came from, and the findings themselves in a `<details>`
//! block.
//!
//! Size: a PR comment holds 65,536 characters and a job summary 1 MiB. If the
//! full report does not fit in `MAX_CHARS`, the details are dropped first, then
//! table rows are capped, with a note pointing to the JSON or SARIF report.

use crate::finding::{Finding, Severity};
use crate::report::{Report, digest};

/// Under GitHub's PR comment limit (65,536), with room for a bot's header.
const MAX_CHARS: usize = 60_000;

/// Where each rule's documentation page lives.
pub const RULE_DOCS: &str = "https://github.com/hugomn/heldkeys/blob/main/docs/rules";

pub fn render(report: &Report) -> Result<String, String> {
    // Most complete first; fall back to shorter layouts until it fits.
    let attempts = [
        (None, true),
        (None, false),
        (Some(50), false),
        (Some(10), false),
    ];
    let mut out = String::new();
    for (max_rows, details) in attempts {
        out = render_with(report, max_rows, details);
        if out.chars().count() <= MAX_CHARS {
            break;
        }
    }
    Ok(out)
}

fn render_with(report: &Report, max_rows: Option<usize>, details: bool) -> String {
    let summary = report.summary();
    let mut out = format!(
        "## {} {}\n\n**{}**\n\n",
        crate::TOOL_NAME,
        report.mode.as_str(),
        escape(&summary.line(), Place::Inline)
    );
    notices(&mut out, report);
    if report.findings.is_empty() {
        out.push_str("No findings.\n");
        ignored(&mut out, report, max_rows, details);
        out.push_str(&footer());
        return out;
    }

    summary_sections(&mut out, report);

    out.push_str("### All findings\n\n");
    out.push_str("| Severity | Findings |\n| --- | ---: |\n");
    for (severity, count) in [
        (Severity::High, summary.high),
        (Severity::Medium, summary.medium),
        (Severity::Low, summary.low),
        (Severity::Info, summary.info),
    ] {
        out.push_str(&format!("| {} | {count} |\n", label(severity)));
    }
    out.push('\n');

    let mut hidden = 0;
    for severity in Severity::ALL {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect();
        if group.is_empty() {
            continue;
        }
        let shown = max_rows.map_or(group.len(), |m| m.min(group.len()));
        hidden += group.len() - shown;
        out.push_str(&format!("### {} ({})\n\n", label(severity), group.len()));
        out.push_str("| Rule | Finding | Location | Fingerprint | Lifetime | Access |\n");
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for f in &group[..shown] {
            out.push_str(&format!(
                "| [{rule}]({RULE_DOCS}/{rule}.md) | {} | {} | {} | {} | {} |\n",
                escape(&f.title, Place::Cell),
                code(&f.location, Place::Cell),
                f.fingerprint
                    .as_deref()
                    .map(|fp| code(fp, Place::Cell))
                    .unwrap_or_default(),
                f.lifetime.as_str(),
                f.access.as_str(),
                rule = f.rule,
            ));
        }
        out.push('\n');
        if details {
            out.push_str(&format!(
                "<details><summary>Details ({})</summary>\n\n",
                group.len()
            ));
            for f in &group {
                out.push_str(&format!(
                    "- **{}** at {}",
                    escape(&f.title, Place::Inline),
                    code(&f.location, Place::Inline)
                ));
                if let Some(d) = &f.detail {
                    out.push_str(&format!(": {}", escape(d, Place::Inline)));
                }
                out.push_str(&format!(". Fix: {}\n", escape(&f.fix, Place::Inline)));
            }
            out.push_str("\n</details>\n\n");
        }
    }
    if hidden > 0 {
        out.push_str(&format!(
            "_{hidden} more finding(s) not shown to keep this under GitHub's size limit; see the JSON or SARIF report._\n\n"
        ));
    }

    ignored(&mut out, report, max_rows, details);
    out.push_str(&footer());
    out
}

/// Warnings about where ignore rules came from, right under the verdict.
fn notices(out: &mut String, report: &Report) {
    for notice in &report.suppression.notices {
        out.push_str(&format!(
            "> **Warning:** {}\n\n",
            escape(notice, Place::Inline)
        ));
    }
}

/// The "Ignored" section (see the module documentation). `max_rows` caps
/// the listed findings like the tables; `details` folds them in.
fn ignored(out: &mut String, report: &Report, max_rows: Option<usize>, details: bool) {
    let s = &report.suppression;
    if report.suppressed.is_empty() && s.expired.is_empty() {
        return;
    }
    out.push_str(&format!("### Ignored ({})\n\n", report.suppressed.len()));
    if let Some(line) = crate::report::text::ignored_counts(report) {
        out.push_str(&format!("{}.\n\n", escape(&line, Place::Inline)));
    }
    if !s.hits.is_empty() {
        out.push_str("| Rule | Path or location | Findings | Reason | File | Expires |\n");
        out.push_str("| --- | --- | ---: | --- | --- | --- |\n");
        for hit in &s.hits {
            let ig = &hit.ignore;
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                code(&ig.rule, Place::Cell),
                [ig.path.as_deref(), ig.location.as_deref()]
                    .into_iter()
                    .flatten()
                    .map(|p| code(p, Place::Cell))
                    .collect::<Vec<_>>()
                    .join(" "),
                hit.findings,
                escape(&ig.reason, Place::Cell),
                code(&ig.source, Place::Cell),
                ig.expires.map(|d| d.to_string()).unwrap_or_default(),
            ));
        }
        out.push('\n');
    }
    for ig in &s.expired {
        out.push_str(&format!(
            "- Expired on {}, no longer applied: {} in {}\n",
            ig.expires.map(|d| d.to_string()).unwrap_or_default(),
            code(&ig.rule, Place::Inline),
            code(&ig.source, Place::Inline),
        ));
    }
    if !s.expired.is_empty() {
        out.push('\n');
    }
    if report.suppressed.is_empty() || !details {
        return;
    }
    let shown = max_rows.map_or(report.suppressed.len(), |m| m.min(report.suppressed.len()));
    out.push_str(&format!(
        "<details><summary>Ignored findings ({})</summary>\n\n",
        report.suppressed.len()
    ));
    for sup in &report.suppressed[..shown] {
        let f = &sup.finding;
        out.push_str(&format!(
            "- {} **{}** at {}",
            label(f.severity),
            escape(&f.title, Place::Inline),
            code(&f.location, Place::Inline)
        ));
        if let Some(fp) = &f.fingerprint {
            out.push_str(&format!(" {}", code(fp, Place::Inline)));
        }
        out.push_str(&format!(
            " ({}): {}\n",
            code(f.rule, Place::Inline),
            escape(&sup.reason, Place::Inline)
        ));
    }
    if shown < report.suppressed.len() {
        out.push_str(&format!(
            "- _{} more; see the JSON report._\n",
            report.suppressed.len() - shown
        ));
    }
    out.push_str("\n</details>\n\n");
}

/// The summary the text output leads with (see `digest`): the credentials
/// to fix first, where the findings are, secrets found in several places
/// and the next steps.
fn summary_sections(out: &mut String, report: &Report) {
    let d = digest::digest(report);
    if d.secrets.is_empty() {
        return;
    }
    out.push_str("### Fix these first\n\n");
    out.push_str("| Severity | Credential | Location | Fingerprint | Places |\n");
    out.push_str("| --- | --- | --- | --- | ---: |\n");
    for secret in d.top() {
        let f = secret.first();
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            label(f.severity),
            escape(&f.title, Place::Cell),
            code(&f.location, Place::Cell),
            f.fingerprint
                .as_deref()
                .map(|fp| code(fp, Place::Cell))
                .unwrap_or_default(),
            secret.places.len(),
        ));
    }
    out.push('\n');

    out.push_str("### Where they are\n\n");
    out.push_str("| Where | High | Medium | Low |\n| --- | ---: | ---: | ---: |\n");
    for row in &d.categories {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            escape(row.category.label(), Place::Cell),
            row.high,
            row.medium,
            row.low
        ));
    }
    out.push('\n');

    let shared = d.shared();
    if !shared.is_empty() {
        out.push_str("### Same secret in several places\n\n");
        const MAX_SHARED: usize = 20;
        for secret in shared.iter().take(MAX_SHARED) {
            let f = secret.first();
            let (file, inside) = digest::split_location(&f.location);
            let id = match &f.fingerprint {
                Some(fp) => code(fp, Place::Inline),
                None => code(&inside, Place::Inline),
            };
            let n = secret.places.len();
            let unit = if secret.only_in_files() {
                digest::plural(secret.files(), "file", "files")
            } else {
                digest::plural(n, "place", "places")
            };
            out.push_str(&format!(
                "- {} {id} in {unit} ({}, +{})\n",
                escape(&f.title, Place::Inline),
                code(file.unwrap_or(&f.location), Place::Inline),
                n - 1
            ));
        }
        if shared.len() > MAX_SHARED {
            out.push_str(&format!(
                "- _{} more; every finding is listed below._\n",
                shared.len() - MAX_SHARED
            ));
        }
        out.push('\n');
    }

    if !d.steps.is_empty() {
        out.push_str("### Next steps\n\n");
        for (i, step) in d.steps.iter().enumerate() {
            out.push_str(&format!("{}. {}\n", i + 1, escape(step, Place::Inline)));
        }
        out.push('\n');
    }
}

fn footer() -> String {
    format!(
        "\n<sub>{} {}: read-only, never prints a secret. Fingerprints show at most 4 + 3 characters.</sub>\n",
        crate::TOOL_NAME,
        crate::TOOL_VERSION
    )
}

fn label(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

/// Where a value is written. In a table cell a `|` must be escaped even
/// inside a code span (GFM splits cells first); anywhere else that escape
/// would show up as a stray backslash in a code span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    Cell,
    Inline,
}

/// Characters with a meaning in GitHub Markdown that are written with a
/// backslash: links and images (`[`, `]`, `(`, `)`, `!`), emphasis (`*`,
/// `_`, `~`), code (`` ` ``), headings and issue links (`#`), and the
/// backslash itself so it cannot cancel one of these escapes.
const MARKDOWN_PUNCTUATION: &[char] = &['\\', '[', ']', '(', ')', '!', '*', '_', '~', '`', '#'];

/// Plain text in a table cell or list item. Values can come from files the
/// scan read (workflow YAML), so nothing in them may become a link, an image,
/// HTML, emphasis, a table column or a notification:
///
/// - `&`, `<` and `>` become entities (no HTML, no `<url>` autolinks);
/// - Markdown punctuation and `|` get a backslash;
/// - a word with an `@` (a would-be @mention, an e-mail address, or a fix
///   such as `owner/action@<sha>`) becomes a code span, which GitHub never
///   turns into a mention and which copies exactly as written;
/// - so does a word with a URL in it (`://` or `www.`): GitHub turns bare
///   URLs into links, and the only links in the report are its own rule
///   pages.
fn escape(s: &str, place: Place) -> String {
    let s = s.replace('\r', "").replace('\n', " ");
    let mut out = String::with_capacity(s.len());
    for (i, word) in s.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if word.contains('@') || is_link(word) {
            out.push_str(&code(word, place));
            continue;
        }
        for c in word.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '|' => out.push_str("\\|"),
                c if MARKDOWN_PUNCTUATION.contains(&c) => {
                    out.push('\\');
                    out.push(c);
                }
                c => out.push(c),
            }
        }
    }
    out
}

/// A word GitHub would turn into a link: a URL (`scheme://`, including
/// `http`, `https` and `ftp`) or an extended `www.` autolink.
fn is_link(word: &str) -> bool {
    word.contains("://") || word.to_ascii_lowercase().contains("www.")
}

/// A code span. Markdown does not interpret HTML, links or mentions inside
/// it, and what the reader copies is the text itself. The fence is one
/// backtick longer than the longest run of backticks in `s`, so nothing in
/// `s` can close it early; line breaks would end the table row, so `\r` is
/// dropped and `\n` becomes a space.
fn code(s: &str, place: Place) -> String {
    let mut s = s.replace('\r', "").replace('\n', " ");
    if s.is_empty() {
        return String::new();
    }
    if place == Place::Cell {
        s = s.replace('|', "\\|");
    }
    let longest_run = s.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest_run + 1);
    // A span that starts or ends with a backtick needs a space inside the
    // fence; CommonMark strips one space from each side again.
    let pad = s.starts_with('`') || s.ends_with('`') || (s.starts_with(' ') && s.ends_with(' '));
    let pad = if pad { " " } else { "" };
    format!("{fence}{pad}{s}{pad}{fence}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime, TEST_RULE};
    use crate::report::Mode;

    fn finding(severity: Severity, title: &str) -> Finding {
        Finding::new(
            TEST_RULE,
            title,
            "~/.aws/credentials [default]",
            severity,
            Lifetime::LongLived,
            Access::Write,
            "Rotate it.",
        )
    }

    #[test]
    fn empty_report() {
        let out = render(&Report::new(Mode::Ci, vec![])).unwrap();
        assert!(out.starts_with(
            "## heldkeys ci\n\n**No AI agent workflow risks and no credentials reachable in this job.**"
        ));
        assert!(out.contains("No findings."));
    }

    #[test]
    fn tables_details_and_fixes() {
        let f = finding(Severity::High, "Long-lived <AWS> key | x")
            .with_fingerprint(Some("AKIA…PLE".to_string()))
            .with_detail("profile default");
        let out = render(&Report::new(Mode::Scan, vec![f])).unwrap();
        assert!(out.contains("| High | 1 |"), "{out}");
        assert!(out.contains("### High (1)"));
        assert!(out.contains(
            "| [HK-TEST-001](https://github.com/hugomn/heldkeys/blob/main/docs/rules/HK-TEST-001.md) | Long-lived &lt;AWS&gt; key \\| x | `~/.aws/credentials [default]` | `AKIA…PLE` | long-lived | write access |"
        ), "{out}");
        assert!(out.contains("<details><summary>Details (1)</summary>"));
        assert!(out.contains(": profile default. Fix: Rotate it.\n"));
        assert!(out.contains("### Next steps\n\n1. Rotate it.\n"), "{out}");
        let summary = out.find("### Fix these first").unwrap();
        assert!(summary < out.find("### High (1)").unwrap());
        assert!(out.contains("| High | Long-lived &lt;AWS&gt; key \\| x | `~/.aws/credentials [default]` | `AKIA…PLE` | 1 |"), "{out}");
    }

    #[test]
    fn escape_neutralises_markdown_and_html() {
        assert_eq!(
            escape(
                "[x](https://evil) ![i](https://evil/p) <a href=x>",
                Place::Inline
            ),
            "`[x](https://evil)` `![i](https://evil/p)` &lt;a href=x&gt;"
        );
        assert_eq!(
            escape("[x](y) ![i](z)", Place::Inline),
            "\\[x\\]\\(y\\) \\!\\[i\\]\\(z\\)"
        );
        assert_eq!(
            escape("*b* _i_ ~s~ `c` #1", Place::Inline),
            "\\*b\\* \\_i\\_ \\~s\\~ \\`c\\` \\#1"
        );
        // A backslash cannot cancel the escape that follows it.
        assert_eq!(escape("\\[x]", Place::Inline), "\\\\\\[x\\]");
        assert_eq!(escape("a | b\r\nc", Place::Cell), "a \\| b c");
    }

    #[test]
    fn words_with_an_at_sign_become_code_spans() {
        // Copy-pastable: no zero-width characters anywhere.
        assert_eq!(
            escape("Pin owner/action@<sha> and ping @octocat", Place::Inline),
            "Pin `owner/action@<sha>` and ping `@octocat`"
        );
        assert!(!escape("a@b", Place::Inline).contains('\u{200b}'));
        assert_eq!(escape("x|y@z", Place::Cell), "`x\\|y@z`");
        assert_eq!(escape("x|y@z", Place::Inline), "`x|y@z`");
    }

    #[test]
    fn urls_become_code_spans() {
        assert_eq!(
            escape("see https://evil.example/fix now", Place::Inline),
            "see `https://evil.example/fix` now"
        );
        assert_eq!(
            escape(
                "[Fix](https://evil.example/x) www.evil.example",
                Place::Cell
            ),
            "`[Fix](https://evil.example/x)` `www.evil.example`"
        );
        assert_eq!(escape("ftp://h/x", Place::Inline), "`ftp://h/x`");
    }

    /// Nothing from a finding becomes a clickable link: every `http` outside
    /// a code span is one of our rule-page links.
    #[test]
    fn only_rule_pages_are_links() {
        let f = finding(Severity::Medium, "Agent at https://evil.example/a").with_detail(
            "uses: owner/x@main [Fix guide](https://evil.example/fix) www.evil.example",
        );
        let mut f = f;
        f.location = ".github/workflows/x.yml jobs.https://evil.example/job".to_string();
        f.fix = "Read http://evil.example/fix first.".to_string();
        let out = render(&Report::new(Mode::Ci, vec![f])).unwrap();
        assert_only_rule_links(&out);
    }

    /// Fails if any `http`/`www.` outside a code span is not a rule page.
    fn assert_only_rule_links(markdown: &str) {
        let mut outside = String::new();
        let mut rest = markdown;
        while let Some(start) = rest.find('`') {
            outside.push_str(&rest[..start]);
            let fence_len = rest[start..].chars().take_while(|&c| c == '`').count();
            let fence = &rest[start..start + fence_len];
            let after = &rest[start + fence_len..];
            match after.find(fence) {
                Some(end) => rest = &after[end + fence_len..],
                None => {
                    rest = after;
                }
            }
        }
        outside.push_str(rest);
        let cleaned = outside.replace(&format!("({RULE_DOCS}/"), "(RULE_DOCS/");
        for needle in ["http", "www."] {
            assert!(
                !cleaned.to_ascii_lowercase().contains(needle),
                "{needle} outside a code span:\n{markdown}"
            );
        }
    }

    #[test]
    fn code_spans_cannot_be_closed_early() {
        assert_eq!(code("a`b", Place::Inline), "``a`b``");
        assert_eq!(code("``x", Place::Inline), "``` ``x ```");
        assert_eq!(code("a\r\nb", Place::Inline), "`a b`");
        assert_eq!(code("", Place::Inline), "");
    }

    #[test]
    fn large_reports_are_cut_to_fit() {
        let findings: Vec<Finding> = (0..2000)
            .map(|i| {
                finding(
                    Severity::Medium,
                    &format!("Finding number {i} with a long title"),
                )
            })
            .collect();
        let out = render(&Report::new(Mode::Ci, findings)).unwrap();
        assert!(out.chars().count() <= MAX_CHARS, "{}", out.len());
        assert!(!out.contains("<details>"));
        assert!(out.contains("more finding(s) not shown"));
    }
}
