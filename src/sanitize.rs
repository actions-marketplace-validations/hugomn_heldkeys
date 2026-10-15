//! Making untrusted text safe to print.
//!
//! Much of what a report shows comes from files and processes that someone
//! else controls: workflow YAML in a pull request, an MCP config in a cloned
//! repo, the JSON a container sends back. Printed as is, such text could
//! drive the terminal (escape sequences), hide or reorder what the reader
//! sees (bidi controls), or turn into GitHub Actions workflow commands in a
//! job log (`::error ...`, `::stop-commands::...`).
//!
//! `sanitize` is applied to every string field of every finding in
//! `Report::new`, and to every string `sandbox::remote` reads back from a
//! target, so the renderers can treat their input as one line of plain text.

/// Format characters that are not `char::is_control` but still change how
/// text is laid out: the bidirectional controls, which can make text display
/// in a different order than it is stored ("Trojan Source", CVE-2021-42574),
/// and the Unicode line and paragraph separators.
const LAYOUT_CONTROLS: &[char] = &[
    '\u{061C}', // ARABIC LETTER MARK
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', // embeddings and overrides
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // isolates
    '\u{2028}', '\u{2029}', // LINE SEPARATOR, PARAGRAPH SEPARATOR
];

/// Replaces each of these characters with `?`.
pub const REPLACEMENT: char = '?';

/// Returns `s` as a single line of inert text:
///
/// - every control character (`char::is_control`: C0 including `\t`, `\n`
///   and `\r`, DEL, and the C1 range with CSI U+009B), every bidi control
///   and the Unicode line and paragraph separators become `?`, so no
///   terminal escape sequence, carriage-return overwrite, line break or
///   reordering survives;
/// - text that would begin a line with `::` (after leading whitespace, which
///   the Actions runner trims) gets a `?` in front, so it can never be read
///   as a workflow command;
/// - `##[`, the older workflow-command marker, becomes `## [`.
///
/// Printable text, including non-ASCII letters, is left alone.
pub fn sanitize(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_control() || LAYOUT_CONTROLS.contains(&c) {
                REPLACEMENT
            } else {
                c
            }
        })
        .collect();
    if out.contains("##[") {
        out = out.replace("##[", "## [");
    }
    if out.trim_start().starts_with("::") {
        out.insert(0, REPLACEMENT);
    }
    out
}

/// Longest text, in characters, that `clip` lets through.
pub const MAX_SHOWN: usize = 200;

/// Characters `clip` keeps from the end of a long text, so a suffix such as
/// `.steps[3]` or `@v1` stays visible.
const CLIP_TAIL: usize = 20;

/// `s` as is when it has at most `MAX_SHOWN` characters; otherwise its
/// start and its last `CLIP_TAIL` characters around an ellipsis, `MAX_SHOWN`
/// characters in all.
///
/// For names a repository or a CI environment controls (job ids, `uses:`
/// values, file names, secret names) before they go into a location or a
/// detail: a 200 000-character job id says nothing a reader can use, and
/// every later pass over the report (scrubbing, rendering) pays for it.
pub fn clip(s: &str) -> String {
    let n = s.chars().count();
    if n <= MAX_SHOWN {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX_SHOWN - CLIP_TAIL - 1).collect();
    let tail: String = s.chars().skip(n - CLIP_TAIL).collect();
    format!("{head}\u{2026}{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_keeps_short_text_and_shortens_long_text() {
        assert_eq!(clip(""), "");
        let exact = "a".repeat(MAX_SHOWN);
        assert_eq!(clip(&exact), exact);
        let long = format!("jobs.{}.steps[3]", "x".repeat(500));
        let clipped = clip(&long);
        assert_eq!(clipped.chars().count(), MAX_SHOWN);
        assert!(clipped.starts_with("jobs.xxx"));
        assert!(clipped.ends_with("xxxxxxxxxx.steps[3]"));
        assert!(clipped.contains('\u{2026}'));
        // Counts characters, not bytes, and never splits one.
        let wide = "é".repeat(300);
        assert_eq!(clip(&wide).chars().count(), MAX_SHOWN);
    }

    #[test]
    fn plain_text_is_unchanged() {
        for s in [
            "",
            "~/.aws/credentials [default]",
            "Pin owner/action@0123abc",
            "Zoë's café ~/données",
            "a: b :: c",
        ] {
            assert_eq!(sanitize(s), s);
        }
    }

    #[test]
    fn control_characters_become_question_marks() {
        assert_eq!(sanitize("a\x1b[31mb"), "a?[31mb");
        assert_eq!(sanitize("x\x1b]0;T\x07y"), "x?]0;T?y");
        assert_eq!(sanitize("a\r\nb\tc"), "a??b?c");
        assert_eq!(sanitize("\u{9b}31m\u{85}\u{7f}"), "?31m??");
    }

    #[test]
    fn bidi_controls_become_question_marks() {
        assert_eq!(sanitize("a\u{202E}b\u{2066}c\u{200F}d\u{061C}"), "a?b?c?d?");
        assert_eq!(sanitize("a\u{2028}b\u{2029}"), "a?b?");
    }

    #[test]
    fn workflow_commands_cannot_start_a_line() {
        assert_eq!(sanitize("::error::x"), "?::error::x");
        assert_eq!(sanitize("  ::stop-commands::t"), "?  ::stop-commands::t");
        // A line break inside becomes `?`, so `::` is no longer at a line start.
        assert_eq!(sanitize("job\n::error::x"), "job?::error::x");
        assert_eq!(sanitize("##[error]x"), "## [error]x");
        assert!(!sanitize("\u{2003}::warning::x").starts_with(char::is_whitespace));
    }
}
