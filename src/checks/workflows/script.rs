//! Reading `run:` scripts: which parts the shell runs as code, and which
//! program each simple command in them runs.
//!
//! This is a scanner for a linter, not a shell parser. It has to tell prose
//! (quoted strings, comments, `cat <<EOF` bodies) from commands in typical
//! workflow scripts, and when it cannot tell, it errs towards code: a
//! workflow that hides an agent call from heldkeys is worse than one extra
//! finding.

use std::sync::LazyLock;

use regex::Regex;

/// Where the scanner is inside a line of shell.
#[derive(Clone, Copy, PartialEq)]
enum Quote {
    None,
    Single,
    Double,
}

/// Starts a heredoc: `<<EOF`, `<<-EOF`, `<<'EOF'`, `<< "EOF"`, `<<\EOF`
/// (not `<<<`).
static HEREDOC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[^<])(<<)(-?)[ \t]*\\?['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?"#)
        .expect("valid regex")
});

/// Text just before a quote whose content the shell runs as code:
/// `bash -c '...'`, `sh -ec "..."`, `eval "..."`.
static CODE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|[\s;&|(])(?:(?:\S*/)?(?:ba|z|da|k)?sh(?:\s+--?[A-Za-z-]+)*?\s+-[A-Za-z]*c[A-Za-z]*|eval)\s*$",
    )
    .expect("valid regex")
});

/// How far before a quote `CODE_QUOTE` looks.
const CODE_QUOTE_WINDOW: usize = 256;

/// Programs a heredoc can feed code to (`bash <<'EOF'`, `cat <<EOF | sh`).
const INTERPRETERS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "python", "python3"];

/// How many times an unterminated quote may restart the scan.
const MAX_RESCANS: usize = 8;

struct Heredoc {
    delimiter: String,
    strip_tabs: bool,
    /// Fed to a shell or interpreter, so the body is code, not prose.
    code: bool,
}

struct ScanState {
    quote: Quote,
    /// The open quote's content is code (`bash -c '...'`).
    code_quote: bool,
    /// Each `$(` opened inside double quotes: its paren depth, and whether
    /// the quote around it was a code quote.
    substs: Vec<(usize, bool)>,
    /// Where the outermost open quote started: the length of the output
    /// before it, and the byte offset in the script just after it.
    opened: Option<(usize, usize)>,
}

/// The parts of a `run:` script the shell runs as code. Comments and the
/// bodies of heredocs fed to anything but a shell or interpreter are
/// dropped. With `blank_quotes`, so is the inside of quoted strings (`echo
/// "claude ran"` becomes `echo ""`), except a `$(...)` inside double quotes
/// and the argument of `bash -c` or `eval`, which the shell does run (their
/// quotes become `;`, so the code inside starts a command). Lines are kept,
/// so line-based matching still works.
///
/// A quote left open at the end of the script is a syntax error the shell
/// would refuse, but it must not hide the rest of the script: the scan
/// restarts after it, reading the rest as code.
pub(super) fn shell_code(script: &str, blank_quotes: bool) -> String {
    shell_code_from(script, blank_quotes, MAX_RESCANS)
}

fn shell_code_from(script: &str, blank_quotes: bool, rescans: usize) -> String {
    let mut out = String::with_capacity(script.len());
    let mut heredoc: Option<Heredoc> = None;
    let mut st = ScanState {
        quote: Quote::None,
        code_quote: false,
        substs: Vec::new(),
        opened: None,
    };
    let mut line_start = 0;
    for line in script.split('\n') {
        let start = line_start;
        line_start += line.len() + 1;
        if let Some(h) = &heredoc {
            let l = if h.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if l.trim_end() == h.delimiter {
                heredoc = None;
                st.quote = Quote::None;
                st.code_quote = false;
                st.substs.clear();
                st.opened = None;
            } else if h.code {
                scan_line(line, start, &mut st, blank_quotes, &mut out);
            }
            out.push('\n');
            continue;
        }
        let starts_heredoc = if st.quote == Quote::None {
            heredoc_start(line)
        } else {
            None
        };
        scan_line(line, start, &mut st, blank_quotes, &mut out);
        out.push('\n');
        heredoc = starts_heredoc;
    }
    out.pop();
    let unterminated = st.quote != Quote::None || !st.substs.is_empty();
    if unterminated && let Some((out_len, offset)) = st.opened {
        out.truncate(out_len);
        out.push(' ');
        let rest = &script[offset.min(script.len())..];
        if rescans > 0 {
            out.push_str(&shell_code_from(rest, blank_quotes, rescans - 1));
        } else {
            out.push_str(rest);
        }
    }
    out
}

/// The heredoc `line` starts, if any. `<<` inside `$(( ))` or `(( ))` is
/// a shift, not a heredoc.
///
/// The `((` and `))` before each `<<` are counted in one left-to-right pass
/// shared by all the `<<` of the line, so a line of many shifts stays linear.
fn heredoc_start(line: &str) -> Option<Heredoc> {
    let mut opens = PairCounter::new(b'(');
    let mut closes = PairCounter::new(b')');
    HEREDOC.captures_iter(line).find_map(|c| {
        let op = c.get(1)?;
        let before = &line[..op.start()];
        if opens.count_to(line, op.start()) > closes.count_to(line, op.start()) {
            return None; // arithmetic
        }
        let after = &line[c.get(0)?.end()..];
        let fed_to_interpreter = simple_commands(before)
            .last()
            .and_then(program)
            .is_some_and(|(p, _)| INTERPRETERS.contains(&p.as_str()))
            || after.split('|').skip(1).any(|piece| {
                program(piece).is_some_and(|(p, _)| INTERPRETERS.contains(&p.as_str()))
            });
        Some(Heredoc {
            delimiter: c[3].to_string(),
            strip_tabs: !c[2].is_empty(),
            code: fed_to_interpreter,
        })
    })
}

/// Counts non-overlapping pairs of one byte (`((` or `))`) from the start of
/// a line, as `str::matches` would, up to a position that only grows, so
/// each byte is looked at once whatever the number of calls.
struct PairCounter {
    byte: u8,
    /// Where the next pair may start.
    at: usize,
    count: usize,
}

impl PairCounter {
    fn new(byte: u8) -> PairCounter {
        PairCounter {
            byte,
            at: 0,
            count: 0,
        }
    }

    /// The pairs in `line[..end]`. `end` must not decrease between calls.
    fn count_to(&mut self, line: &str, end: usize) -> usize {
        let bytes = &line.as_bytes()[..end];
        while self.at + 1 < bytes.len() {
            if bytes[self.at] == self.byte && bytes[self.at + 1] == self.byte {
                self.count += 1;
                self.at += 2;
            } else {
                self.at += 1;
            }
        }
        self.count
    }
}

fn scan_line(line: &str, line_start: usize, st: &mut ScanState, blank: bool, out: &mut String) {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (at, c) = chars[i];
        let next = chars.get(i + 1).map(|&(_, n)| n);
        let keep = !blank || st.quote == Quote::None || st.code_quote;
        match st.quote {
            Quote::None => {
                let after_space = i == 0 || " \t;&|(".contains(chars[i - 1].1);
                if c == '#' && after_space {
                    return; // a comment: the rest of the line is not code
                }
                if c == '\\' {
                    out.push(c);
                    if let Some(next) = next {
                        out.push(next);
                    }
                    i += 2;
                    continue;
                }
                match c {
                    '\'' | '"' => {
                        if st.substs.is_empty() {
                            st.opened = Some((out.len(), line_start + at + 1));
                        }
                        st.code_quote = CODE_QUOTE.is_match(before(line, at));
                        st.quote = if c == '\'' {
                            Quote::Single
                        } else {
                            Quote::Double
                        };
                        out.push(if st.code_quote { ';' } else { c });
                        i += 1;
                        continue;
                    }
                    '(' => {
                        if let Some((depth, _)) = st.substs.last_mut() {
                            *depth += 1;
                        }
                    }
                    ')' => match st.substs.last_mut() {
                        Some((0, code_quote)) => {
                            st.code_quote = *code_quote;
                            st.substs.pop();
                            st.quote = Quote::Double;
                        }
                        Some((depth, _)) => *depth -= 1,
                        None => {}
                    },
                    _ => {}
                }
                out.push(c);
            }
            Quote::Single => {
                if c == '\'' {
                    out.push(if st.code_quote { ';' } else { c });
                    st.quote = Quote::None;
                    st.code_quote = false;
                } else if keep {
                    out.push(c);
                }
            }
            Quote::Double => {
                if c == '\\' {
                    if keep {
                        out.push(c);
                        if let Some(next) = next {
                            out.push(next);
                        }
                    }
                    i += 2;
                    continue;
                }
                if c == '"' {
                    out.push(if st.code_quote { ';' } else { c });
                    st.quote = Quote::None;
                    st.code_quote = false;
                } else if c == '$' && next == Some('(') {
                    // Command substitution: code again until its `)`.
                    out.push_str("$(");
                    st.substs.push((0, st.code_quote));
                    st.quote = Quote::None;
                    st.code_quote = false;
                    i += 2;
                    continue;
                } else if keep {
                    out.push(c);
                }
            }
        }
        i += 1;
    }
}

/// At most the last `CODE_QUOTE_WINDOW` bytes of `line` before byte `at`,
/// so that a line of many quotes stays linear to scan.
fn before(line: &str, at: usize) -> &str {
    let mut start = at.saturating_sub(CODE_QUOTE_WINDOW);
    while !line.is_char_boundary(start) {
        start += 1;
    }
    &line[start..at]
}

/// The simple commands of shell code (as `shell_code` returns it): split at
/// newlines, `;`, `&`, `|`, parentheses, braces and backticks, so that
/// `(claude)`, `{ claude; }`, `$(claude)` and `a && claude` each give a
/// piece that starts with the command.
pub(super) fn simple_commands(code: &str) -> impl Iterator<Item = &str> {
    code.split(['\n', ';', '&', '|', '(', ')', '{', '}', '`'])
}

/// Words that may come before the command itself.
const KEYWORDS: &[&str] = &["if", "then", "else", "elif", "do", "while", "until", "!"];

/// Commands that run the command after them, and their options that take a
/// value (`timeout -s KILL 600 claude`).
const WRAPPERS: &[(&str, &[&str])] = &[
    (
        "env",
        &["-u", "--unset", "-C", "--chdir", "-S", "--split-string"],
    ),
    ("timeout", &["-s", "--signal", "-k", "--kill-after"]),
    ("nohup", &[]),
    ("command", &[]),
    ("builtin", &[]),
    ("exec", &["-a"]),
    ("time", &[]),
    ("stdbuf", &["-i", "-o", "-e"]),
    (
        "xargs",
        &[
            "-I",
            "-n",
            "-P",
            "-L",
            "-s",
            "-d",
            "-E",
            "-a",
            "--arg-file",
            "--delimiter",
        ],
    ),
    (
        "sudo",
        &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"],
    ),
    ("nice", &["-n"]),
    ("setsid", &[]),
    ("npx", &["-p", "--package", "-c", "--call"]),
    ("pnpx", &[]),
    ("bunx", &["-p", "--package"]),
    ("uvx", &["--from", "--with", "-p", "--python"]),
];

/// Two-word package runners (`npm exec -- @anthropic-ai/claude-code`).
const RUNNERS: &[(&str, &str)] = &[
    ("npm", "exec"),
    ("npm", "x"),
    ("pnpm", "dlx"),
    ("pnpm", "exec"),
    ("yarn", "dlx"),
    ("yarn", "exec"),
    ("bun", "x"),
    ("pipx", "run"),
];
const RUNNER_OPTIONS: &[&str] = &["-p", "--package", "-c", "--call", "-w", "--workspace"];

/// What a simple command runs: its program and arguments, once keywords
/// (`if`, `then`, `!`...), variable assignments (`A=b`) and wrappers (`env`,
/// `timeout 600`, `sudo`, `npx -y`, `npm exec --`...) are skipped. The
/// program is the base name of a path (`./node_modules/.bin/claude` gives
/// `claude`), without a leading backslash (`\claude`) or a package version
/// (`@anthropic-ai/claude-code@1.2` gives `@anthropic-ai/claude-code`).
/// `None` for an empty command and for `command -v x`, which only looks a
/// program up.
pub(super) fn program(command: &str) -> Option<(String, Vec<&str>)> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let mut i = 0;
    loop {
        let word = *words.get(i)?;
        if KEYWORDS.contains(&word) || is_assignment(word) {
            i += 1;
            continue;
        }
        let name = program_name(word);
        if let Some(&sub) = words.get(i + 1)
            && RUNNERS.contains(&(name.as_str(), sub))
        {
            i = skip_options(&words, i + 2, RUNNER_OPTIONS);
            continue;
        }
        if let Some((wrapper, with_value)) = WRAPPERS.iter().find(|(w, _)| *w == name) {
            if *wrapper == "command" && matches!(words.get(i + 1), Some(&("-v" | "-V"))) {
                return None;
            }
            i = skip_options(&words, i + 1, with_value);
            if *wrapper == "timeout" && words.get(i).is_some_and(|w| is_duration(w)) {
                i += 1;
            }
            continue;
        }
        return Some((name, words[i + 1..].to_vec()));
    }
}

fn program_name(word: &str) -> String {
    let word = word.trim_start_matches('\\');
    let name = if word.starts_with('@') {
        word
    } else {
        word.rsplit('/').next().unwrap_or(word)
    };
    // A package version: `pkg@1.2`, `@scope/pkg@latest`.
    let name = match name.char_indices().skip(1).find(|&(_, c)| c == '@') {
        Some((at, _)) => &name[..at],
        None => name,
    };
    name.to_ascii_lowercase()
}

fn skip_options(words: &[&str], mut i: usize, with_value: &[&str]) -> usize {
    while let Some(&word) = words.get(i) {
        if word == "--" {
            return i + 1;
        }
        if is_assignment(word) {
            i += 1;
            continue;
        }
        if !word.starts_with('-') || word == "-" {
            break;
        }
        i += if with_value.contains(&word) { 2 } else { 1 };
    }
    i
}

/// `NAME=value`.
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        let mut chars = name.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// `600`, `10m`, `1.5h`.
fn is_duration(word: &str) -> bool {
    let digits = word.trim_end_matches(['s', 'm', 'h', 'd']);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Arguments without redirections (`2>`, `> /dev/null`, `<in.txt`).
pub(super) fn plain_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut plain = Vec::new();
    let mut skip_next = false;
    for &arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let is_operator = !arg.is_empty()
            && arg
                .trim_start_matches(|c: char| c.is_ascii_digit())
                .chars()
                .all(|c| "<>&".contains(c))
            && arg.contains(['<', '>']);
        if is_operator {
            skip_next = true;
        } else if !arg.contains(['<', '>']) {
            plain.push(arg);
        }
    }
    plain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_code_keeps_commands_only() {
        assert_eq!(shell_code("echo \"a b\" # c", true), "echo \"\" ");
        assert_eq!(shell_code("echo \"a b\" # c", false), "echo \"a b\" ");
        assert_eq!(
            shell_code("x=\"$(claude -p 'q')\"", true),
            "x=\"$(claude -p '')\""
        );
        assert_eq!(shell_code("echo $#; a#b", true), "echo $#; a#b");
        assert_eq!(
            shell_code("cat <<'EOF'\nclaude\nEOF\ncodex", true),
            "cat <<''\n\n\ncodex"
        );
        assert_eq!(shell_code("cat <<< claude", true), "cat <<< claude");
        assert_eq!(
            shell_code("echo 'it''s'\nclaude", true),
            "echo ''''\nclaude"
        );
    }

    #[test]
    fn code_inside_quotes_and_heredocs_is_kept() {
        assert_eq!(
            shell_code("bash -c 'claude -p x'", true),
            "bash -c ;claude -p x;"
        );
        assert_eq!(shell_code("eval \"codex exec\"", true), "eval ;codex exec;");
        assert_eq!(
            shell_code("bash <<'X'\nclaude\nX\necho done", true),
            "bash <<''\nclaude\n\necho done"
        );
        assert_eq!(
            shell_code("cat <<EOF | sh\nclaude\nEOF", true),
            "cat <<EOF | sh\nclaude\n"
        );
        assert_eq!(
            shell_code("x=$((1<<EOF))\nclaude", true),
            "x=$((1<<EOF))\nclaude"
        );
    }

    #[test]
    fn shifts_in_arithmetic_are_not_heredocs() {
        // `((` opened before the `<<`, closed after it: a shift.
        assert!(heredoc_start("(( x<<a ))").is_none());
        assert!(heredoc_start("y=$(( 1 << 2 )) && cat <<EOF").is_some());
        assert!(heredoc_start("((a)) cat <<EOF").is_some());
        // `(((` counts one pair, as `str::matches` does.
        assert!(heredoc_start("((( x<<a").is_none());
        let shifts = format!("(({}", " x<<a".repeat(5));
        assert!(heredoc_start(&shifts).is_none());
    }

    #[test]
    fn many_shifts_on_one_line_stay_linear() {
        // Was quadratic: the `((` before every `<<` were counted again.
        let line = format!("(({}", " x<<a".repeat(80_000));
        let started = std::time::Instant::now();
        assert!(heredoc_start(&line).is_none());
        shell_code(&line, true);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn pair_counter_matches_str_matches() {
        for line in ["", "(", "((", "(((", "((((", "a((b))((c", "( ( ((x(("] {
            let mut opens = PairCounter::new(b'(');
            for end in 0..=line.len() {
                assert_eq!(
                    opens.count_to(line, end),
                    line[..end].matches("((").count(),
                    "{line:?}[..{end}]"
                );
            }
        }
    }

    #[test]
    fn an_unterminated_quote_does_not_hide_the_rest() {
        assert_eq!(
            shell_code("echo \"unterminated\nclaude -p fix", true),
            "echo  unterminated\nclaude -p fix"
        );
        // Terminated across lines: still a string.
        assert_eq!(shell_code("echo 'a\nclaude'\nb", true), "echo '\n'\nb");
        // Many stray quotes stay linear and keep the text.
        let stray = "'\"".repeat(10_000);
        assert!(shell_code(&stray, true).len() <= stray.len());
        let started = std::time::Instant::now();
        let quotes = format!("echo {}x\n", "'' \"\" ".repeat(100_000));
        assert_eq!(shell_code(&quotes, true), quotes);
        let unterminated = format!("echo \"{}", "a' b\" ".repeat(50_000));
        shell_code(&unterminated, true);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn programs_of_simple_commands() {
        let p = |cmd: &str| program(cmd).map(|(name, _)| name);
        assert_eq!(p("claude -p x").as_deref(), Some("claude"));
        assert_eq!(p("  if ! \\claude -p x").as_deref(), Some("claude"));
        assert_eq!(
            p("A=1 B=\"\" env -u X C=2 claude").as_deref(),
            Some("claude")
        );
        assert_eq!(p("timeout -s KILL 10m claude").as_deref(), Some("claude"));
        assert_eq!(
            p("sudo -u runner nohup time stdbuf -oL claude").as_deref(),
            Some("claude")
        );
        assert_eq!(
            p("npm exec --yes -- @anthropic-ai/claude-code@1.0.0 -p x").as_deref(),
            Some("@anthropic-ai/claude-code")
        );
        assert_eq!(
            p("pnpm dlx opencode-ai@latest").as_deref(),
            Some("opencode-ai")
        );
        assert_eq!(p("/usr/local/bin/claude").as_deref(), Some("claude"));
        assert_eq!(p("npm install claude").as_deref(), Some("npm"));
        assert_eq!(p("command -v claude"), None);
        assert_eq!(p("   "), None);
        assert_eq!(
            plain_args(&["--version", "2>", "/dev/null"]),
            vec!["--version"]
        );
        assert_eq!(plain_args(&["--help", ">out.txt"]), vec!["--help"]);
    }
}
