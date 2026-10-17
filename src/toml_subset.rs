//! A small reader for the part of TOML that Codex's `config.toml` uses.
//!
//! Codex keeps MCP servers in `[mcp_servers.<name>]` tables with string
//! values, arrays of strings and inline tables (`env = { KEY = "value" }`).
//! The `toml` crate reads heldkeys' own `.heldkeys.toml`, where a syntax
//! error must be refused. Scanned files need the opposite: this reader never
//! fails and skips a line it cannot parse, so one odd line in a file someone
//! else wrote does not hide the credentials after it.
//!
//! The result is a `serde_json::Value` tree, so the `mcp` check can walk
//! Codex servers with the same code as the JSON-based clients.
//!
//! Supported: comments, `[table]` headers with dotted and quoted keys,
//! `key = value` with dotted keys, basic and literal strings (single and
//! multi-line), arrays (also across lines) and inline tables. Numbers,
//! dates and other scalars become `null`, and `[[array.tables]]` are skipped,
//! because MCP credentials are always strings. A line that does not parse is
//! skipped rather than failing the whole file.

use serde_json::{Map, Value};

/// Parses `text` into a JSON object. Never fails: unparseable lines are skipped.
pub fn parse(text: &str) -> Value {
    let mut parser = Parser {
        chars: text.chars().collect(),
        pos: 0,
    };
    let mut root = Value::Object(Map::new());
    // `None` while inside an `[[array.table]]`, whose keys we ignore.
    let mut table: Option<Vec<String>> = Some(Vec::new());

    loop {
        parser.skip_blank_lines();
        let Some(c) = parser.peek() else {
            break;
        };
        let start = parser.pos;
        let ok = if c == '[' {
            parser.table_header().map(|header| {
                table = header;
                if let Some(path) = &table {
                    ensure_object(&mut root, path);
                }
            })
        } else {
            parser.key_value().map(|(key, value)| {
                if let Some(path) = &table {
                    let mut full = path.clone();
                    full.extend(key);
                    insert(&mut root, &full, value);
                }
            })
        };
        if ok.is_none() || parser.pos == start {
            parser.skip_line();
        }
    }
    root
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn starts_with(&self, s: &str) -> bool {
        s.chars()
            .enumerate()
            .all(|(i, c)| self.chars.get(self.pos + i) == Some(&c))
    }

    /// Skips spaces and tabs (not newlines).
    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.pos += 1;
        }
    }

    fn skip_line(&mut self) {
        while let Some(c) = self.peek() {
            self.pos += 1;
            if c == '\n' {
                break;
            }
        }
    }

    /// Skips whitespace, newlines and comments.
    fn skip_blank_lines(&mut self) {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => self.pos += 1,
                Some('#') => self.skip_line(),
                _ => break,
            }
        }
    }

    /// `[a.b]` gives `Some(["a", "b"])`; `[[a.b]]` gives `None` (skipped).
    fn table_header(&mut self) -> Option<Option<Vec<String>>> {
        let array = self.starts_with("[[");
        self.pos += if array { 2 } else { 1 };
        let key = self.key()?;
        self.skip_spaces();
        let close = if array { "]]" } else { "]" };
        if !self.starts_with(close) {
            return None;
        }
        self.pos += close.len();
        self.skip_line();
        Some(if array { None } else { Some(key) })
    }

    /// `key = value` at the current position.
    fn key_value(&mut self) -> Option<(Vec<String>, Value)> {
        let key = self.key()?;
        self.skip_spaces();
        if self.peek() != Some('=') {
            return None;
        }
        self.pos += 1;
        self.skip_spaces();
        let value = self.value()?;
        Some((key, value))
    }

    /// A dotted key: `a.b`, `"quoted key".c`, `'literal'`.
    fn key(&mut self) -> Option<Vec<String>> {
        let mut parts = Vec::new();
        loop {
            self.skip_spaces();
            let part = match self.peek()? {
                '"' => self.basic_string()?,
                '\'' => self.literal_string()?,
                _ => {
                    let start = self.pos;
                    while self
                        .peek()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    {
                        self.pos += 1;
                    }
                    if self.pos == start {
                        return None;
                    }
                    self.chars[start..self.pos].iter().collect()
                }
            };
            parts.push(part);
            self.skip_spaces();
            if self.peek() == Some('.') {
                self.pos += 1;
            } else {
                return Some(parts);
            }
        }
    }

    fn value(&mut self) -> Option<Value> {
        match self.peek()? {
            '"' if self.starts_with("\"\"\"") => self.multiline("\"\"\"").map(Value::String),
            '\'' if self.starts_with("'''") => self.multiline("'''").map(Value::String),
            '"' => self.basic_string().map(Value::String),
            '\'' => self.literal_string().map(Value::String),
            '[' => self.array(),
            '{' => self.inline_table(),
            _ => Some(self.scalar()),
        }
    }

    /// `"..."` with the common escapes. Stops at the end of the line.
    fn basic_string(&mut self) -> Option<String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.pos += 1;
            match c {
                '"' => return Some(out),
                '\n' => return None,
                '\\' => {
                    let escaped = self.peek()?;
                    self.pos += 1;
                    match escaped {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'u' | 'U' => {
                            let len = if escaped == 'u' { 4 } else { 8 };
                            let hex: String =
                                self.chars.get(self.pos..self.pos + len)?.iter().collect();
                            self.pos += len;
                            out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                        }
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
    }

    /// `'...'`: no escapes.
    fn literal_string(&mut self) -> Option<String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.pos += 1;
            match c {
                '\'' => return Some(out),
                '\n' => return None,
                other => out.push(other),
            }
        }
    }

    /// `"""..."""` or `'''...'''`, taken as is (escapes are not processed:
    /// we only classify these values, and a token never contains one).
    fn multiline(&mut self, delimiter: &str) -> Option<String> {
        self.pos += delimiter.len();
        let start = self.pos;
        while !self.starts_with(delimiter) {
            self.peek()?;
            self.pos += 1;
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        self.pos += delimiter.len();
        Some(text.strip_prefix('\n').unwrap_or(&text).to_string())
    }

    /// `[a, "b", [c]]`, possibly across lines and with comments.
    fn array(&mut self) -> Option<Value> {
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_blank_lines();
            match self.peek()? {
                ']' => {
                    self.pos += 1;
                    return Some(Value::Array(items));
                }
                ',' => self.pos += 1,
                _ => {
                    let start = self.pos;
                    let value = self.value()?;
                    if self.pos == start {
                        // Nothing a value can start with, such as a stray `}`:
                        // the array is broken. Give up on it instead of
                        // pushing empty values forever.
                        return None;
                    }
                    items.push(value);
                }
            }
        }
    }

    /// `{ a = "b", c.d = "e" }`.
    fn inline_table(&mut self) -> Option<Value> {
        self.pos += 1;
        let mut table = Value::Object(Map::new());
        loop {
            self.skip_blank_lines();
            match self.peek()? {
                '}' => {
                    self.pos += 1;
                    return Some(table);
                }
                ',' => self.pos += 1,
                _ => {
                    let (key, value) = self.key_value()?;
                    insert(&mut table, &key, value);
                }
            }
        }
    }

    /// Numbers, booleans, dates: only booleans are kept.
    fn scalar(&mut self) -> Value {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|c| !matches!(c, ',' | ']' | '}' | '\n' | '#'))
        {
            self.pos += 1;
        }
        let raw: String = self.chars[start..self.pos].iter().collect();
        match raw.trim() {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => Value::Null,
        }
    }
}

/// Makes sure `path` exists as nested objects under `root`.
fn ensure_object(root: &mut Value, path: &[String]) {
    let mut node = root;
    for part in path {
        let Value::Object(map) = node else {
            return;
        };
        node = map
            .entry(part.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
}

/// Sets `root[path...] = value`, creating objects on the way. Paths that run
/// into a non-object value are ignored.
fn insert(root: &mut Value, path: &[String], value: Value) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut node = root;
    for part in parents {
        let Value::Object(map) = node else {
            return;
        };
        node = map
            .entry(part.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if let Value::Object(map) = node {
        map.insert(last.clone(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_style_config() {
        let text = r#"
model = "o3"   # trailing comment
[mcp_servers.github]
command = "npx"
args = [
  "-y",   # comment inside an array
  "@modelcontextprotocol/server-github",
]
env = { GITHUB_TOKEN = "abc", "QUOTED KEY" = 'lit\eral' }
startup_timeout_sec = 20

[mcp_servers."my.server".env]
API_KEY = "x\"y"

[[profiles]]
ignored = "yes"
"#;
        let v = parse(text);
        assert_eq!(v["model"], "o3");
        let github = &v["mcp_servers"]["github"];
        assert_eq!(github["command"], "npx");
        assert_eq!(github["args"][1], "@modelcontextprotocol/server-github");
        assert_eq!(github["env"]["GITHUB_TOKEN"], "abc");
        assert_eq!(github["env"]["QUOTED KEY"], "lit\\eral");
        assert_eq!(github["startup_timeout_sec"], Value::Null);
        assert_eq!(v["mcp_servers"]["my.server"]["env"]["API_KEY"], "x\"y");
        assert!(v.get("ignored").is_none());
    }

    #[test]
    fn dotted_keys_and_multiline_strings() {
        let v = parse("[a]\nb.c = \"\"\"\nline\"\"\"\nd = true\n");
        assert_eq!(v["a"]["b"]["c"], "line");
        assert_eq!(v["a"]["d"], true);
    }

    #[test]
    fn stray_brace_inside_an_array_ends_it() {
        // Found by fuzzing: the array loop made no progress on `}` and pushed
        // nulls until memory ran out. The broken line is skipped, the rest
        // still parses.
        let v = parse("k-=[\n}\n[t]\nk = \"v\"\n");
        assert!(v.get("k-").is_none());
        assert_eq!(v["t"]["k"], "v");
    }

    #[test]
    fn broken_lines_are_skipped() {
        let v = parse("this is not toml\n[t]\nk = \"v\"\nx = \"unterminated\n");
        assert_eq!(v["t"]["k"], "v");
    }
}
