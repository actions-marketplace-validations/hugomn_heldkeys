//! JSON with comments, as VS Code and Zed write their settings files.
//!
//! `settings.json` in those editors allows `//` and `/* */` comments and
//! trailing commas, which strict JSON parsers reject. We strip both and hand
//! the rest to `serde_json`, which is simpler to audit than a second parser.

use serde_json::Value;

/// Parses JSON that may contain comments, trailing commas and a leading
/// byte order mark. `None` if it is still not valid JSON after stripping them.
pub fn parse(text: &str) -> Option<Value> {
    serde_json::from_str(&strip(strip_bom(text))).ok()
}

/// Editors on Windows save a UTF-8 byte order mark, which JSON parsers reject.
pub fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// A file with nothing but whitespace, comments and a byte order mark: what
/// an editor leaves in a config it created and never filled. Not an error.
pub fn is_blank(text: &str) -> bool {
    strip(strip_bom(text)).trim().is_empty()
}

/// Removes comments and trailing commas outside of strings.
pub fn strip(text: &str) -> String {
    let without_comments = strip_comments(text);
    strip_trailing_commas(&without_comments)
}

fn strip_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            // Line comment: skip to the end of the line, keep the newline.
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            // Block comment: skip past the closing */ (or to the end).
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
            continue;
        }
        if c == '"' {
            in_string = true;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_string = true;
        }
        if c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_trailing_commas() {
        let text = r#"{
            // a comment with "quotes"
            "a": "http://example.com/x", /* block */
            "b": [1, 2,],
            "c": "not // a comment",
        }"#;
        let v = parse(text).unwrap();
        assert_eq!(v["a"], "http://example.com/x");
        assert_eq!(v["b"].as_array().unwrap().len(), 2);
        assert_eq!(v["c"], "not // a comment");
    }

    #[test]
    fn escaped_quotes_stay_inside_strings() {
        let v = parse(r#"{"a": "say \"hi\" // still text", }"#).unwrap();
        assert_eq!(v["a"], "say \"hi\" // still text");
    }

    #[test]
    fn top_level_comments_bom_and_urls_in_strings() {
        let text = "\u{feff}// VS Code MCP servers\n/* block */\n{\n  \"servers\": {\n    \"x\": {\"url\": \"https://example.com//path\", \"args\": [\"--a\", \"//b\",],},\n  },\n}\n// trailing\n";
        let v = parse(text).unwrap();
        assert_eq!(v["servers"]["x"]["url"], "https://example.com//path");
        assert_eq!(v["servers"]["x"]["args"][1], "//b");
        assert_eq!(parse("\u{feff}{}").unwrap(), serde_json::json!({}));
    }

    #[test]
    fn blank_files() {
        for text in ["", "  \n", "\u{feff}", "// nothing yet\n", "/* */"] {
            assert!(is_blank(text), "{text:?}");
        }
        assert!(!is_blank("{}"));
        assert!(!is_blank("x"));
    }

    #[test]
    fn invalid_is_none() {
        assert!(parse("{ not json").is_none());
    }
}
