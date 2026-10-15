//! A deliberately tiny INI reader.
//!
//! Several credential files share the same `[section]` / `key = value` shape:
//! `~/.aws/credentials`, `~/.aws/config`, `~/.pypirc`, `~/.gitconfig`,
//! `~/.cargo/credentials.toml` (simple TOML is close enough) and gcloud
//! properties. We only need to find a few keys in them, so a 40-line reader is
//! easier to audit than a dependency.

/// One `[section]` and its entries, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The text between the brackets, trimmed. Entries before any header end
    /// up in a section with an empty name.
    pub name: String,
    /// `(key, value)` pairs. Keys are lowercased; values are trimmed and have
    /// one layer of surrounding quotes removed.
    pub entries: Vec<(String, String)>,
}

impl Section {
    /// The last value for `key` (case-insensitive), as INI readers usually do.
    pub fn get(&self, key: &str) -> Option<&str> {
        let key = key.to_ascii_lowercase();
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
}

/// Parses INI text. Lines starting with `#` or `;` are comments. Lines that
/// are neither a header nor `key = value` are ignored.
pub fn parse(text: &str) -> Vec<Section> {
    let mut sections = vec![Section {
        name: String::new(),
        entries: Vec::new(),
    }];
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            sections.push(Section {
                name: line[1..line.len() - 1].trim().to_string(),
                entries: Vec::new(),
            });
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            let value = crate::rules::trim_value(value).to_string();
            if let Some(current) = sections.last_mut() {
                current.entries.push((key, value));
            }
        }
    }
    sections.retain(|s| !s.name.is_empty() || !s.entries.is_empty());
    sections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_and_keys() {
        let text = "\n# comment\n[default]\naws_access_key_id = AKIA\nRegion=eu-west-1\n\n[profile x]\n; c\nkey = \"quoted\"\n";
        let s = parse(text);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].name, "default");
        assert_eq!(s[0].get("aws_access_key_id"), Some("AKIA"));
        assert_eq!(s[0].get("region"), Some("eu-west-1"));
        assert_eq!(s[1].name, "profile x");
        assert_eq!(s[1].get("KEY"), Some("quoted"));
    }

    #[test]
    fn values_may_contain_equals() {
        let s = parse("[a]\nk = x=y==\n");
        assert_eq!(s[0].get("k"), Some("x=y=="));
    }

    #[test]
    fn empty_values_are_none() {
        let s = parse("[a]\nk =\n");
        assert_eq!(s[0].get("k"), None);
    }
}
