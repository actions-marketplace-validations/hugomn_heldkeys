//! `heldkeys incident <set>`: the credential inventory, with checks for the
//! indicators of a named supply-chain incident in front of it.
//!
//! Plenty of tools scan for one indicator of compromise. The question that
//! follows is the one heldkeys already answers: if this machine ran the
//! malicious build, which credentials did it hand over, and which ones do I
//! rotate first? An incident set bundles the indicators of one wave of
//! disclosures with the normal inventory, and the report leads with a
//! verdict: indicators found (treat the host as compromised, rotate
//! everything below) or none found (the list is what an attacker would have
//! got).
//!
//! An indicator list is a snapshot: it covers what the advisories had
//! published on the date in `as_of`, and finding nothing proves nothing.
//! Every report says so and links the primary advisories.

use crate::checks::{self, Check};
use crate::finding::{Category, Finding, Severity};

/// A named set of indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Set {
    /// The 19 to 22 October 2026 wave: the compromised LiteLLM 1.107.0
    /// release on PyPI and Docker, the tampered OVHcloud CLI release
    /// binaries, the php2shell PHP fixes, the Node.js October security
    /// release, and the Railway, Zeabur and OpenCode Console breaches.
    BlackOctober,
}

impl Set {
    pub const ALL: [Set; 1] = [Set::BlackOctober];

    /// The name on the command line.
    pub fn id(self) -> &'static str {
        match self {
            Set::BlackOctober => "black-october",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Set::BlackOctober => "Black October (19 to 22 October 2026)",
        }
    }

    /// The date the indicator list was last checked against the advisories.
    pub fn as_of(self) -> &'static str {
        match self {
            Set::BlackOctober => "2026-10-23",
        }
    }

    /// The checks that look for this set's indicators. The credential
    /// inventory (`checks::local_checks`) runs next to them.
    pub fn checks(self) -> Vec<Box<dyn Check>> {
        match self {
            Set::BlackOctober => checks::incident::black_october(),
        }
    }

    /// The primary sources, in the order the report lists them.
    pub fn advisories(self) -> &'static [Advisory] {
        match self {
            Set::BlackOctober => BLACK_OCTOBER_ADVISORIES,
        }
    }
}

/// A primary source for an indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Advisory {
    pub what: &'static str,
    pub url: &'static str,
}

const BLACK_OCTOBER_ADVISORIES: &[Advisory] = &[
    Advisory {
        what: "LiteLLM: release v1.107.0 compromised (21 Oct 2026)",
        url: "https://docs.litellm.ai/blog/security-incident-oct-21-2026",
    },
    Advisory {
        what: "SafeDep: analysis and file hashes of the LiteLLM stealer",
        url: "https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/",
    },
    Advisory {
        what: "StepSecurity: LiteLLM indicators, loader behaviour and image digests",
        url: "https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer",
    },
    Advisory {
        what: "OVHcloud: ovhcloud-cli security incident of 19 Oct 2026 (GHSA-862f-55f5-vmvw)",
        url: "https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw",
    },
    Advisory {
        what: "CISA: critical PHP vulnerabilities require immediate patching (21 Oct 2026)",
        url: "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching",
    },
    Advisory {
        what: "Node.js: October 2026 security releases",
        url: "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
    },
    Advisory {
        what: "Railway: security disclosure of 21 Oct 2026",
        url: "https://blog.railway.com/p/security-disclosure-wednesday-october-21st",
    },
    Advisory {
        what: "Zeabur: October 2026 security incident",
        url: "https://zeabur.com/blogs/october-2026-security-incident",
    },
    Advisory {
        what: "OpenCode Console breach, as reported by TechCrunch (OpenCode emailed the affected users)",
        url: "https://techcrunch.com/2026/10/19/hackers-hit-ai-coding-tool-opencode-running-up-charges-on-users-ai-accounts/",
    },
];

/// What `heldkeys incident` adds to a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incident {
    pub set: Set,
}

impl Incident {
    pub fn id(&self) -> &'static str {
        self.set.id()
    }

    pub fn title(&self) -> &'static str {
        self.set.title()
    }

    pub fn as_of(&self) -> &'static str {
        self.set.as_of()
    }

    pub fn advisories(&self) -> &'static [Advisory] {
        self.set.advisories()
    }

    /// The line every report carries: the list is a snapshot, not a proof.
    pub fn disclaimer(&self) -> String {
        format!(
            "Indicators as published up to {}; finding none proves nothing, and the list is no substitute for the advisories below.",
            self.as_of()
        )
    }
}

/// A confirmed indicator: the host ran, or holds, a malicious build.
pub fn is_indicator(f: &Finding) -> bool {
    f.category == Category::Indicators && f.severity == Severity::High
}

/// A sign of exposure to check, short of a confirmed indicator: a lockfile
/// that pins the bad release, a binary installed during the window.
pub fn is_exposure(f: &Finding) -> bool {
    f.category == Category::Indicators && matches!(f.severity, Severity::Medium | Severity::Low)
}

/// Named verdicts, for the JSON output and the summary line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// At least one confirmed indicator.
    Compromised,
    /// No confirmed indicator, but signs of exposure to check.
    Exposed,
    /// Nothing of the set found.
    Clean,
}

pub fn verdict(findings: &[Finding]) -> Verdict {
    if findings.iter().any(is_indicator) {
        Verdict::Compromised
    } else if findings.iter().any(is_exposure) {
        Verdict::Exposed
    } else {
        Verdict::Clean
    }
}

/// `black-october` to `Set::BlackOctober`.
pub fn parse_set(name: &str) -> Option<Set> {
    Set::ALL.into_iter().find(|s| s.id() == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime, Rule};

    fn finding(check: &'static str, severity: Severity) -> Finding {
        let rule = match check {
            "ioc-litellm" => Rule {
                check,
                id: "HK-LITELLM-001",
                summary: "t",
            },
            _ => Rule {
                check,
                id: "HK-ENV-001",
                summary: "t",
            },
        };
        Finding::new(
            rule,
            "t",
            "l",
            severity,
            Lifetime::Unknown,
            Access::Unknown,
            "f",
        )
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(&[]), Verdict::Clean);
        assert_eq!(
            verdict(&[finding("env", Severity::High)]),
            Verdict::Clean,
            "a credential is not an indicator"
        );
        assert_eq!(
            verdict(&[finding("ioc-litellm", Severity::Medium)]),
            Verdict::Exposed
        );
        assert_eq!(
            verdict(&[
                finding("ioc-litellm", Severity::Medium),
                finding("ioc-litellm", Severity::High)
            ]),
            Verdict::Compromised
        );
        assert_eq!(
            verdict(&[finding("ioc-litellm", Severity::Info)]),
            Verdict::Clean
        );
    }

    #[test]
    fn sets_parse_and_have_sources() {
        assert_eq!(parse_set("black-october"), Some(Set::BlackOctober));
        assert_eq!(parse_set("nope"), None);
        for set in Set::ALL {
            assert!(!set.advisories().is_empty());
            assert!(
                set.advisories()
                    .iter()
                    .all(|a| a.url.starts_with("https://"))
            );
            assert!(!set.checks().is_empty());
            assert!(Incident { set }.disclaimer().contains(set.as_of()));
        }
    }
}
