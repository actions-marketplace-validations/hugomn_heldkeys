//! `cloud-metadata`: can this machine reach the cloud instance metadata service?
//!
//! On AWS, GCP, Azure and most other clouds, 169.254.169.254 hands out the
//! instance's role credentials to any local process. We only test whether a
//! TCP connection opens: no HTTP request, no payload, 300 ms timeout. This is
//! the only network access heldkeys makes by default, and it is skipped
//! when `HELDKEYS_NO_NET=1` (tests set it).

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};

pub struct CloudMetadataCheck;

const ID: &str = "cloud-metadata";

const REACHABLE: Rule = Rule {
    check: ID,
    id: "HK-META-001",
    summary: "Cloud instance metadata endpoint reachable (context)",
};

const RULES: &[Rule] = &[REACHABLE];

/// The link-local metadata address used by AWS, GCP, Azure, DigitalOcean and others.
const METADATA_ADDR: [u8; 4] = [169, 254, 169, 254];
const TIMEOUT: Duration = Duration::from_millis(300);

impl Check for CloudMetadataCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Whether the cloud metadata endpoint 169.254.169.254 is reachable (one TCP connect, 300 ms timeout, no payload)."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        if !ctx.network_allowed() || !metadata_reachable() {
            return Vec::new();
        }
        vec![
            Finding::new(
                REACHABLE,
                "Cloud metadata endpoint is reachable",
                "169.254.169.254:80",
                Severity::Info,
                Lifetime::ShortLived,
                Access::Unknown,
                "Block 169.254.169.254 from the agent's sandbox, or require IMDSv2 with a hop limit of 1.",
            )
            .with_detail("any process here may be able to fetch the instance role's credentials"),
        ]
    }
}

fn metadata_reachable() -> bool {
    let addr = SocketAddr::from((METADATA_ADDR, 80));
    // The stream is dropped (closed) right away; nothing is written to it.
    TcpStream::connect_timeout(&addr, TIMEOUT).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::fixture_ctx;

    #[test]
    fn never_probes_in_unit_tests() {
        // network_allowed() is false under cfg(test), so this returns at once.
        assert!(CloudMetadataCheck.run(&fixture_ctx("empty")).is_empty());
    }
}
