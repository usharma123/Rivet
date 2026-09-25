//! Install and execution policy. Every decision here is made from a
//! verified registry statement, never from local metadata.

use std::collections::BTreeSet;

use anyhow::{bail, Result};

use super::{attestation::Statement, manifest::PolicySection};
use crate::CommonFlags;

#[derive(Debug, Clone)]
pub struct Policy {
    pub min_release_age_hours: f64,
    pub allow_scripts: BTreeSet<String>,
    pub allow_all_scripts: bool,
    pub allow_network: BTreeSet<String>,
    pub require_provenance: bool,
    pub require_sandbox_audit: bool,
    pub allow_unverified: bool,
    pub unsafe_allow_risk: bool,
    pub unsafe_allow_revoked: bool,
}

/// Why a statement was refused, used to decide whether an optional
/// dependency can be skipped instead of failing the install.
#[derive(Debug)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

impl Policy {
    pub fn new(section: Option<&PolicySection>, flags: &CommonFlags) -> Self {
        let section = section.cloned().unwrap_or_default();
        let min_age = match (flags.allow_fresh, flags.min_age_hours) {
            (true, _) => 0.0,
            (false, Some(hours)) => hours,
            (false, None) => section.min_release_age_hours,
        };
        Self {
            min_release_age_hours: min_age.max(0.0),
            allow_scripts: section.allow_scripts.into_iter().collect(),
            allow_all_scripts: flags.allow_scripts,
            allow_network: section.allow_network.into_iter().collect(),
            require_provenance: section.require_provenance || flags.require_provenance,
            require_sandbox_audit: section.require_sandbox_audit,
            allow_unverified: flags.allow_unverified,
            unsafe_allow_risk: flags.unsafe_allow_risk,
            unsafe_allow_revoked: flags.unsafe_allow_revoked,
        }
    }

    pub fn scripts_allowed(&self, name: &str) -> bool {
        self.allow_all_scripts || self.allow_scripts.contains(name)
    }

    /// Checks a verified statement. `from_lock` permits yanked releases that a
    /// lockfile already pins (cargo semantics). Returns warnings to show.
    pub fn check(&self, statement: &Statement, from_lock: bool) -> Result<Vec<String>> {
        let id = statement.id();
        let mut warnings = Vec::new();
        match statement.state.as_str() {
            "active" => {}
            "warned" => warnings.push(format!(
                "{id} is marked warned by its audit ({})",
                statement
                    .audit
                    .as_ref()
                    .and_then(|a| a.reasons.first().cloned())
                    .unwrap_or_default()
            )),
            "yanked" if from_lock => {
                warnings.push(format!("{id} was yanked: {}", statement.revoke_reason))
            }
            "yanked" => refuse(format!("{id} was yanked: {}", statement.revoke_reason))?,
            "pending" if self.allow_unverified => warnings.push(format!(
                "{id} has not passed a registry audit (--allow-unverified)"
            )),
            "pending" => refuse(format!(
                "{id} has not passed a registry audit; use --allow-unverified to override"
            ))?,
            "quarantined" if self.unsafe_allow_risk => {
                warnings.push(format!("{id} is quarantined (--unsafe-allow-risk)"))
            }
            "quarantined" => refuse(format!(
                "{id} is quarantined ({}); use --unsafe-allow-risk to override",
                audit_reason(statement)
            ))?,
            "blocked" | "revoked" if self.unsafe_allow_revoked => warnings.push(format!(
                "{id} is {} (--unsafe-allow-revoked)",
                statement.state
            )),
            "blocked" | "revoked" => refuse(format!(
                "{id} is {} ({}); use --unsafe-allow-revoked to override",
                statement.state,
                if statement.revoke_reason.is_empty() {
                    audit_reason(statement)
                } else {
                    statement.revoke_reason.clone()
                }
            ))?,
            other => refuse(format!("{id} has unknown release state {other}"))?,
        }
        if statement.audit.is_none() && !self.allow_unverified {
            refuse(format!("{id} has no registry audit"))?;
        }
        if self.require_provenance && statement.provenance_status() != "verified" {
            refuse(format!(
                "{id} has no verified provenance ({}) and policy requires it",
                statement.provenance_status()
            ))?;
        }
        if self.require_sandbox_audit
            && statement.audit.as_ref().map(|a| a.sandbox_runtime.as_str()) != Some("gvisor/runsc")
        {
            refuse(format!(
                "{id} was not audited in the gVisor sandbox and policy requires it"
            ))?;
        }
        if statement.manifest.deprecated {
            warnings.push(format!("{id} is deprecated upstream"));
        }
        Ok(warnings)
    }
}

fn refuse(message: String) -> Result<()> {
    bail!(Refusal(message))
}

fn audit_reason(statement: &Statement) -> String {
    statement
        .audit
        .as_ref()
        .map(|a| a.reasons.join("; "))
        .unwrap_or_else(|| "no audit".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::attestation::tests::sample_statement;

    fn policy(flags: CommonFlags) -> Policy {
        Policy::new(None, &flags)
    }

    #[test]
    fn default_policy_blocks_unsafe_states() {
        let p = policy(CommonFlags::default());
        let mut s = sample_statement("demo", "1.0.0");
        assert!(p.check(&s, false).unwrap().is_empty());
        for state in ["quarantined", "blocked", "revoked", "pending", "yanked"] {
            s.state = state.into();
            let err = p.check(&s, false).unwrap_err();
            assert!(err.downcast_ref::<Refusal>().is_some(), "{state}: {err}");
        }
        s.state = "yanked".into();
        assert_eq!(p.check(&s, true).unwrap().len(), 1);
        s.state = "warned".into();
        assert_eq!(p.check(&s, false).unwrap().len(), 1);
    }

    #[test]
    fn overrides_are_explicit() {
        let mut s = sample_statement("demo", "1.0.0");
        s.state = "quarantined".into();
        let p = policy(CommonFlags {
            unsafe_allow_risk: true,
            ..Default::default()
        });
        assert!(p.check(&s, false).is_ok());
        s.state = "revoked".into();
        assert!(p.check(&s, false).is_err());
    }

    #[test]
    fn provenance_and_cooldown_settings() {
        let s = sample_statement("demo", "1.0.0");
        let section = PolicySection {
            require_provenance: true,
            min_release_age_hours: 24.0,
            ..Default::default()
        };
        let p = Policy::new(Some(&section), &CommonFlags::default());
        assert_eq!(p.min_release_age_hours, 24.0);
        assert!(p.check(&s, false).is_err());
        let fresh = Policy::new(
            Some(&section),
            &CommonFlags {
                allow_fresh: true,
                ..Default::default()
            },
        );
        assert_eq!(fresh.min_release_age_hours, 0.0);
    }
}
