use anyhow::{bail, Result};
use serde_json::json;

use crate::core::{
    output::{emit_many, Event},
    registry_client::RegistryClient,
    store::{LocalStore, StoredAudit},
};
use crate::CommonFlags;

pub fn run(target: String, sandbox: String, flags: CommonFlags) -> Result<()> {
    if sandbox != "gvisor" {
        bail!("only --sandbox gvisor is supported");
    }
    let store = LocalStore::from_env()?;
    let (name, version) = resolve_target(&store, &target)?;
    let registry = RegistryClient::from_env()?;

    let audit = if flags.dry_run || flags.plan {
        registry.latest_audit(&name, &version).ok()
    } else {
        Some(registry.trigger_audit(&name, &version, "gvisor")?)
    };
    let stored_audit = audit_from_value(audit.as_ref());
    if let Some(stored_audit) = &stored_audit {
        if let Ok(mut package) = store.read_package(&name, Some(&version)) {
            package.risk_score = stored_audit.risk_score.min(100) as u8;
            package.state = stored_audit
                .release_state_applied
                .clone()
                .unwrap_or_else(|| state_for_verdict(&stored_audit.verdict).to_string());
            package.verified_audit = Some(stored_audit.clone());
            store.write_package(&package)?;
        }
    }

    let verdict = stored_audit
        .as_ref()
        .map(|audit| audit.verdict.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let score = stored_audit
        .as_ref()
        .map(|audit| audit.risk_score)
        .unwrap_or(0);
    emit_many(
        flags.output_mode(),
        "Rivet Verify",
        vec![
            format!("Package: {name}@{version}"),
            "Sandbox: gvisor/runsc".to_string(),
            format!("Verified audit: {}", stored_audit.is_some()),
            format!("Verdict: {verdict}"),
            format!("Risk score: {score}"),
        ],
        vec![
            Event::new("audit.started")
                .with("package", name.clone())
                .with("version", version.clone())
                .with("sandbox", "gvisor"),
            Event::new("audit.completed")
                .with("package", name.clone())
                .with("version", version.clone())
                .with("verdict", verdict.clone())
                .with("risk_score", score),
        ],
        json!({
            "package": name,
            "version": version,
            "sandbox": "gvisor/runsc",
            "audit": audit,
        }),
    )
}

pub fn audit_from_value(value: Option<&serde_json::Value>) -> Option<StoredAudit> {
    let value = value?;
    let reasons = value
        .get("reasons")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let suggested_actions = value
        .get("suggested_actions")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    Some(StoredAudit {
        id: value
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        status: value
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        sandbox_runtime: value
            .get("sandbox_runtime")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("gvisor/runsc")
            .to_string(),
        agent_image: value
            .get("agent_image")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        verdict: value
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        risk_score: value
            .get("risk_score")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            .min(100) as u16,
        reasons,
        suggested_actions,
        signature: value
            .get("signature")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string(),
        cost_cents: value
            .get("cost_cents")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(50) as u16,
        release_state_applied: value
            .get("release_state_applied")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
    })
}

pub fn resolve_target(store: &LocalStore, target: &str) -> Result<(String, String)> {
    if let Ok(command) = store.read_command(target) {
        return Ok((command.package, command.version));
    }
    if let Some((name, version)) = parse_package_version(target) {
        return Ok((name, version));
    }
    let package = store.read_package(target, None)?;
    Ok((package.name, package.version))
}

fn parse_package_version(spec: &str) -> Option<(String, String)> {
    if spec.starts_with('@') {
        let slash_index = spec.find('/')?;
        let relative_version_index = spec[slash_index + 1..].rfind('@')?;
        let index = slash_index + 1 + relative_version_index;
        return Some((spec[..index].to_string(), spec[index + 1..].to_string()));
    }
    let (name, version) = spec.rsplit_once('@')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn state_for_verdict(verdict: &str) -> &'static str {
    match verdict {
        "low" => "active",
        "medium" => "warned",
        "high" => "quarantined",
        "critical" => "blocked",
        _ => "quarantined",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::audit_from_value;

    #[test]
    fn parses_stored_audit_from_registry_json() {
        let audit = audit_from_value(Some(&json!({
            "id": "audit-1",
            "status": "passed",
            "sandbox_runtime": "gvisor/runsc",
            "agent_image": "rivet-audit-agent:local",
            "verdict": "medium",
            "risk_score": 42,
            "reasons": ["install script"],
            "suggested_actions": ["warn_user"],
            "signature": "hmac-sha256:test",
            "cost_cents": 50,
            "release_state_applied": "warned"
        })))
        .unwrap();
        assert_eq!(audit.verdict, "medium");
        assert_eq!(audit.risk_score, 42);
        assert_eq!(audit.release_state_applied.as_deref(), Some("warned"));
    }
}
