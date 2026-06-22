use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::json;

use crate::core::{
    byok::ByokConfig,
    output::{emit_many, Event, OutputMode},
    registry_client::RegistryClient,
    risk::{combine_risk, RiskLevel},
    store::{LocalStore, StoredPackage},
};
use crate::CommonFlags;

pub fn run(package: String, provider: String, flags: CommonFlags) -> Result<()> {
    let config = ByokConfig::read()?;
    if !config.providers.contains_key(&provider) {
        bail!("BYOK provider {provider} is not configured; run `rivet byok add {provider}`");
    }
    let (name, version) = parse_package_version(&package)?;
    let store = LocalStore::from_env()?;
    let stored = store.read_package(&name, Some(&version)).ok();
    let result = deterministic_eval(&name, stored.as_ref());
    let privacy = privacy_summary();

    if flags.output_mode() != OutputMode::Json || flags.dry_run || flags.plan {
        emit_many(
            flags.output_mode(),
            "Agentic Security Eval",
            vec![
                format!("Provider: {provider}"),
                format!("Package: {name}@{version}"),
                "Will send: manifest, dependency summary, executable metadata, install scripts, release diff, selected suspicious snippets".to_string(),
                "Will not send: .env files, registry tokens, git credentials, private project files, shell history".to_string(),
                format!("Eval verdict: {}", result.verdict),
                format!("Risk score: {}", result.risk_score),
            ],
            vec![
                Event::new("eval.started")
                    .with("provider", provider.clone())
                    .with("package", name.clone())
                    .with("version", version.clone()),
                Event::new("eval.completed")
                    .with("verdict", result.verdict.clone())
                    .with("risk_score", result.risk_score),
            ],
            json!({
                "result": result,
                "privacy_summary": privacy,
            }),
        )?;
    }
    if flags.dry_run || flags.plan {
        return Ok(());
    }

    let registry = RegistryClient::from_env()?;
    let request = EvalRequest {
        package: name,
        version,
        provider,
        model: "deterministic-stub".to_string(),
        verdict: result.verdict.clone(),
        risk_score: result.risk_score,
        reasons: result.reasons.clone(),
        suggested_actions: result.suggested_actions.clone(),
        privacy_summary: privacy.clone(),
    };
    let response = registry.post("/v1/evals", &request)?;
    if flags.output_mode() == OutputMode::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "result": result,
                "privacy_summary": privacy,
                "registry_response": response,
            }))?
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct EvalResult {
    verdict: String,
    risk_score: u16,
    reasons: Vec<String>,
    suggested_actions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EvalRequest {
    #[serde(rename = "package")]
    package: String,
    version: String,
    provider: String,
    model: String,
    verdict: String,
    risk_score: u16,
    reasons: Vec<String>,
    suggested_actions: Vec<String>,
    privacy_summary: serde_json::Value,
}

fn deterministic_eval(name: &str, package: Option<&StoredPackage>) -> EvalResult {
    let (base_score, base_reasons) = package
        .map(|package| (package.risk_score, package.risk_reasons.clone()))
        .unwrap_or_else(|| {
            (
                20,
                vec!["package metadata not available locally".to_string()],
            )
        });
    let risk = combine_risk(base_score, &base_reasons, name);
    let verdict = match risk.level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
    .to_string();
    let suggested_actions = match risk.level {
        RiskLevel::Low => vec!["allow_install".to_string()],
        RiskLevel::Medium => vec!["warn_user".to_string(), "request_audit".to_string()],
        RiskLevel::High => vec!["publish_warned".to_string(), "request_audit".to_string()],
        RiskLevel::Critical => vec![
            "quarantine_release".to_string(),
            "block_install".to_string(),
        ],
    };
    EvalResult {
        verdict,
        risk_score: risk.score as u16,
        reasons: risk.reasons,
        suggested_actions,
    }
}

fn privacy_summary() -> serde_json::Value {
    json!({
        "will_send": [
            "package manifest",
            "dependency summary",
            "executable metadata",
            "install scripts",
            "release diff",
            "selected suspicious snippets"
        ],
        "will_not_send": [
            ".env files",
            "registry tokens",
            "git credentials",
            "private project files",
            "shell history"
        ]
    })
}

fn parse_package_version(spec: &str) -> Result<(String, String)> {
    if spec.starts_with('@') {
        if let Some(slash_index) = spec.find('/') {
            if let Some(relative_version_index) = spec[slash_index + 1..].rfind('@') {
                let index = slash_index + 1 + relative_version_index;
                return Ok((spec[..index].to_string(), spec[index + 1..].to_string()));
            }
        }
    } else if let Some((name, version)) = spec.rsplit_once('@') {
        if !name.is_empty() && !version.is_empty() {
            return Ok((name.to_string(), version.to_string()));
        }
    }
    bail!("package must be in name@version form")
}

#[cfg(test)]
mod tests {
    use super::{deterministic_eval, parse_package_version};

    #[test]
    fn deterministic_eval_returns_stub_verdict() {
        let result = deterministic_eval("demo", None);
        assert_eq!(result.verdict, "low");
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason.contains("metadata")));
    }

    #[test]
    fn parses_eval_package_spec() {
        assert_eq!(
            parse_package_version("demo@0.1.0").unwrap(),
            ("demo".into(), "0.1.0".into())
        );
    }
}
