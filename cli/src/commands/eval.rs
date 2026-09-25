use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::json;

use crate::core::{
    attestation::Statement,
    byok::ByokConfig,
    output::{emit_many, Event, OutputMode},
    registry_client::RegistryClient,
    risk::namesquat,
    store::LocalStore,
    trust,
};
use crate::CommonFlags;

pub fn run(package: String, provider: String, flags: CommonFlags) -> Result<()> {
    let config = ByokConfig::read()?;
    if !config.providers.contains_key(&provider) {
        bail!("BYOK provider {provider} is not configured; run `rivet byok add {provider}`");
    }
    let (name, version) = parse_package_version(&package)?;
    let registry = RegistryClient::from_env()?;
    let store = LocalStore::open(registry.base_url())?;
    let key = trust::trusted_key(&registry)?;
    let stored = store
        .cached_attestation(&name, &version, &key)?
        .map(|(statement, _)| statement);
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

/// Advisory local eval (BYOK stub). It starts from the registry's signed
/// audit when one is cached; it never overrides the registry verdict.
fn deterministic_eval(name: &str, statement: Option<&Statement>) -> EvalResult {
    let (mut score, mut reasons) = statement
        .and_then(|s| s.audit.as_ref())
        .map(|audit| (audit.risk_score, audit.reasons.clone()))
        .unwrap_or_else(|| {
            (
                20,
                vec!["package metadata not available locally".to_string()],
            )
        });
    if let Some(squat) = namesquat(name) {
        score = score.saturating_add(30);
        reasons.push(format!(
            "possible namesquat: confusable with {}",
            squat.confusable_with
        ));
    }
    let score = score.min(100);
    let verdict = match score {
        0..=29 => "low",
        30..=59 => "medium",
        60..=79 => "high",
        _ => "critical",
    };
    let suggested_actions = match verdict {
        "low" => vec!["allow_install".to_string()],
        "medium" => vec!["warn_user".to_string(), "request_audit".to_string()],
        "high" => vec!["publish_warned".to_string(), "request_audit".to_string()],
        _ => vec![
            "quarantine_release".to_string(),
            "block_install".to_string(),
        ],
    };
    EvalResult {
        verdict: verdict.to_string(),
        risk_score: score,
        reasons,
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
