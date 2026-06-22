use anyhow::Result;
use serde_json::json;

use crate::core::{
    byok::{default_provider, ByokConfig},
    output::{emit, Event},
};
use crate::{ByokCommand, CommonFlags};

pub fn run(command: ByokCommand) -> Result<()> {
    match command {
        ByokCommand::Add { provider, flags } => add(provider, flags),
        ByokCommand::List { flags } => list(flags),
    }
}

fn add(provider: String, flags: CommonFlags) -> Result<()> {
    let mut config = ByokConfig::read()?;
    let provider_config = default_provider(&provider);
    let configured = !(flags.dry_run || flags.plan);
    if configured {
        config
            .providers
            .insert(provider.clone(), provider_config.clone());
        config.write()?;
    }
    emit(
        flags.output_mode(),
        "Rivet BYOK",
        vec![
            format!("Provider: {provider}"),
            format!("Key env: {}", provider_config.key_env),
            format!("Endpoint: {}", provider_config.endpoint),
        ],
        Event::new("eval.started")
            .with("provider", provider.clone())
            .with("configured", configured),
        json!({
            "provider": provider,
            "config": provider_config,
            "configured": configured,
        }),
    )
}

fn list(flags: CommonFlags) -> Result<()> {
    let config = ByokConfig::read()?;
    let providers = config.providers.keys().cloned().collect::<Vec<_>>();
    emit(
        flags.output_mode(),
        "Rivet BYOK Providers",
        providers
            .iter()
            .map(|provider| format!("Provider: {provider}"))
            .collect(),
        Event::new("eval.started").with("providers", providers.clone()),
        json!({"providers": config.providers}),
    )
}
