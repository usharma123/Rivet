use anyhow::Result;
use serde_json::json;

use crate::core::{
    output::{emit, Event},
    registry_client::RegistryClient,
    trust::{pin_path, read_pin, reset_pin},
};
use crate::TrustCommand;

pub fn run(command: TrustCommand) -> Result<()> {
    let client = RegistryClient::from_env()?;
    let registry = client.base_url().to_string();
    match command {
        TrustCommand::Show { flags } => {
            let explicit = std::env::var("RIVET_REGISTRY_PUBKEY")
                .ok()
                .filter(|v| !v.is_empty());
            let pin = read_pin(&registry)?;
            let mut lines = vec![format!("Registry: {registry}")];
            match (&explicit, &pin) {
                (Some(key), _) => lines.push(format!("Key: {key} (from RIVET_REGISTRY_PUBKEY)")),
                (None, Some(pin)) => {
                    lines.push(format!("Key id: {}", pin.keyid));
                    lines.push(format!("Public key: {}", pin.public_key));
                    lines.push(format!("Pinned by: {}", pin.pinned_by));
                }
                (None, None) => lines.push("Key: not pinned yet (pinned on first use)".into()),
            }
            emit(
                flags.output_mode(),
                "Rivet Trust",
                lines,
                Event::new("trust.shown").with("registry", registry.clone()),
                json!({"registry": registry, "pin": pin, "explicit": explicit, "path": pin_path(&registry)?}),
            )
        }
        TrustCommand::Reset { flags } => {
            let removed = reset_pin(&registry)?;
            emit(
                flags.output_mode(),
                "Rivet Trust",
                vec![if removed {
                    format!(
                        "Removed pinned key for {registry}; the next command pins the key it sees"
                    )
                } else {
                    format!("No key pinned for {registry}")
                }],
                Event::new("trust.reset").with("registry", registry.clone()),
                json!({"registry": registry, "removed": removed}),
            )
        }
    }
}
