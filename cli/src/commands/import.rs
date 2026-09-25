use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::json;

use crate::commands::install::materialize;
use crate::core::{
    attestation::Statement,
    output::{emit_many, Event},
    policy::Policy,
    resolver::{split_name_version, Resolver},
    session::Session,
    store::StoredCommand,
};
use crate::CommonFlags;

/// `rivet import npm:<name>[@range]`: installs an npm package and its full
/// dependency tree as a global tool, verified and ready for `rivet run`.
pub fn run(spec: String, flags: CommonFlags) -> Result<()> {
    let bare = spec.strip_prefix("npm:").unwrap_or(&spec);
    let (name, range) = split_name_version(bare);
    let range = range.unwrap_or_else(|| "latest".to_string());
    let policy = Policy::new(None, &flags);
    let session = Session::open()?;
    let resolver = Resolver {
        client: &session.client,
        key: &session.key,
        policy: &policy,
        locked: None,
    };
    let graph = resolver.resolve(&BTreeMap::from([(name.clone(), range.clone())]))?;
    let root_id = graph.roots[&name].package.clone();
    let root = graph.nodes[&root_id].statement.clone();

    let tool_dir = session.store.tool_dir(&root.name, &root.version);
    let mut commands = Vec::new();
    let mut script_failures = Vec::new();
    let mut lines = describe(&root);
    lines.push(format!("Dependencies: {}", graph.nodes.len() - 1));
    for warning in &graph.warnings {
        lines.push(format!("Warning: {warning}"));
    }
    for note in &graph.notes {
        lines.push(format!("Note: {note}"));
    }
    if !graph.other_platforms.is_empty() {
        lines.push(format!(
            "Skipped {} optional packages built for other platforms",
            graph.other_platforms.len()
        ));
    }

    if !(flags.dry_run || flags.plan) {
        std::fs::create_dir_all(&tool_dir)?;
        let (state, report) = materialize(&session, &policy, &tool_dir, &graph, &flags)
            .with_context(|| format!("install {}", root.id()))?;
        for command in state.bins.keys() {
            session.store.write_command(&StoredCommand {
                command: command.clone(),
                package: root.name.clone(),
                version: root.version.clone(),
                tool_dir: tool_dir.clone(),
            })?;
            commands.push(command.clone());
        }
        for skipped in &report.scripts_skipped {
            lines.push(format!(
                "Install script not run: {skipped} (use --allow-scripts to run it sandboxed)"
            ));
        }
        for failure in &report.script_failures {
            lines.push(format!("Install script failed: {failure}"));
        }
        script_failures = report.script_failures;
        lines.push(format!(
            "Commands: {}",
            if commands.is_empty() {
                "none".to_string()
            } else {
                commands.join(", ")
            }
        ));
    }

    emit_many(
        flags.output_mode(),
        "Rivet Import",
        lines,
        vec![
            Event::new("artifact.verified")
                .with("name", root.name.clone())
                .with("version", root.version.clone())
                .with("tree_digest", root.artifact.tree_digest.clone()),
            Event::new("dependency.resolved")
                .with("name", root.name.clone())
                .with("packages", graph.nodes.len()),
        ],
        json!({
            "package": root,
            "packages": graph.nodes.keys().collect::<Vec<_>>(),
            "commands": commands,
            "warnings": graph.warnings,
            "notes": graph.notes,
            "tool_dir": tool_dir,
            "script_failures": script_failures,
        }),
    )
}

/// Human summary of a verified statement, shared with inspect/verify.
pub fn describe(statement: &Statement) -> Vec<String> {
    let mut lines = vec![
        format!("Package: {}", statement.id()),
        format!("Source: {}", statement.source),
        format!("State: {}", statement.state),
        format!("Artifact: {}", short(&statement.artifact.hash)),
        format!("Tree digest: {}", short(&statement.artifact.tree_digest)),
        format!(
            "Publisher: {}",
            if statement.publisher.is_empty() {
                "unknown"
            } else {
                &statement.publisher
            }
        ),
        format!("Signed statement: valid until {}", statement.expires_at),
    ];
    if let Some(upstream) = &statement.upstream {
        lines.push(format!(
            "Upstream integrity: {} (verified by registry)",
            upstream.integrity_algorithm
        ));
        if !upstream.published_at.is_empty() {
            lines.push(format!("Published upstream: {}", upstream.published_at));
        }
        for mismatch in &upstream.manifest_mismatch {
            lines.push(format!("Manifest confusion: {mismatch}"));
        }
    }
    match &statement.provenance {
        Some(p) if p.status == "verified" => {
            lines.push(format!(
                "Provenance: verified ({} @ {})",
                p.source_repo,
                short(&p.source_commit)
            ));
            if p.repo_matches == Some(false) {
                lines.push(format!(
                    "Warning: provenance repo differs from declared {}",
                    p.declared_repo
                ));
            }
        }
        Some(p) => lines.push(format!(
            "Provenance: {}{}",
            p.status,
            if p.detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", p.detail)
            }
        )),
        None => lines.push("Provenance: absent".into()),
    }
    match &statement.audit {
        Some(audit) => {
            lines.push(format!(
                "Audit: {} (score {}, {})",
                audit.verdict, audit.risk_score, audit.sandbox_runtime
            ));
            for reason in &audit.reasons {
                lines.push(format!("  - {reason}"));
            }
            if !audit.capabilities.is_empty() {
                lines.push(format!("Capabilities: {}", audit.capabilities.join(", ")));
            }
            if let Some(diff) = &audit.diff {
                let mut changes = Vec::new();
                if !diff.new_capabilities.is_empty() {
                    changes.push(format!(
                        "new capabilities {}",
                        diff.new_capabilities.join(", ")
                    ));
                }
                if !diff.new_install_scripts.is_empty() {
                    changes.push(format!(
                        "new install scripts {}",
                        diff.new_install_scripts.join(", ")
                    ));
                }
                if !diff.added_dependencies.is_empty() {
                    changes.push(format!("added deps {}", diff.added_dependencies.join(", ")));
                }
                if diff.publisher_changed {
                    changes.push("publisher changed".into());
                }
                if diff.provenance_regressed {
                    changes.push("provenance dropped".into());
                }
                lines.push(format!(
                    "Changes since {}: {}",
                    diff.previous_version,
                    if changes.is_empty() {
                        "none flagged".to_string()
                    } else {
                        changes.join("; ")
                    }
                ));
            }
        }
        None => lines.push("Audit: none".into()),
    }
    if !statement.manifest.install_scripts.is_empty() {
        lines.push(format!(
            "Install scripts: {}",
            statement
                .manifest
                .install_scripts
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !statement.revoke_reason.is_empty() {
        lines.push(format!("Revoke reason: {}", statement.revoke_reason));
    }
    lines
}

fn short(value: &str) -> String {
    let (prefix, rest) = value
        .rsplit_once(':')
        .or_else(|| value.split_once('-'))
        .unwrap_or(("", value));
    let head: String = rest.chars().take(16).collect();
    if prefix.is_empty() {
        head
    } else {
        format!("{prefix}:{head}…")
    }
}
