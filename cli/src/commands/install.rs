use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::core::{
    linker::{InstalledState, LinkReport, Linker},
    lockfile::Lockfile,
    manifest::Manifest,
    output::{emit_many, Event},
    paths::ProjectPaths,
    policy::Policy,
    resolver::{Graph, Resolver},
    session::Session,
};
use crate::CommonFlags;

pub fn run(frozen: bool, flags: CommonFlags) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    if !paths.manifest.exists() {
        bail!("rivet.toml not found; run `rivet init` first");
    }
    let manifest = Manifest::read_from(&paths.manifest)
        .with_context(|| format!("read {}", paths.manifest.display()))?;
    let policy = Policy::new(manifest.policy.as_ref(), &flags);
    let session = Session::open()?;
    let lock = Lockfile::read_current(&paths.lockfile)?;
    if let Some(lock) = &lock {
        if !lock.registry_key.is_empty() && lock.registry_key != session.key.keyid {
            bail!(
                "rivet.lock was signed by registry key {} but {} uses {}; refusing to mix trust roots",
                lock.registry_key,
                session.client.base_url(),
                session.key.keyid
            );
        }
    }
    let resolver = Resolver {
        client: &session.client,
        key: &session.key,
        policy: &policy,
        locked: lock.as_ref(),
    };
    let from_lock = lock
        .as_ref()
        .is_some_and(|l| l.satisfies(&manifest.dependencies));
    let graph = if from_lock {
        resolver.load_lockfile(lock.as_ref().expect("lock present"))?
    } else if frozen {
        bail!("rivet.lock is missing or out of date with rivet.toml (--frozen)");
    } else {
        resolver.resolve(&manifest.dependencies)?
    };

    if flags.dry_run || flags.plan {
        return emit_graph(
            &flags,
            "Rivet Install Plan",
            &manifest.package.name,
            &graph,
            None,
            from_lock,
        );
    }
    let (state, report) = materialize(&session, &policy, &paths.root, &graph, &flags)?;
    state.lock.write_to(&paths.lockfile)?;
    paths.ensure_metadata()?;
    emit_graph(
        &flags,
        "Rivet Install",
        &manifest.package.name,
        &graph,
        Some(&report),
        from_lock,
    )
}

/// Links a verified graph under `root` and caches its attestations.
pub fn materialize(
    session: &Session,
    policy: &Policy,
    root: &Path,
    graph: &Graph,
    flags: &CommonFlags,
) -> Result<(InstalledState, LinkReport)> {
    for node in graph.nodes.values() {
        session
            .store
            .cache_attestation(&node.statement, &node.envelope, &session.key)?;
    }
    let linker = Linker {
        store: &session.store,
        client: &session.client,
        key: &session.key,
        policy,
        unsafe_no_sandbox: flags.unsafe_no_sandbox,
    };
    linker.link(root, graph, session.client.base_url())
}

pub fn emit_graph(
    flags: &CommonFlags,
    title: &str,
    project: &str,
    graph: &Graph,
    report: Option<&LinkReport>,
    from_lock: bool,
) -> Result<()> {
    let mut lines = vec![
        format!("Project: {project}"),
        format!("Packages: {}", graph.nodes.len()),
        format!(
            "Source: {}",
            if from_lock {
                "rivet.lock (re-verified)"
            } else {
                "resolved via registry"
            }
        ),
    ];
    let count = |verdict: &str| {
        graph
            .nodes
            .values()
            .filter(|n| n.statement.verdict() == verdict)
            .count()
    };
    lines.push(format!(
        "Audit verdicts: {} low, {} medium, {} high, {} critical",
        count("low"),
        count("medium"),
        count("high"),
        count("critical")
    ));
    let provenance = graph
        .nodes
        .values()
        .filter(|n| n.statement.provenance_status() == "verified")
        .count();
    lines.push(format!(
        "Verified provenance: {provenance}/{}",
        graph.nodes.len()
    ));
    for (alias, root) in &graph.roots {
        lines.push(format!("  {alias} -> {}", root.package));
    }
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
    if let Some(report) = report {
        for skipped in &report.scripts_skipped {
            lines.push(format!(
                "Install script not run: {skipped} (allow with [policy].allow_scripts)"
            ));
        }
        for ran in &report.scripts_ran {
            lines.push(format!("Install script ran in sandbox: {ran}"));
        }
        for failure in &report.script_failures {
            lines.push(format!("Install script failed: {failure}"));
        }
    }
    emit_many(
        flags.output_mode(),
        title,
        lines,
        vec![
            Event::new("plan.created").with("packages", graph.nodes.len()),
            Event::new("install.completed").with("packages", graph.nodes.len()),
        ],
        json!({
            "project": project,
            "roots": graph.roots,
            "packages": graph.nodes.iter().map(|(id, node)| (id.clone(), json!({
                "state": node.statement.state,
                "verdict": node.statement.verdict(),
                "provenance": node.statement.provenance_status(),
                "dependencies": node.deps,
            }))).collect::<serde_json::Map<_, _>>(),
            "warnings": graph.warnings,
            "notes": graph.notes,
            "other_platforms": graph.other_platforms,
            "scripts_skipped": report.map(|r| r.scripts_skipped.clone()).unwrap_or_default(),
            "script_failures": report.map(|r| r.script_failures.clone()).unwrap_or_default(),
        }),
    )
}
