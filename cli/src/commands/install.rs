use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::core::{
    error::Failure,
    linker::{InstalledState, LinkReport, Linker},
    lockfile::Lockfile,
    output::{emit_many, progress, Event},
    paths::ProjectPaths,
    policy::Policy,
    project::{atomic_write, Project, ProjectLock},
    resolver::{target_key, Graph, Resolver},
    session::Session,
};
use crate::CommonFlags;

#[derive(Default)]
pub enum Edit {
    #[default]
    None,
    Add(Vec<String>, bool),
    Remove(Vec<String>),
    Update,
}

pub fn run(frozen: bool, edit: Edit, flags: CommonFlags) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    let _guard = ProjectLock::acquire(&paths.root)?;
    let mut project = Project::read(&paths.root)?;
    let before = project.manifest.dependencies.clone();
    let editing = !matches!(edit, Edit::None | Edit::Update);
    match &edit {
        Edit::Add(packages, dev) => {
            for package in packages {
                let (name, range) = super::add::parse_dependency(package);
                project.add(&name, &range, *dev)?;
            }
        }
        Edit::Remove(packages) => {
            for package in packages {
                project.remove(package)?;
            }
        }
        _ => {}
    }
    let manifest = &project.manifest;
    progress(
        flags.output_mode(),
        Event::new("install.started")
            .with("project", &manifest.package.name)
            .with("plan", flags.plan || flags.dry_run),
    )?;
    let policy = Policy::new(manifest.policy.as_ref(), &flags);
    let lock_bytes = std::fs::read(&paths.lockfile).ok();
    let lock = Lockfile::read_current(&paths.lockfile)?;
    if frozen
        && !lock
            .as_ref()
            .is_some_and(|l| l.satisfies(&manifest.dependencies))
    {
        bail!(Failure::new("LOCKFILE_STALE", "rivet.lock is missing, unsupported, or out of date with the project manifest", "Run rivet install to create a current lockfile, then commit it before running rivet ci."));
    }
    let session = Session::open()?;
    if let Some(lock) = &lock {
        if !lock.registry.is_empty() && lock.registry != session.client.base_url() {
            bail!(
                "rivet.lock pins registry {} but this session uses {}",
                lock.registry,
                session.client.base_url()
            );
        }
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
        locked: if matches!(edit, Edit::Update) {
            None
        } else {
            lock.as_ref()
        },
    };
    let from_lock = !matches!(edit, Edit::Update)
        && lock
            .as_ref()
            .is_some_and(|l| l.satisfies(&manifest.dependencies));
    progress(
        flags.output_mode(),
        Event::new("resolution.started").with("from_lock", from_lock),
    )?;
    let portable = match &lock {
        Some(lock) if from_lock => lock.clone(),
        _ => resolver.resolve_portable(&manifest.dependencies)?,
    };
    let selected = portable.selected(&target_key()?)?;
    let graph = resolver.load_lockfile(&selected)?;

    progress(
        flags.output_mode(),
        Event::new("resolution.completed").with("packages", graph.nodes.len()),
    )?;
    let changes = serde_json::json!({"before": before, "after": manifest.dependencies});
    if flags.dry_run || flags.plan {
        return emit_graph(
            &flags,
            "Rivet Install Plan",
            &manifest.package.name,
            &graph,
            None,
            from_lock,
            Some(changes),
        );
    }
    for node in graph.nodes.values() {
        session
            .store
            .cache_attestation(&node.statement, &node.envelope, &session.key)?;
    }
    let linker = Linker {
        store: &session.store,
        client: &session.client,
        key: &session.key,
        policy: &policy,
        unsafe_no_sandbox: flags.unsafe_no_sandbox,
    };
    let original_manifest = std::fs::read(&project.path)?;
    let mut wrote_manifest = false;
    let mut wrote_lock = false;
    progress(
        flags.output_mode(),
        Event::new("materialization.started").with("packages", graph.nodes.len()),
    )?;
    let result = linker.link_with_commit(&paths.root, &graph, session.client.base_url(), || {
        project.assert_unchanged()?;
        if std::fs::read(&paths.lockfile).ok() != lock_bytes {
            bail!(Failure::new(
                "PROJECT_CHANGED",
                "rivet.lock changed during installation",
                "Review concurrent changes and retry."
            ));
        }
        if editing {
            project.save()?;
            wrote_manifest = true;
        }
        if !from_lock {
            atomic_write(
                &paths.lockfile,
                &(serde_json::to_string_pretty(&portable)? + "\n").into_bytes(),
            )?;
            wrote_lock = true;
        }
        Ok(())
    });
    let (_state, report) = match result {
        Ok(result) => result,
        Err(error) => {
            if wrote_manifest {
                atomic_write(&project.path, &original_manifest)
                    .context("restore manifest after failed activation")?;
            }
            if wrote_lock {
                if let Some(bytes) = &lock_bytes {
                    atomic_write(&paths.lockfile, bytes)?;
                } else {
                    std::fs::remove_file(&paths.lockfile)?;
                }
            }
            return Err(error);
        }
    };
    emit_graph(
        &flags,
        "Rivet Install",
        &manifest.package.name,
        &graph,
        Some(&report),
        from_lock,
        Some(changes),
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
    changes: Option<serde_json::Value>,
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
        vec![Event::new(if report.is_some() {
            "install.completed"
        } else {
            "plan.created"
        })
        .with("packages", graph.nodes.len())
        .with("changes", &changes)],
        json!({
            "project": project,
            "changed": report.is_some(),
            "from_lock": from_lock,
            "changes": changes,
            "permission_requests": graph.nodes.values().filter(|node| !node.statement.manifest.install_scripts.is_empty()).map(|node| serde_json::json!({"package": node.statement.id(), "scripts": node.statement.manifest.install_scripts.keys().collect::<Vec<_>>()})).collect::<Vec<_>>(),
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
