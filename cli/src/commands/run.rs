use std::{
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::core::{
    error::Failure,
    installed::Verifier,
    linker::{self, BinTarget, InstalledState},
    manifest::Manifest,
    output::{emit, progress, Event, OutputMode},
    policy::Policy,
    project::{Project, ProjectLock},
    sandbox::{self, SandboxSpec},
    session::Session,
};
use crate::CommonFlags;

pub struct Located {
    pub root: PathBuf,
    pub state: InstalledState,
    pub target: BinTarget,
    pub manifest: Option<Manifest>,
}

/// Finds `command` in the project (`--project` or the current directory) or
/// among globally imported tools.
pub fn locate(project: Option<&Path>, command: &str, session: &Session) -> Result<Located> {
    let cwd = std::env::current_dir()?;
    let explicit = project.is_some();
    let project_root = project.map(Path::to_path_buf).unwrap_or(cwd);
    if let Some(state) = linker::read_state(&project_root)? {
        if let Some(target) = state.bins.get(command).cloned() {
            let manifest = if project_root.join("package.json").exists()
                || project_root.join("rivet.toml").exists()
            {
                Some(Project::read(&project_root)?.manifest)
            } else {
                None
            };
            return Ok(Located {
                root: project_root,
                state,
                target,
                manifest,
            });
        }
    }
    if explicit {
        bail!("{command} is not installed in {}", project_root.display());
    }
    let stored = session.store.read_command(command).with_context(|| {
        format!("command not found: {command} (try `rivet import npm:{command}`)")
    })?;
    let state = linker::read_state(&stored.tool_dir)?
        .with_context(|| format!("tool install for {command} is missing; re-run `rivet import`"))?;
    let target = state
        .bins
        .get(command)
        .cloned()
        .with_context(|| format!("{command} is not exposed by {}", stored.package))?;
    Ok(Located {
        root: stored.tool_dir,
        state,
        target,
        manifest: None,
    })
}

pub fn run(
    project: Option<PathBuf>,
    command: String,
    args: Vec<String>,
    flags: CommonFlags,
) -> Result<()> {
    let session = Session::open()?;
    let mut located = locate(project.as_deref(), &command, &session)?;
    let _guard = ProjectLock::acquire(&located.root)?;
    located.state = linker::read_state(&located.root)?.context("installation disappeared")?;
    if located.manifest.is_some() {
        located.manifest = Some(Project::read(&located.root)?.manifest);
    }
    let policy = Policy::new(
        located.manifest.as_ref().and_then(|m| m.policy.as_ref()),
        &flags,
    );
    let report = Verifier {
        store: &session.store,
        client: &session.client,
        key: &session.key,
        policy: &policy,
    }
    .verify(&located.root, &located.state)?;
    let statement = report
        .statements
        .get(&located.target.package)
        .context("target package missing from verified closure")?;

    let permissions = statement
        .executables
        .iter()
        .find(|e| e.command == command)
        .and_then(|e| e.permissions.clone())
        .unwrap_or_else(|| json!({}));
    let declared_fs = string_list(&permissions, "filesystem");
    let declared_env = string_list(&permissions, "env");
    // A package declaring network use is a request, not a grant: the user
    // opts in per command with --allow-network or [policy].allow_network.
    let wants_network = permissions.get("network").and_then(|v| v.as_bool()) == Some(true);
    let network = flags.allow_network || policy.allow_network.contains(&command);
    if wants_network && !network && !flags.quiet {
        eprintln!("rivet: {command} declares network access; it stays off unless you pass --allow-network");
    }
    if !flags.quiet {
        for name in &declared_env {
            if !flags.allow_env.contains(name) {
                eprintln!(
                    "rivet: {command} requests {name}; pass --allow-env {name} to share its value"
                );
            }
        }
    }

    let cwd = std::env::current_dir()?;
    // Running from $HOME (or above it) must not expose the whole home
    // directory; the user can still grant paths explicitly.
    let cwd_is_home = dirs::home_dir()
        .and_then(|home| home.canonicalize().ok())
        .zip(cwd.canonicalize().ok())
        .is_some_and(|(home, cwd)| home.starts_with(&cwd));
    if cwd_is_home && !flags.quiet {
        eprintln!("rivet: not granting access to {} (home directory); use --allow-write or run from a project directory", cwd.display());
    }
    let mut write_paths: Vec<PathBuf> = flags.allow_write.clone();
    if declared_fs.iter().any(|p| p == "write:cwd") && !cwd_is_home {
        write_paths.push(cwd.clone());
    }
    let mut read_paths = vec![located.root.clone()];
    if !cwd_is_home {
        read_paths.push(cwd.clone());
    }
    let package_dir = linker::package_path(&located.root, &located.target.package, &statement.name);
    linker::validate_entry(&located.target.entry)?;
    let entry = package_dir.join(&located.target.entry);
    if !entry.starts_with(&package_dir) {
        bail!(
            "executable entry escapes its package: {}",
            located.target.entry
        );
    }
    let (program, program_args) = invocation(&entry, &args)?;
    let control_paths = [located.root.as_path(), cwd.as_path()]
        .into_iter()
        .flat_map(|root| {
            [
                root.join("rivet.toml"),
                root.join("package.json"),
                root.join("package-lock.json"),
                root.join(".rivet"),
                root.join("rivet.lock"),
                // Node can resolve packages and shims anywhere below this tree.
                // Protect the parent itself so it cannot be renamed, edited under
                // its new name, then moved back after the sandbox exits.
                root.join("node_modules"),
            ]
        })
        .collect();
    let spec = SandboxSpec {
        cwd: cwd.clone(),
        read_paths,
        write_paths,
        protect_paths: control_paths,
        network,
        env: vec![],
        allow_env: flags.allow_env.clone(),
        unsafe_no_sandbox: flags.unsafe_no_sandbox,
        allow_store_tools: false,
        store_home: Some(session.store.home.clone()),
    };
    let mut prepared = sandbox::prepare(&spec, &program, &program_args)?;

    let summary = format!(
        "{} verified ({} packages{}), audit {} [{}], provenance {}, sandbox {}, network {}",
        statement.id(),
        report.statements.len(),
        if report.online { "" } else { ", offline" },
        statement.verdict(),
        statement.audit.as_ref().map(|a| a.risk_score).unwrap_or(0),
        statement.provenance_status(),
        prepared.backend.describe(),
        if network { "on" } else { "off" },
    );
    let mut result = json!({
        "command": command, "args": args, "package": statement.id(),
        "packages_verified": report.statements.len(), "verify_timings_ms": report.timings,
        "online": report.online, "warnings": report.warnings,
        "sandbox": prepared.backend.describe(), "network": network, "entry": entry,
        "planned": flags.dry_run || flags.plan,
    });
    if flags.dry_run || flags.plan {
        return emit(
            flags.output_mode(),
            "Rivet Run Plan",
            vec![summary],
            Event::new("plan.created").with("command", &command),
            result,
        );
    }
    if flags.verbose && flags.output_mode() == OutputMode::Human {
        eprintln!("rivet: {summary}");
    }
    if !flags.quiet && flags.output_mode() == OutputMode::Human {
        for warning in &report.warnings {
            eprintln!("rivet: warning: {warning}");
        }
    }
    progress(
        flags.output_mode(),
        Event::new("run.started")
            .with("command", &command)
            .with("packages_verified", report.statements.len()),
    )?;
    execute(&mut prepared, &flags)?;
    result["exit_code"] = 0.into();
    if flags.output_mode() != OutputMode::Human {
        emit(
            flags.output_mode(),
            "Rivet Run",
            vec![],
            Event::new("run.completed")
                .with("command", &command)
                .with("exit_code", 0),
            result,
        )?;
    }
    Ok(())
}

fn execute(prepared: &mut sandbox::Prepared, flags: &CommonFlags) -> Result<()> {
    if flags.output_mode() != OutputMode::Human {
        // Keep stdout exclusively machine-readable without buffering unlimited
        // child output in memory. Tool output remains live on stderr.
        prepared.command.stdout(Stdio::from(std::io::stderr()));
    }
    let status = prepared
        .command
        .status()
        .context("start sandboxed process")?;
    if !status.success() {
        use std::os::unix::process::ExitStatusExt;
        let mut failure = Failure::new(
            "PROCESS_FAILED",
            format!("sandboxed command exited with {status}"),
            "Inspect the command output on stderr and fix the reported failure.",
        );
        failure.exit_code = status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
        bail!(failure);
    }
    Ok(())
}

/// Project scripts take precedence for `run`; `exec` and generated shims always
/// select a verified binary and cannot be redirected by a same-named script.
pub fn run_or_script(
    project: Option<PathBuf>,
    command: String,
    args: Vec<String>,
    flags: CommonFlags,
) -> Result<()> {
    let root = project.clone().unwrap_or(std::env::current_dir()?);
    if root.join("package.json").exists() || root.join("rivet.toml").exists() {
        let project_manifest = Project::read(&root)?;
        if project_manifest.manifest.scripts.contains_key(&command) {
            return run_script(&root, &command, &args, &flags);
        }
    }
    run(project, command, args, flags)
}

fn run_script(root: &Path, name: &str, args: &[String], flags: &CommonFlags) -> Result<()> {
    let root = root.canonicalize()?;
    let _guard = ProjectLock::acquire(&root)?;
    let project = Project::read(&root)?;
    let script = project
        .manifest
        .scripts
        .get(name)
        .context("project script disappeared")?;
    let session = Session::open()?;
    let state = linker::read_state(&root)?.ok_or_else(|| {
        Failure::new(
            "NOT_INSTALLED",
            "project dependencies are not installed",
            "Run rivet install first, including for projects with no dependencies.",
        )
    })?;
    let policy = Policy::new(project.manifest.policy.as_ref(), flags);
    let report = Verifier {
        store: &session.store,
        client: &session.client,
        key: &session.key,
        policy: &policy,
    }
    .verify(&root, &state)?;
    // Never execute mutable .bin wrappers inside a sandbox: build direct entry
    // wrappers from the verified receipt, with the entire installed tree checked.
    let bins = tempfile::Builder::new()
        .prefix("rivet-script-bins-")
        .tempdir()?;
    let bin_path = bins.path().canonicalize()?;
    for (command, target) in &state.bins {
        linker::validate_command(command)?;
        linker::validate_entry(&target.entry)?;
        let statement = report
            .statements
            .get(&target.package)
            .context("binary missing from verified graph")?;
        let entry =
            linker::package_path(&root, &target.package, &statement.name).join(&target.entry);
        let (program, invocation_args) = invocation(&entry, &[])?;
        let words: Vec<_> = std::iter::once(program.display().to_string())
            .chain(invocation_args)
            .map(|s| linker::shell_quote(&s))
            .collect();
        let path = bin_path.join(command);
        std::fs::write(
            &path,
            format!("#!/bin/sh\nexec {} \"$@\"\n", words.join(" ")),
        )?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555))?;
    }
    let node = sandbox::node_binary()?;
    let network = flags.allow_network || policy.allow_network.contains(name);
    let protect_paths = [
        "package.json",
        "package-lock.json",
        "rivet.toml",
        "rivet.lock",
        "node_modules",
        ".rivet",
    ]
    .map(|p| root.join(p))
    .into_iter()
    .chain(std::iter::once(bin_path.clone()))
    .collect();
    let spec = SandboxSpec {
        cwd: root.clone(),
        read_paths: vec![root.clone(), bin_path.clone()],
        write_paths: flags.allow_write.clone(),
        protect_paths,
        network,
        env: vec![
            (
                "PATH".into(),
                format!(
                    "{}:{}:/usr/bin:/bin",
                    bin_path.display(),
                    node.parent().context("node parent")?.display()
                ),
            ),
            ("npm_lifecycle_event".into(), name.into()),
            (
                "npm_package_name".into(),
                project.manifest.package.name.clone(),
            ),
            (
                "npm_package_version".into(),
                project.manifest.package.version.clone(),
            ),
        ],
        allow_env: flags.allow_env.clone(),
        unsafe_no_sandbox: flags.unsafe_no_sandbox,
        allow_store_tools: false,
        store_home: Some(session.store.home.clone()),
    };
    // The script is project-authored shell code. Extra arguments are shell
    // quoted individually and cannot introduce operators or substitutions.
    let mut command = script.command.clone();
    for arg in args {
        command.push(' ');
        command.push_str(&linker::shell_quote(arg));
    }
    project.assert_unchanged()?;
    let mut prepared = sandbox::prepare(&spec, Path::new("/bin/sh"), &["-c".into(), command])?;
    let mut result = json!({"script": name, "args": args, "packages_verified": report.statements.len(), "online": report.online, "warnings": report.warnings, "sandbox": prepared.backend.describe(), "network": network, "planned": flags.dry_run || flags.plan});
    if flags.dry_run || flags.plan {
        return emit(
            flags.output_mode(),
            "Rivet Script Plan",
            vec![format!("Run {name}: {}", script.command)],
            Event::new("plan.created").with("script", name),
            result,
        );
    }
    if !flags.quiet && flags.output_mode() == OutputMode::Human {
        for warning in &report.warnings {
            eprintln!("rivet: warning: {warning}");
        }
    }
    progress(
        flags.output_mode(),
        Event::new("run.started").with("script", name),
    )?;
    execute(&mut prepared, flags)?;
    result["exit_code"] = 0.into();
    if flags.output_mode() != OutputMode::Human {
        emit(
            flags.output_mode(),
            "Rivet Script",
            vec![],
            Event::new("run.completed")
                .with("script", name)
                .with("exit_code", 0),
            result,
        )?;
    }
    Ok(())
}

fn string_list(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Chooses how to execute an entry: Node for JavaScript (by extension or
/// shebang), direct execution for native binaries and other scripts.
fn invocation(entry: &Path, args: &[String]) -> Result<(PathBuf, Vec<String>)> {
    let mut head = [0u8; 256];
    let read = std::fs::File::open(entry)
        .with_context(|| format!("open {}", entry.display()))?
        .read(&mut head)?;
    let head = &head[..read];
    let ext = entry.extension().and_then(|e| e.to_str()).unwrap_or("");
    let first_line = head.split(|b| *b == b'\n').next().unwrap_or(&[]);
    let node_shebang =
        first_line.starts_with(b"#!") && String::from_utf8_lossy(first_line).contains("node");
    let is_native = head.starts_with(&[0x7f, b'E', b'L', b'F'])
        || head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe]);
    if matches!(ext, "js" | "cjs" | "mjs")
        || node_shebang
        || (!is_native && !first_line.starts_with(b"#!"))
    {
        let mut all = vec![entry.display().to_string()];
        all.extend(args.iter().cloned());
        return Ok((sandbox::node_binary()?, all));
    }
    Ok((entry.to_path_buf(), args.to_vec()))
}
