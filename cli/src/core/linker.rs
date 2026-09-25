//! Materializes a verified graph as a node_modules tree Node.js can load.
//!
//! Layout (pnpm-style, supports several versions of one package):
//!   node_modules/<alias>                 -> .rivet/<id>/node_modules/<name>
//!   node_modules/.rivet/<id>/node_modules/<name>/   package files (hardlinks
//!                                                   into the read-only store)
//!   node_modules/.rivet/<id>/node_modules/<dep>     -> sibling package dirs
//!   node_modules/.bin/<cmd>              shim that runs `rivet run`
//!   node_modules/.rivet/state.json       what was installed and verified

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::{
        fs::{symlink, PermissionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::{
    attestation::{Statement, TrustedKey},
    lockfile::Lockfile,
    policy::Policy,
    registry_client::RegistryClient,
    resolver::{validate_package_name, Graph},
    sandbox::{self, SandboxSpec},
    store::{remove_tree, safe_id, LocalStore},
    tree,
};

pub const STATE_FILE: &str = "state.json";

#[cfg(test)]
const SCRIPT_TIMEOUT: Duration = Duration::from_millis(300);
#[cfg(not(test))]
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledState {
    pub lock: Lockfile,
    /// Packages whose allowed install scripts modified them, with the digest
    /// recorded right after the script ran.
    #[serde(default)]
    pub script_modified: BTreeMap<String, String>,
    /// Commands exposed by root packages.
    #[serde(default)]
    pub bins: BTreeMap<String, BinTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinTarget {
    pub package: String,
    pub entry: String,
}

#[derive(Debug, Default)]
pub struct LinkReport {
    pub scripts_ran: Vec<String>,
    pub scripts_skipped: Vec<String>,
    pub script_failures: Vec<String>,
}

pub fn modules_dir(root: &Path) -> PathBuf {
    root.join("node_modules")
}

pub fn state_path(root: &Path) -> PathBuf {
    modules_dir(root).join(".rivet").join(STATE_FILE)
}

pub fn read_state(root: &Path) -> Result<Option<InstalledState>> {
    let path = state_path(root);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_str(&fs::read_to_string(&path)?)
            .with_context(|| format!("read {}", path.display()))?,
    ))
}

/// Directory holding the files of package `id` (name@version).
pub fn package_path(root: &Path, id: &str, name: &str) -> PathBuf {
    modules_dir(root)
        .join(".rivet")
        .join(safe_id(id))
        .join("node_modules")
        .join(name)
}

pub struct Linker<'a> {
    pub store: &'a LocalStore,
    pub client: &'a RegistryClient,
    pub key: &'a TrustedKey,
    pub policy: &'a Policy,
    pub unsafe_no_sandbox: bool,
}

impl Linker<'_> {
    pub fn link(
        &self,
        root: &Path,
        graph: &Graph,
        registry: &str,
    ) -> Result<(InstalledState, LinkReport)> {
        validate_graph_paths(graph)?;
        let modules = modules_dir(root);
        if modules.exists() && !state_path(root).exists() {
            bail!(
                "{} exists but was not created by rivet; remove it before installing",
                modules.display()
            );
        }
        // Build beside the existing installation. A failed fetch, script or
        // link leaves the old tree runnable.
        let staging = tempfile::Builder::new()
            .prefix(".rivet-install-")
            .tempdir_in(root)?;
        let result = self.build(staging.path(), root, graph, registry)?;
        let staged_modules = modules_dir(staging.path());
        let backup = staging.path().join("previous-node_modules");
        if modules.exists() {
            fs::rename(&modules, &backup).context("back up previous install")?;
        }
        if let Err(err) = fs::rename(&staged_modules, &modules) {
            if backup.exists() {
                fs::rename(&backup, &modules)
                    .context("restore previous install after failed swap")?;
            }
            return Err(err).context("activate staged installation");
        }
        if let Err(err) = self.store.write_install_receipt(root, self.key, &result.0) {
            remove_tree(&modules)?;
            if backup.exists() {
                fs::rename(&backup, &modules)
                    .context("restore previous install after receipt failure")?;
            }
            return Err(err).context("record trusted installation");
        }
        if backup.exists() {
            remove_tree(&backup)?;
        }
        Ok(result)
    }

    fn build(
        &self,
        root: &Path,
        final_root: &Path,
        graph: &Graph,
        registry: &str,
    ) -> Result<(InstalledState, LinkReport)> {
        let modules = modules_dir(root);
        fs::create_dir_all(modules.join(".rivet"))?;

        let store_dirs = self.fetch_all(graph)?;
        let mut report = LinkReport::default();
        let mut state = InstalledState {
            lock: graph.to_lockfile(registry, self.key),
            script_modified: BTreeMap::new(),
            bins: BTreeMap::new(),
        };

        for (id, node) in &graph.nodes {
            let name = &node.statement.name;
            let target = package_path(root, id, name);
            let runs_scripts = !node.statement.manifest.install_scripts.is_empty()
                && self.policy.scripts_allowed(name);
            copy_tree(&store_dirs[id], &target, !runs_scripts)?;
            let deps_dir = modules
                .join(".rivet")
                .join(safe_id(id))
                .join("node_modules");
            for (alias, dep) in &node.deps {
                if alias == name {
                    continue;
                }
                let dep_name = &graph.nodes[dep].statement.name;
                let link = deps_dir.join(alias);
                symlink_relative(&package_path(root, dep, dep_name), &link)?;
            }
        }
        for (alias, locked_root) in &graph.roots {
            let Some(node) = graph.nodes.get(&locked_root.package) else {
                continue;
            };
            let link = modules.join(alias);
            symlink_relative(
                &package_path(root, &locked_root.package, &node.statement.name),
                &link,
            )?;
            for (command, entry) in &node.statement.manifest.bin {
                state.bins.insert(
                    command.clone(),
                    BinTarget {
                        package: locked_root.package.clone(),
                        entry: entry.trim_start_matches("./").to_string(),
                    },
                );
            }
        }
        write_bin_shims(root, final_root, &state.bins)?;

        // Install scripts: only for allowed packages, dependencies first, and
        // always inside the sandbox.
        for id in topological(graph) {
            let node = &graph.nodes[&id];
            let scripts = &node.statement.manifest.install_scripts;
            if scripts.is_empty() {
                continue;
            }
            if !self.policy.scripts_allowed(&node.statement.name) {
                report.scripts_skipped.push(format!(
                    "{id} ({})",
                    scripts.keys().cloned().collect::<Vec<_>>().join(", ")
                ));
                continue;
            }
            let dir = package_path(root, &id, &node.statement.name);
            match self.run_scripts(root, &dir, &node.statement) {
                Ok(()) => report.scripts_ran.push(id.clone()),
                Err(err) if node.optional => {
                    report
                        .script_failures
                        .push(format!("optional {id}: {err:#}"));
                    unlink_package(&modules, graph, &id)?;
                    state.lock.packages.remove(&id);
                    for package in state.lock.packages.values_mut() {
                        package.dependencies.retain(|_, dep| dep != &id);
                    }
                    state.lock.roots.retain(|_, root| root.package != id);
                    continue;
                }
                Err(err) => bail!("required install script failed for {id}: {err:#}"),
            }
            state
                .script_modified
                .insert(id.clone(), tree::tree_digest_of_dir(&dir)?);
            make_read_only(&dir)?;
        }

        // Removing a failed optional package can orphan its dependencies.
        for id in state.lock.retain_reachable() {
            remove_tree(&modules.join(".rivet").join(safe_id(&id)))?;
            state.script_modified.remove(&id);
        }

        fs::write(state_path(root), serde_json::to_string_pretty(&state)?)?;
        Ok((state, report))
    }

    fn fetch_all(&self, graph: &Graph) -> Result<BTreeMap<String, PathBuf>> {
        let results = Mutex::new(BTreeMap::new());
        let errors = Mutex::new(Vec::new());
        let work = Mutex::new(graph.nodes.iter());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| loop {
                    let next = work.lock().expect("work").next();
                    let Some((id, node)) = next else { break };
                    match self.store.ensure_package(self.client, &node.statement) {
                        Ok(dir) => {
                            results.lock().expect("results").insert(id.clone(), dir);
                        }
                        Err(err) => errors
                            .lock()
                            .expect("errors")
                            .push(format!("{id}: {err:#}")),
                    }
                });
            }
        });
        let errors = errors.into_inner().expect("errors");
        if !errors.is_empty() {
            bail!("failed to fetch packages:\n  {}", errors.join("\n  "));
        }
        Ok(results.into_inner().expect("results"))
    }

    fn run_scripts(&self, root: &Path, dir: &Path, statement: &Statement) -> Result<()> {
        let network = self.policy.allow_network.contains(&statement.name);
        for lifecycle in ["preinstall", "install", "postinstall"] {
            let Some(script) = statement.manifest.install_scripts.get(lifecycle) else {
                continue;
            };
            let spec = SandboxSpec {
                cwd: dir.to_path_buf(),
                read_paths: vec![modules_dir(root)],
                write_paths: vec![dir.to_path_buf()],
                protect_paths: vec![],
                network,
                env: vec![
                    ("npm_lifecycle_event".into(), lifecycle.into()),
                    ("npm_package_name".into(), statement.name.clone()),
                    ("npm_package_version".into(), statement.version.clone()),
                ],
                allow_env: vec![],
                unsafe_no_sandbox: self.unsafe_no_sandbox,
                allow_store_tools: true,
                store_home: Some(self.store.home.clone()),
            };
            let mut prepared =
                sandbox::prepare(&spec, Path::new("/bin/sh"), &["-c".into(), script.clone()])?;
            let mut stderr = tempfile::tempfile().context("capture install script errors")?;
            prepared
                .command
                .stdout(Stdio::null())
                .stderr(stderr.try_clone()?)
                .process_group(0);
            let mut child = prepared.command.spawn().context("run install script")?;
            let started = Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if started.elapsed() >= SCRIPT_TIMEOUT {
                    // Kill the whole process group, not just the shell.
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!(
                        "{lifecycle} timed out after {} seconds",
                        SCRIPT_TIMEOUT.as_secs_f64()
                    );
                }
                std::thread::sleep(Duration::from_millis(25));
            };
            if !status.success() {
                let mut error = String::new();
                stderr.read_to_string(&mut error)?;
                bail!(
                    "{lifecycle} exited with {}: {}",
                    status,
                    error.chars().take(500).collect::<String>()
                );
            }
        }
        Ok(())
    }
}

/// Removes a package's virtual-store slot and every link pointing at it.
fn unlink_package(modules: &Path, graph: &Graph, id: &str) -> Result<()> {
    remove_tree(&modules.join(".rivet").join(safe_id(id)))?;
    for (parent_id, parent) in &graph.nodes {
        for (alias, dep) in &parent.deps {
            if dep == id {
                remove_tree(
                    &modules
                        .join(".rivet")
                        .join(safe_id(parent_id))
                        .join("node_modules")
                        .join(alias),
                )?;
            }
        }
    }
    for (alias, root) in &graph.roots {
        if root.package == id {
            remove_tree(&modules.join(alias))?;
        }
    }
    Ok(())
}

/// Dependencies before dependents, so install scripts see built deps.
fn topological(graph: &Graph) -> Vec<String> {
    fn visit(
        id: &str,
        graph: &Graph,
        seen: &mut std::collections::BTreeSet<String>,
        out: &mut Vec<String>,
    ) {
        if !seen.insert(id.to_string()) {
            return;
        }
        if let Some(node) = graph.nodes.get(id) {
            for dep in node.deps.values() {
                visit(dep, graph, seen, out);
            }
        }
        out.push(id.to_string());
    }
    let mut seen = Default::default();
    let mut out = Vec::new();
    for id in graph.nodes.keys() {
        visit(id, graph, &mut seen, &mut out);
    }
    out
}

/// Hardlinks (or copies) a store package into place. Writable copies are
/// made for packages whose install scripts will run.
fn copy_tree(from: &Path, to: &Path, hardlink: bool) -> Result<()> {
    for entry in walkdir::WalkDir::new(from).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(from)?;
        let target = to.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if hardlink && fs::hard_link(entry.path(), &target).is_ok() {
            continue;
        }
        fs::copy(entry.path(), &target)?;
        let mode = entry.metadata()?.permissions().mode();
        let writable = if hardlink { mode } else { mode | 0o200 };
        fs::set_permissions(&target, fs::Permissions::from_mode(writable))?;
    }
    Ok(())
}

fn make_read_only(dir: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(dir).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let mode = entry.metadata()?.permissions().mode() & !0o222;
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn symlink_relative(target: &Path, link: &Path) -> Result<()> {
    let parent = link.parent().context("link has no parent")?;
    fs::create_dir_all(parent)?;
    let relative = relative_path(target, parent);
    if fs::symlink_metadata(link).is_ok() {
        fs::remove_file(link)?;
    }
    symlink(&relative, link)
        .with_context(|| format!("link {} -> {}", link.display(), relative.display()))
}

/// Path to `target` relative to directory `base`; both must be absolute.
pub fn relative_path(target: &Path, base: &Path) -> PathBuf {
    let target: Vec<Component> = target.components().collect();
    let base: Vec<Component> = base.components().collect();
    let common = target.iter().zip(&base).take_while(|(a, b)| a == b).count();
    let mut out = PathBuf::new();
    for _ in common..base.len() {
        out.push("..");
    }
    for component in &target[common..] {
        out.push(component.as_os_str());
    }
    out
}

fn write_bin_shims(
    root: &Path,
    final_root: &Path,
    bins: &BTreeMap<String, BinTarget>,
) -> Result<()> {
    if bins.is_empty() {
        return Ok(());
    }
    let bin_dir = modules_dir(root).join(".bin");
    fs::create_dir_all(&bin_dir)?;
    let rivet = std::env::current_exe().context("locate rivet executable")?;
    for command in bins.keys() {
        validate_command(command)?;
        let shim = bin_dir.join(command);
        let body = format!(
            "#!/bin/sh\n# Generated by rivet.\nexec {} run --project {} {} \"$@\"\n",
            shell_quote(&rivet.display().to_string()),
            shell_quote(&final_root.display().to_string()),
            shell_quote(command),
        );
        fs::write(&shim, body)?;
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

pub fn validate_command(command: &str) -> Result<()> {
    if command.is_empty()
        || command.len() > 214
        || command.starts_with(['-', '.'])
        || !command
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        bail!("unsafe executable command {command:?}");
    }
    Ok(())
}

fn validate_graph_paths(graph: &Graph) -> Result<()> {
    for (alias, root) in &graph.roots {
        validate_package_name(alias)?;
        if !graph.nodes.contains_key(&root.package) {
            bail!("root {alias} refers to absent package {}", root.package);
        }
    }
    for (id, node) in &graph.nodes {
        validate_package_name(&node.statement.name)?;
        for (alias, dep) in &node.deps {
            validate_package_name(alias)?;
            if alias == &node.statement.name {
                bail!("{id} has a dependency alias that collides with its own package directory");
            }
            if !graph.nodes.contains_key(dep) {
                bail!("{id} refers to absent dependency {dep}");
            }
        }
        for (command, entry) in &node.statement.manifest.bin {
            validate_command(command)?;
            validate_entry(entry).with_context(|| format!("{id} command {command}"))?;
        }
    }
    Ok(())
}

pub fn validate_entry(entry: &str) -> Result<()> {
    let trimmed = entry.strip_prefix("./").unwrap_or(entry);
    let path = Path::new(trimmed);
    if trimmed.is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || entry.contains('\\')
        || entry.chars().any(char::is_control)
    {
        bail!("unsafe executable entry {entry:?}");
    }
    Ok(())
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread::JoinHandle,
    };

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::core::{
        attestation::{
            tests::{sample_statement, test_key},
            Envelope, Executable,
        },
        lockfile::LockedRoot,
        resolver::Node,
    };
    use crate::CommonFlags;

    /// A disposable project directory, Rivet home and signing key.
    pub(crate) struct Fixture {
        _temp: tempfile::TempDir,
        pub project: PathBuf,
        pub store: LocalStore,
        pub signing: SigningKey,
        pub key: TrustedKey,
        pub policy: Policy,
    }

    impl Fixture {
        pub fn new(flags: CommonFlags) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let project = temp.path().join("project");
            fs::create_dir(&project).unwrap();
            let store = fixture_store(&temp.path().join("rivet-home"));
            let (signing, key) = test_key();
            Self {
                _temp: temp,
                project,
                store,
                signing,
                key,
                policy: Policy::new(None, &flags),
            }
        }

        pub fn with_scripts() -> Self {
            Self::new(CommonFlags {
                allow_scripts: true,
                ..Default::default()
            })
        }

        pub fn linker<'a>(&'a self, client: &'a RegistryClient, sandboxed: bool) -> Linker<'a> {
            Linker {
                store: &self.store,
                client,
                key: &self.key,
                policy: &self.policy,
                unsafe_no_sandbox: !sandboxed,
            }
        }

        pub fn offline_client(&self) -> RegistryClient {
            RegistryClient::new(&self.store.registry, None).unwrap()
        }

        pub fn state_bytes(&self) -> Vec<u8> {
            fs::read(state_path(&self.project)).unwrap()
        }
    }

    pub(crate) fn fixture_store(home: &Path) -> LocalStore {
        LocalStore {
            registry: "http://127.0.0.1:9".into(),
            home: home.to_path_buf(),
            store_dir: home.join("store"),
            attestation_dir: home.join("attestations"),
            tools_dir: home.join("tools"),
            index_dir: home.join("index"),
        }
    }

    /// A one-package graph ("demo@1.0.0" exposing `demo`) whose files are
    /// already in the store, so linking needs no registry.
    pub(crate) fn fixture_graph(
        store: &LocalStore,
        hash_char: char,
        script: Option<&str>,
    ) -> Graph {
        let mut statement = sample_statement("demo", "1.0.0");
        statement.artifact.hash = format!("sha512-{}", hash_char.to_string().repeat(128));
        statement
            .manifest
            .bin
            .insert("demo".into(), "bin/demo.js".into());
        statement.executables.push(Executable {
            command: "demo".into(),
            entry: "bin/demo.js".into(),
            permissions: None,
        });
        if let Some(script) = script {
            statement
                .manifest
                .install_scripts
                .insert("postinstall".into(), script.into());
        }
        let package = store.package_dir(&statement.artifact.hash).unwrap();
        fs::create_dir_all(package.join("bin")).unwrap();
        fs::write(package.join("bin/demo.js"), "console.log('old')\n").unwrap();
        statement.artifact.tree_digest = tree::tree_digest_of_dir(&package).unwrap();
        let id = statement.id();
        Graph {
            roots: BTreeMap::from([(
                "demo".into(),
                LockedRoot {
                    spec: "1.0.0".into(),
                    package: id.clone(),
                },
            )]),
            nodes: BTreeMap::from([(id, unsigned_node(statement))]),
            ..Default::default()
        }
    }

    pub(crate) fn unsigned_node(statement: Statement) -> Node {
        Node {
            statement,
            envelope: Envelope {
                payload_type: String::new(),
                payload: String::new(),
                keyid: String::new(),
                signature: String::new(),
            },
            deps: BTreeMap::new(),
            optional: false,
        }
    }

    /// Answers a single HTTP request with `body` and returns a client for it.
    pub(crate) fn serve_once(body: String) -> (RegistryClient, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client =
            RegistryClient::new(&format!("http://{}", listener.local_addr().unwrap()), None)
                .unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 8192];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        (client, server)
    }

    #[test]
    fn relative_paths_between_virtual_store_entries() {
        let target = Path::new("/p/node_modules/.rivet/b@1.0.0/node_modules/b");
        let base = Path::new("/p/node_modules/.rivet/a@1.0.0/node_modules");
        assert_eq!(
            relative_path(target, base),
            PathBuf::from("../../b@1.0.0/node_modules/b")
        );
        let scoped_base = Path::new("/p/node_modules/.rivet/a@1.0.0/node_modules/@scope");
        assert_eq!(
            relative_path(target, scoped_base),
            PathBuf::from("../../../b@1.0.0/node_modules/b")
        );
        assert_eq!(
            relative_path(
                Path::new("/p/node_modules/.rivet/x/node_modules/x"),
                Path::new("/p/node_modules")
            ),
            PathBuf::from(".rivet/x/node_modules/x")
        );
    }

    #[test]
    fn shims_quote_paths() {
        assert_eq!(shell_quote("a b'c"), "'a b'\\''c'");
    }

    #[test]
    fn command_names_cannot_inject_shell_or_escape_bin_directory() {
        for command in ["ok\ntouch PWN\n#", "bad\rname", "-option", "a/b", "x;touch"] {
            assert!(validate_command(command).is_err(), "accepted {command:?}");
        }
        assert!(validate_command("hello-cli").is_ok());
    }

    #[test]
    fn executable_entry_rejects_lexical_escape() {
        for entry in [
            "../escape",
            "package/../../escape",
            "/tmp/escape",
            "a\\b",
            "a\n",
        ] {
            assert!(validate_entry(entry).is_err(), "accepted {entry:?}");
        }
        assert!(validate_entry("./bin/hello.js").is_ok());
    }

    #[test]
    fn failed_required_script_preserves_previous_installation() {
        let fx = Fixture::with_scripts();
        let client = fx.offline_client();
        let linker = fx.linker(&client, false);
        linker
            .link(
                &fx.project,
                &fixture_graph(&fx.store, 'a', None),
                &fx.store.registry,
            )
            .unwrap();
        let before = fx.state_bytes();
        let failing = fixture_graph(&fx.store, 'b', Some("exit 9"));
        assert!(linker
            .link(&fx.project, &failing, &fx.store.registry)
            .is_err());
        assert_eq!(fx.state_bytes(), before);
        assert!(fx.project.join("node_modules/.bin/demo").exists());
    }

    #[test]
    fn timed_out_required_script_preserves_previous_installation() {
        let fx = Fixture::with_scripts();
        let client = fx.offline_client();
        let linker = fx.linker(&client, false);
        linker
            .link(
                &fx.project,
                &fixture_graph(&fx.store, 'a', None),
                &fx.store.registry,
            )
            .unwrap();
        let before = fx.state_bytes();
        let error = linker
            .link(
                &fx.project,
                &fixture_graph(&fx.store, 'b', Some("sleep 2")),
                &fx.store.registry,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
        assert_eq!(fx.state_bytes(), before);
    }

    #[test]
    fn failed_optional_script_is_removed_from_installed_state() {
        let fx = Fixture::with_scripts();
        let client = fx.offline_client();
        let mut graph = fixture_graph(&fx.store, 'a', Some("exit 9"));
        graph.nodes.get_mut("demo@1.0.0").unwrap().optional = true;
        let (state, report) = fx
            .linker(&client, false)
            .link(&fx.project, &graph, &fx.store.registry)
            .unwrap();
        assert_eq!(report.script_failures.len(), 1);
        assert!(!state.lock.packages.contains_key("demo@1.0.0"));
        assert!(!fx.project.join("node_modules/demo").exists());
        // No orphaned slot may remain: the verifier rejects unknown slots.
        assert!(!fx
            .project
            .join("node_modules/.rivet")
            .join(safe_id("demo@1.0.0"))
            .exists());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn global_install_script_builds_in_stage_without_editing_trust() {
        let fx = Fixture::with_scripts();
        let tool = fx.store.tools_dir.join("demo");
        fs::create_dir_all(&tool).unwrap();
        fs::create_dir_all(fx.store.home.join("trust")).unwrap();
        let pin = fx.store.home.join("trust/pin.json");
        fs::write(&pin, "pinned").unwrap();
        let script = format!(
            "printf built > built.txt; if printf evil > '{}' 2>/dev/null; then exit 9; fi",
            pin.display()
        );
        let graph = fixture_graph(&fx.store, 'a', Some(&script));
        let client = fx.offline_client();
        let (state, report) = fx
            .linker(&client, true)
            .link(&tool, &graph, &fx.store.registry)
            .unwrap();
        assert_eq!(report.scripts_ran, vec!["demo@1.0.0"]);
        assert!(state.script_modified.contains_key("demo@1.0.0"));
        assert_eq!(
            fs::read_to_string(package_path(&tool, "demo@1.0.0", "demo").join("built.txt"))
                .unwrap(),
            "built"
        );
        assert_eq!(fs::read_to_string(pin).unwrap(), "pinned");
    }

    #[test]
    fn failed_artifact_fetch_preserves_previous_installation() {
        let fx = Fixture::new(CommonFlags::default());
        let client = fx.offline_client();
        let linker = fx.linker(&client, false);
        linker
            .link(
                &fx.project,
                &fixture_graph(&fx.store, 'a', None),
                &fx.store.registry,
            )
            .unwrap();
        let before = fx.state_bytes();
        let mut missing = fixture_graph(&fx.store, 'b', None);
        let node = missing.nodes.get_mut("demo@1.0.0").unwrap();
        remove_tree(&fx.store.package_dir(&node.statement.artifact.hash).unwrap()).unwrap();
        node.statement.artifact.hash = "sha512-invalid".into();
        assert!(linker
            .link(&fx.project, &missing, &fx.store.registry)
            .is_err());
        assert_eq!(fx.state_bytes(), before);
    }
}
