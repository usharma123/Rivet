//! Run-time sandbox for package code. Declared permissions are enforced by
//! the operating system: macOS Seatbelt (sandbox-exec) or Linux bubblewrap.
//! When neither is available Rivet refuses to run package code unless the
//! user passes --unsafe-no-sandbox.

use std::{
    env,
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};

/// Environment variables passed through from the caller. Everything else
/// (tokens, cloud credentials, SSH agents) is dropped.
const PASS_ENV: &[&str] = &[
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TZ",
    "COLORTERM",
    "NO_COLOR",
    "FORCE_COLOR",
    "COLUMNS",
    "LINES",
    "NODE_ENV",
];

/// Paths under $HOME that package code may never read or write, even when
/// the project directory contains them. Rivet's own home is handled
/// separately because tools installed there must stay readable.
const SENSITIVE_HOME_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".config/gh",
    ".config/gcloud",
    ".azure",
    ".docker",
    ".kube",
    ".terraform.d",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware",
    ".mozilla",
    ".config/google-chrome",
    ".bash_history",
    ".zsh_history",
    ".env",
];

#[derive(Debug, Clone, Default)]
pub struct SandboxSpec {
    pub cwd: PathBuf,
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    /// Paths that stay read-only even if inside a write path.
    pub protect_paths: Vec<PathBuf>,
    pub network: bool,
    pub env: Vec<(String, String)>,
    pub allow_env: Vec<String>,
    pub unsafe_no_sandbox: bool,
    /// Let the process write under Rivet's tools directory (install scripts
    /// building a global tool in its staging directory).
    pub allow_store_tools: bool,
    /// Rivet home to protect; defaults to the configured one.
    pub store_home: Option<PathBuf>,
}

/// Rivet control data inside RIVET_HOME: unreadable and unwritable.
const RIVET_SECRETS: &[&str] = &[
    "trust",
    "attestations",
    "receipts",
    "index",
    "store",
    "config.json",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Seatbelt,
    Bubblewrap,
    None,
}

impl Backend {
    pub fn detect() -> Self {
        if cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists() {
            return Backend::Seatbelt;
        }
        if cfg!(target_os = "linux") && which("bwrap").is_some() {
            return Backend::Bubblewrap;
        }
        Backend::None
    }

    pub fn describe(self) -> &'static str {
        match self {
            Backend::Seatbelt => "macOS seatbelt",
            Backend::Bubblewrap => "bubblewrap",
            Backend::None => "none",
        }
    }
}

pub struct Prepared {
    pub command: Command,
    pub backend: Backend,
    _temp: tempfile::TempDir,
    _seccomp: Option<File>,
}

/// Builds a command that runs `program args` under the sandbox.
pub fn prepare(spec: &SandboxSpec, program: &Path, args: &[String]) -> Result<Prepared> {
    let temp = tempfile::Builder::new().prefix("rivet-run-").tempdir()?;
    let temp_path = canonical(temp.path());
    let fake_home = temp_path.join("home");
    std::fs::create_dir_all(&fake_home)?;

    let home = dirs::home_dir().map(|h| canonical(&h));
    let mut read_paths: Vec<PathBuf> = spec.read_paths.iter().map(|p| canonical(p)).collect();
    let mut write_paths: Vec<PathBuf> = spec.write_paths.iter().map(|p| canonical(p)).collect();
    write_paths.push(temp_path.clone());
    read_paths.push(temp_path.clone());
    let node = node_binary()?;
    if let Some(prefix) = node.parent().and_then(Path::parent) {
        read_paths.push(prefix.to_path_buf());
    }
    let (protect, secrets) = control_paths(spec, home.as_deref(), &write_paths)?;

    let path_env = format!(
        "{}:/usr/bin:/bin:/usr/sbin:/sbin",
        node.parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    );
    let mut env_vars: Vec<(String, String)> = vec![
        ("PATH".into(), path_env),
        ("HOME".into(), fake_home.display().to_string()),
        ("TMPDIR".into(), temp_path.display().to_string()),
        ("RIVET_SANDBOX".into(), "1".into()),
    ];
    for key in PASS_ENV
        .iter()
        .map(|k| k.to_string())
        .chain(spec.allow_env.iter().cloned())
    {
        if let Ok(value) = env::var(&key) {
            env_vars.push((key, value));
        }
    }
    env_vars.extend(spec.env.iter().cloned());

    let backend = if spec.unsafe_no_sandbox {
        Backend::None
    } else {
        Backend::detect()
    };
    let (mut command, seccomp) = match backend {
        Backend::Seatbelt => {
            let profile = seatbelt_profile(
                home.as_deref(),
                &read_paths,
                &write_paths,
                &protect,
                &secrets,
                spec.network,
            );
            let mut command = Command::new("/usr/bin/sandbox-exec");
            command.arg("-p").arg(profile).arg(program).args(args);
            (command, None)
        }
        Backend::Bubblewrap => {
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                let filter = linux_socket_filter(&temp_path)?;
                let fd = filter.as_raw_fd();
                let bwrap = which("bwrap").context("bwrap disappeared")?;
                let mut command = Command::new(bwrap);
                command.arg("--seccomp").arg(fd.to_string());
                command.args(bubblewrap_args(
                    home.as_deref(),
                    &read_paths,
                    &write_paths,
                    &protect,
                    &secrets,
                    spec.network,
                    &spec.cwd,
                ));
                command.arg("--").arg(program).args(args);
                (command, Some(filter))
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("bubblewrap is supported only on Linux");
            }
        }
        Backend::None => {
            if !spec.unsafe_no_sandbox {
                bail!(
                    "no sandbox is available on this system (need sandbox-exec on macOS or bwrap on Linux); \
                     install bubblewrap or pass --unsafe-no-sandbox to run without isolation"
                );
            }
            let mut command = Command::new(program);
            command.args(args);
            (command, None)
        }
    };
    command.env_clear().envs(env_vars).current_dir(&spec.cwd);
    Ok(Prepared {
        command,
        backend,
        _temp: temp,
        _seccomp: seccomp,
    })
}

/// Paths package code may not modify (`protect`) and, of those, the ones it
/// may not read either (`secrets`).
fn control_paths(
    spec: &SandboxSpec,
    home: Option<&Path>,
    write_paths: &[PathBuf],
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut protect: Vec<PathBuf> = spec
        .protect_paths
        .iter()
        .flat_map(|path| [path.clone(), canonical(path)])
        .collect();
    let mut secrets: Vec<PathBuf> = home
        .map(|home| SENSITIVE_HOME_PATHS.iter().map(|p| home.join(p)).collect())
        .unwrap_or_default();
    let rivet_home = match &spec.store_home {
        Some(home) => home.clone(),
        None => super::paths::rivet_home()?,
    };
    let rivet_home = if rivet_home.is_absolute() {
        rivet_home
    } else {
        env::current_dir()?.join(rivet_home)
    };
    // Seatbelt rules follow canonical paths, so a symlink the package can
    // rename would let it swap a protected directory for its own.
    for path in spec
        .protect_paths
        .iter()
        .chain(std::iter::once(&rivet_home))
    {
        for ancestor in path.ancestors() {
            let is_symlink =
                std::fs::symlink_metadata(ancestor).is_ok_and(|m| m.file_type().is_symlink());
            let parent_writable = ancestor
                .parent()
                .is_some_and(|parent| write_paths.iter().any(|w| canonical(parent).starts_with(w)));
            if is_symlink && parent_writable {
                bail!(
                    "protected control path {} crosses a symlink inside a writable grant; use its canonical path or narrow --allow-write",
                    path.display()
                );
            }
        }
    }
    let canonical_home = canonical(&rivet_home);
    if !spec.allow_store_tools {
        protect.push(rivet_home);
        protect.push(canonical_home.clone());
        protect.push(canonical_home.join("tools"));
    }
    secrets.extend(RIVET_SECRETS.iter().map(|part| canonical_home.join(part)));
    protect.extend(secrets.iter().cloned());
    Ok((protect, secrets))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn linux_socket_filter(dir: &Path) -> Result<File> {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "x86_64")]
    const SOCKET: u32 = 41;
    #[cfg(target_arch = "x86_64")]
    const SOCKETPAIR: u32 = 53;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xC000_00B7;
    #[cfg(target_arch = "aarch64")]
    const SOCKET: u32 = 198;
    #[cfg(target_arch = "aarch64")]
    const SOCKETPAIR: u32 = 199;

    // seccomp_data: nr at 0, arch at 4, first syscall argument at 16.
    // Reject unknown ABIs, io_uring setup and socket(AF_UNIX). An AF_UNIX
    // datagram/seqpacket socketpair can be reconnected to a pathname broker,
    // so only the already-connected stream kind is allowed. Internet sockets
    // remain available when the network namespace is shared.
    let instructions: [(u16, u8, u8, u32); 24] = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, ARCH),
        (0x06, 0, 0, 0x8000_0000),
        (0x20, 0, 0, 0),
        (0x54, 0, 0, 0x4000_0000),
        (0x15, 1, 0, 0),
        (0x06, 0, 0, 0x8000_0000),
        (0x20, 0, 0, 0),
        (0x15, 0, 1, 425),
        (0x06, 0, 0, 0x0005_0000 | libc::EPERM as u32),
        (0x15, 2, 0, SOCKET),
        (0x15, 5, 0, SOCKETPAIR),
        (0x05, 0, 0, 10),
        (0x20, 0, 0, 16),
        (0x15, 0, 1, libc::AF_UNIX as u32),
        (0x06, 0, 0, 0x0005_0000 | libc::EPERM as u32),
        (0x05, 0, 0, 6),
        (0x20, 0, 0, 16),
        (0x15, 0, 4, libc::AF_UNIX as u32),
        (0x20, 0, 0, 24),
        (0x54, 0, 0, 0xf),
        (0x15, 1, 0, libc::SOCK_STREAM as u32),
        (0x06, 0, 0, 0x0005_0000 | libc::EPERM as u32),
        (0x06, 0, 0, 0x7fff_0000),
    ];
    let path = dir.join("socket-filter.bpf");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    for (code, jt, jf, k) in instructions {
        file.write_all(&code.to_ne_bytes())?;
        file.write_all(&[jt, jf])?;
        file.write_all(&k.to_ne_bytes())?;
    }
    file.flush()?;
    file.seek(SeekFrom::Start(0))?;
    let fd = file.as_raw_fd();
    // The filter fd must survive exec into bwrap; bwrap installs the filter
    // before launching package code.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        bail!(
            "cannot pass seccomp filter to bubblewrap: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(file)
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn linux_socket_filter(_dir: &Path) -> Result<File> {
    bail!("no vetted Unix-socket seccomp filter for this Linux architecture")
}

fn quote(path: &Path) -> String {
    let text = path.display().to_string();
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Seatbelt rules are evaluated last-match-wins among rules for the same
/// operation; a rule for a specific operation (file-read-data) beats a
/// wildcard (file-read*), so both are emitted where precedence matters.
pub fn seatbelt_profile(
    home: Option<&Path>,
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    protect: &[PathBuf],
    secrets: &[PathBuf],
    network: bool,
) -> String {
    let mut rules = vec!["(version 1)".to_string(), "(allow default)".to_string()];
    if !network {
        rules.push("(deny network*)".into());
    } else {
        rules.push("(deny network* (remote unix-socket))".into());
    }
    rules.push("(deny file-write*)".into());
    let mut writable = vec![
        "(literal \"/dev/null\")".to_string(),
        "(literal \"/dev/zero\")".to_string(),
        "(literal \"/dev/dtracehelper\")".to_string(),
        "(regex #\"^/dev/tty\")".to_string(),
        "(regex #\"^/dev/fd/\")".to_string(),
    ];
    writable.extend(
        write_paths
            .iter()
            .map(|p| format!("(subpath {})", quote(p))),
    );
    rules.push(format!("(allow file-write* {})", writable.join(" ")));
    if let Some(home) = home {
        // Hide the home directory's contents; metadata stays readable so path
        // resolution through it works.
        rules.push(format!("(deny file-read-data (subpath {}))", quote(home)));
    }
    let readable: Vec<String> = read_paths
        .iter()
        .chain(write_paths.iter())
        .map(|p| format!("(subpath {})", quote(p)))
        .collect();
    if !readable.is_empty() {
        // Seatbelt prefers a rule naming the specific operation over a
        // wildcard, so the file-read-data deny on $HOME above is only undone
        // by an explicit file-read-data allow, not by file-read* alone.
        rules.push(format!("(allow file-read* {})", readable.join(" ")));
        rules.push(format!("(allow file-read-data {})", readable.join(" ")));
    }
    if !protect.is_empty() {
        let protected: Vec<String> = protect
            .iter()
            .map(|p| format!("(subpath {})", quote(p)))
            .collect();
        rules.push(format!("(deny file-write* {})", protected.join(" ")));
        // A package with a broader write grant could otherwise move an
        // ancestor, alter the protected tree at its new path, and move it
        // back. Deny removal/rename of each ancestor while retaining ordinary
        // file creation inside writable project directories.
        let mut ancestors = std::collections::BTreeSet::new();
        for path in protect {
            ancestors.insert(path.to_path_buf());
            for ancestor in path.ancestors().skip(1) {
                if write_paths.iter().any(|w| ancestor.starts_with(w)) {
                    ancestors.insert(ancestor.to_path_buf());
                }
            }
        }
        if !ancestors.is_empty() {
            let literals = ancestors
                .iter()
                .map(|p| format!("(literal {})", quote(p)))
                .collect::<Vec<_>>()
                .join(" ");
            rules.push(format!("(deny file-write-unlink {literals})"));
        }
    }
    let secret: Vec<String> = secrets
        .iter()
        .map(|p| format!("(subpath {})", quote(p)))
        .collect();
    if !secret.is_empty() {
        rules.push(format!("(deny file-read* {})", secret.join(" ")));
        rules.push(format!("(deny file-read-data {})", secret.join(" ")));
    }
    rules.join("\n")
}

#[cfg(any(target_os = "linux", test))]
pub fn bubblewrap_args(
    home: Option<&Path>,
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    protect: &[PathBuf],
    secrets: &[PathBuf],
    network: bool,
    cwd: &Path,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    if !network {
        args.push("--unshare-net".into());
    }
    if let Some(home) = home {
        args.extend(["--tmpfs".into(), home.display().to_string()]);
    }
    for path in read_paths {
        if path.exists() {
            args.extend([
                "--ro-bind".into(),
                path.display().to_string(),
                path.display().to_string(),
            ]);
        }
    }
    for path in write_paths {
        if path.exists() {
            args.extend([
                "--bind".into(),
                path.display().to_string(),
                path.display().to_string(),
            ]);
        }
    }
    for path in protect {
        if !path.exists() {
            continue;
        }
        let secret = secrets.contains(path);
        let exposed = read_paths
            .iter()
            .chain(write_paths)
            .any(|p| path.starts_with(p));
        if secret {
            if exposed {
                // Secrets inside an exposed directory are masked entirely.
                if path.is_dir() {
                    // An empty read-only mount: writes fail instead of
                    // silently landing in a throwaway tmpfs.
                    args.extend([
                        "--tmpfs".into(),
                        path.display().to_string(),
                        "--remount-ro".into(),
                        path.display().to_string(),
                    ]);
                } else {
                    args.extend([
                        "--ro-bind".into(),
                        "/dev/null".into(),
                        path.display().to_string(),
                    ]);
                }
            }
        } else if exposed {
            args.extend([
                "--ro-bind".into(),
                path.display().to_string(),
                path.display().to_string(),
            ]);
        }
    }
    args.extend(["--chdir".into(), cwd.display().to_string()]);
    args
}

pub fn node_binary() -> Result<PathBuf> {
    let node = which("node").context("node is not installed or not on PATH")?;
    Ok(canonical(&node))
}

fn which(program: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs node under the sandbox, requiring success, and returns stdout.
    fn run_node(spec: &SandboxSpec, args: &[String]) -> String {
        let mut prepared = prepare(spec, &node_binary().unwrap(), args).unwrap();
        let output = prepared.command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn seatbelt_profile_denies_network_and_secrets() {
        let home = PathBuf::from("/Users/dev");
        let profile = seatbelt_profile(
            Some(&home),
            &[PathBuf::from("/Users/dev/project")],
            &[PathBuf::from("/Users/dev/project")],
            &[
                home.join(".ssh"),
                home.join(".rivet"),
                PathBuf::from("/Users/dev/project/node_modules/.rivet"),
            ],
            &[home.join(".ssh"), home.join(".rivet")],
            false,
        );
        assert!(profile.contains("(deny network*)"));
        assert!(!profile.contains("remote unix-socket"));
        assert!(profile.contains("(deny file-read-data (subpath \"/Users/dev\"))"));
        let secrets = profile
            .rfind("(deny file-read* (subpath \"/Users/dev/.ssh\")")
            .unwrap();
        let allow = profile
            .find("(allow file-read* (subpath \"/Users/dev/project\")")
            .unwrap();
        assert!(
            secrets > allow,
            "secret denies must come last (last match wins)"
        );
        assert!(profile.contains("(deny file-write* (subpath \"/Users/dev/.ssh\") (subpath \"/Users/dev/.rivet\") (subpath \"/Users/dev/project/node_modules/.rivet\"))"));
        let with_network = seatbelt_profile(Some(&home), &[], &[], &[], &[], true);
        assert!(with_network.contains("deny network* (remote unix-socket)"));
    }

    #[test]
    fn bubblewrap_hides_home_and_network() {
        let args = bubblewrap_args(
            Some(Path::new("/home/dev")),
            &[],
            &[],
            &[],
            &[],
            false,
            Path::new("/"),
        );
        let joined = args.join(" ");
        assert!(joined.contains("--unshare-net"));
        assert!(joined.contains("--tmpfs /home/dev"));
    }

    #[test]
    fn caller_secret_requires_explicit_environment_grant() {
        let project = tempfile::tempdir().unwrap();
        let node = node_binary().unwrap();
        // This process-local fake secret is never a real credential.
        unsafe { std::env::set_var("RIVET_TEST_SECRET", "fake-secret") };
        let basic = SandboxSpec {
            cwd: project.path().to_path_buf(),
            unsafe_no_sandbox: true,
            ..Default::default()
        };
        let implicit = prepare(&basic, &node, &[]).unwrap();
        assert!(!implicit
            .command
            .get_envs()
            .any(|(key, _)| key == "RIVET_TEST_SECRET"));
        let explicit = prepare(
            &SandboxSpec {
                allow_env: vec!["RIVET_TEST_SECRET".into()],
                ..basic
            },
            &node,
            &[],
        )
        .unwrap();
        assert!(explicit
            .command
            .get_envs()
            .any(|(key, value)| key == "RIVET_TEST_SECRET"
                && value == Some(std::ffi::OsStr::new("fake-secret"))));
        unsafe { std::env::remove_var("RIVET_TEST_SECRET") };
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn sandbox_blocks_home_secrets_and_network_for_real() {
        let project = tempfile::tempdir().unwrap();
        // A file in the real home directory: Seatbelt denies reading it,
        // bubblewrap hides home behind an empty tmpfs.
        let home_file = tempfile::Builder::new()
            .prefix(".rivet-home-probe-")
            .tempfile_in(dirs::home_dir().unwrap())
            .unwrap();
        std::fs::write(home_file.path(), "secret").unwrap();
        let script = project.path().join("probe.js");
        std::fs::write(
            &script,
            r#"
const fs = require("fs");
const out = {};
try { fs.writeFileSync("ok.txt", "1"); out.cwdWrite = true } catch { out.cwdWrite = false }
try { fs.readFileSync(process.argv[2]); out.homeRead = true } catch { out.homeRead = false }
require("net").connect(443, "1.1.1.1").on("error", () => { out.net = false; console.log(JSON.stringify(out)) })
  .on("connect", () => { out.net = true; console.log(JSON.stringify(out)); process.exit(0) });
"#,
        )
        .unwrap();
        let spec = SandboxSpec {
            cwd: project.path().to_path_buf(),
            read_paths: vec![project.path().to_path_buf()],
            write_paths: vec![project.path().to_path_buf()],
            ..Default::default()
        };
        let mut prepared = prepare(
            &spec,
            &node_binary().unwrap(),
            &[
                script.display().to_string(),
                home_file.path().display().to_string(),
            ],
        )
        .unwrap();
        assert_ne!(prepared.backend, Backend::None);
        // env_clear() plus an explicit allowlist: nothing else is inherited.
        let keys: Vec<String> = prepared
            .command
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        for key in &keys {
            assert!(
                ["PATH", "HOME", "TMPDIR", "RIVET_SANDBOX"].contains(&key.as_str())
                    || PASS_ENV.contains(&key.as_str()),
                "unexpected env {key}"
            );
        }
        let output = prepared.command.output().unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("\"cwdWrite\":true"),
            "{text} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(text.contains("\"homeRead\":false"), "{text}");
        assert!(text.contains("\"net\":false"), "{text}");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn sandbox_blocks_custom_store_and_project_controls() {
        use std::os::unix::fs::symlink;
        let project = tempfile::tempdir().unwrap();
        let real_store = project.path().join("custom-store");
        let alias = project.path().join("store-alias");
        std::fs::create_dir_all(real_store.join("trust")).unwrap();
        std::fs::create_dir_all(real_store.join("receipts")).unwrap();
        std::fs::create_dir_all(project.path().join("node_modules/.bin")).unwrap();
        symlink(&real_store, &alias).unwrap();
        let targets = [
            real_store.join("trust/pin.json"),
            real_store.join("receipts/install.json"),
            project.path().join("rivet.toml"),
            project.path().join("node_modules/.bin/tool"),
        ];
        for target in &targets {
            std::fs::write(target, "original").unwrap();
        }
        let script = project.path().join("probe.js");
        std::fs::write(&script, r#"const fs = require('fs'); const result = process.argv.slice(2).map(p => { try { fs.writeFileSync(p, 'changed'); return true } catch { return false } }); fs.writeFileSync('ordinary.txt', 'ok'); console.log(JSON.stringify(result))"#).unwrap();
        let spec = SandboxSpec {
            cwd: project.path().to_path_buf(),
            read_paths: vec![project.path().to_path_buf()],
            write_paths: vec![project.path().to_path_buf()],
            protect_paths: vec![
                project.path().join("rivet.toml"),
                project.path().join("node_modules"),
            ],
            store_home: Some(real_store.clone()),
            ..Default::default()
        };
        let mut args = vec![script.display().to_string()];
        args.extend(targets.iter().map(|p| p.display().to_string()));
        let stdout = run_node(&spec, &args);
        assert_eq!(stdout.trim(), "[false,false,false,false]");
        assert_eq!(
            std::fs::read_to_string(project.path().join("ordinary.txt")).unwrap(),
            "ok"
        );
        let rename_script = project.path().join("rename.js");
        std::fs::write(&rename_script, "const fs=require('fs'); for(let i=2;i<process.argv.length;i+=2) { try {fs.renameSync(process.argv[i],process.argv[i+1]);console.log('MOVED')} catch {console.log('DENIED')} }").unwrap();
        let args = [
            rename_script.display().to_string(),
            project.path().join("node_modules").display().to_string(),
            project.path().join("moved-modules").display().to_string(),
            real_store.display().to_string(),
            project.path().join("moved-store").display().to_string(),
        ];
        let stdout = run_node(&spec, &args);
        assert_eq!(stdout.trim(), "DENIED\nDENIED");
        assert!(real_store.join("trust/pin.json").exists());
        assert!(project.path().join("node_modules/.bin/tool").exists());
        let alias_spec = SandboxSpec {
            store_home: Some(alias),
            ..spec
        };
        let error = prepare(&alias_spec, &node_binary().unwrap(), &[])
            .err()
            .expect("writable store alias must fail closed")
            .to_string();
        assert!(error.contains("symlink inside a writable grant"), "{error}");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn sandbox_denies_host_unix_socket_in_both_network_modes() {
        use std::os::unix::net::UnixListener;
        let project = tempfile::tempdir().unwrap();
        let socket = project.path().join("broker.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let script = project.path().join("socket.js");
        std::fs::write(&script, "require('net').connect(process.argv[2]).on('connect',()=>{console.log('CONNECTED');process.exit(0)}).on('error',()=>{console.log('DENIED')})").unwrap();
        for network in [false, true] {
            let spec = SandboxSpec {
                cwd: project.path().to_path_buf(),
                read_paths: vec![project.path().to_path_buf()],
                write_paths: vec![project.path().to_path_buf()],
                network,
                ..Default::default()
            };
            let stdout = run_node(
                &spec,
                &[script.display().to_string(), socket.display().to_string()],
            );
            assert!(stdout.contains("DENIED"), "network={network}");
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn sandbox_reads_global_tool_under_custom_store_in_real_home() {
        let home = dirs::home_dir().unwrap();
        let project = tempfile::Builder::new()
            .prefix(".rivet-store-test-")
            .tempdir_in(home)
            .unwrap();
        let store = project.path().join("custom-rivet-home");
        std::fs::create_dir_all(store.join("tools/demo")).unwrap();
        std::fs::create_dir_all(store.join("trust")).unwrap();
        std::fs::create_dir_all(project.path().join("node_modules/demo")).unwrap();
        std::fs::write(store.join("tools/demo/tool.txt"), "TOOL_READ_OK").unwrap();
        std::fs::write(store.join("trust/pin.json"), "pin").unwrap();
        std::fs::write(
            project.path().join("node_modules/demo/index.js"),
            "PROJECT_MODULE_OK",
        )
        .unwrap();
        let script = project.path().join("probe.js");
        std::fs::write(&script, "const fs=require('fs'); console.log(fs.readFileSync(process.argv[2],'utf8')); console.log(fs.readFileSync(process.argv[4],'utf8')); try {fs.writeFileSync(process.argv[4],'evil');console.log('MODULE_WRITABLE')} catch {console.log('MODULE_IMMUTABLE')} try {fs.readFileSync(process.argv[3]);console.log('PIN_READABLE')} catch {console.log('PIN_HIDDEN')} try {fs.writeFileSync(process.argv[3],'evil');console.log('PIN_WRITABLE')} catch {console.log('PIN_DENIED')}").unwrap();
        let spec = SandboxSpec {
            cwd: project.path().to_path_buf(),
            read_paths: vec![project.path().to_path_buf(), store.join("tools/demo")],
            write_paths: vec![project.path().to_path_buf()],
            protect_paths: vec![project.path().join("node_modules")],
            store_home: Some(store.clone()),
            ..Default::default()
        };
        let stdout = run_node(
            &spec,
            &[
                script.display().to_string(),
                store.join("tools/demo/tool.txt").display().to_string(),
                store.join("trust/pin.json").display().to_string(),
                project
                    .path()
                    .join("node_modules/demo/index.js")
                    .display()
                    .to_string(),
            ],
        );
        assert!(
            stdout.contains("TOOL_READ_OK")
                && stdout.contains("PROJECT_MODULE_OK")
                && stdout.contains("MODULE_IMMUTABLE")
                && stdout.contains("PIN_HIDDEN")
                && stdout.contains("PIN_DENIED"),
            "{stdout}"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn sandbox_allows_staged_global_script_output_but_not_trust_edits() {
        let parent = tempfile::tempdir().unwrap();
        let store = parent.path().join("custom-store");
        let stage = store.join("tools/staged/demo");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(store.join("trust")).unwrap();
        std::fs::write(store.join("trust/pin.json"), "pin").unwrap();
        let script = stage.join("build.js");
        std::fs::write(&script, "const fs=require('fs');fs.writeFileSync('output.js','built');try{fs.writeFileSync(process.argv[2],'evil');console.log('TRUST_WRITABLE')}catch{console.log('TRUST_DENIED')}").unwrap();
        let spec = SandboxSpec {
            cwd: stage.clone(),
            read_paths: vec![stage.clone()],
            write_paths: vec![stage.clone()],
            store_home: Some(store.clone()),
            allow_store_tools: true,
            ..Default::default()
        };
        let stdout = run_node(
            &spec,
            &[
                script.display().to_string(),
                store.join("trust/pin.json").display().to_string(),
            ],
        );
        assert!(stdout.contains("TRUST_DENIED"));
        assert_eq!(
            std::fs::read_to_string(stage.join("output.js")).unwrap(),
            "built"
        );
        assert_eq!(
            std::fs::read_to_string(store.join("trust/pin.json")).unwrap(),
            "pin"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn sandbox_protects_project_controls_under_broader_write_grant() {
        // With write access to the project's parent, a package tries to move
        // the project away, edit the protected shim at its new path and move
        // it back. Seatbelt denies the rename itself; on Linux the read-only
        // bind travels with the directory, so the edit fails instead. Either
        // way the shim must be untouched.
        let parent = tempfile::tempdir().unwrap();
        let project = parent.path().join("project");
        let shim = project.join("node_modules/.bin/tool");
        std::fs::create_dir_all(shim.parent().unwrap()).unwrap();
        std::fs::write(&shim, "original").unwrap();
        let script = parent.path().join("probe.js");
        std::fs::write(
            &script,
            r#"
const fs = require("fs"), path = require("path");
const [project, moved] = process.argv.slice(2);
const out = {};
try { fs.writeFileSync(path.join(project, "node_modules/.bin/tool"), "evil"); out.direct = "written" } catch { out.direct = "denied" }
try { fs.renameSync(project, moved); out.rename = "moved" } catch { out.rename = "denied" }
if (out.rename === "moved") {
  try { fs.writeFileSync(path.join(moved, "node_modules/.bin/tool"), "evil"); out.relocated = "written" } catch { out.relocated = "denied" }
  fs.renameSync(moved, project);
}
console.log(JSON.stringify(out));
"#,
        )
        .unwrap();
        let spec = SandboxSpec {
            cwd: parent.path().to_path_buf(),
            read_paths: vec![project.clone()],
            write_paths: vec![parent.path().to_path_buf()],
            protect_paths: vec![project.join("node_modules")],
            ..Default::default()
        };
        let stdout = run_node(
            &spec,
            &[
                script.display().to_string(),
                project.display().to_string(),
                parent.path().join("moved").display().to_string(),
            ],
        );
        assert!(stdout.contains(r#""direct":"denied""#), "{stdout}");
        assert!(!stdout.contains(r#""relocated":"written""#), "{stdout}");
        if cfg!(target_os = "macos") {
            assert!(stdout.contains(r#""rename":"denied""#), "{stdout}");
        }
        assert_eq!(std::fs::read_to_string(&shim).unwrap(), "original");
    }
}
