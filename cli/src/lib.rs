mod commands;
mod core;

use anyhow::Result;
use clap::Parser;
use commands::{
    add, byok, eval, import, init, inspect, install, publish, release, run, trust, verify,
};
use core::output::OutputMode;

#[derive(Debug, Parser)]
#[command(
    name = "rivet",
    version,
    about = "Visible, auditable package management"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    Init {
        #[command(flatten)]
        flags: CommonFlags,
    },
    Add {
        package: String,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Install {
        /// Fail instead of re-resolving when rivet.lock is missing or stale.
        #[arg(long)]
        frozen: bool,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Import {
        spec: String,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Inspect {
        target: String,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Run {
        /// Project whose node_modules provides the command (default: current directory).
        #[arg(long)]
        project: Option<std::path::PathBuf>,
        command: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Verify {
        target: String,
        /// Ask the registry to re-run its audit (requires RIVET_REGISTRY_TOKEN).
        #[arg(long)]
        reaudit: bool,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Publish {
        #[command(flatten)]
        flags: CommonFlags,
    },
    Revoke {
        package: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        replacement: Option<String>,
        /// Registry-admin override for widely used releases (needs the admin token).
        #[arg(long)]
        security_evidence: bool,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Yank {
        package: String,
        #[arg(long)]
        reason: String,
        /// Registry-admin override for widely used releases (needs the admin token).
        #[arg(long)]
        registry_approved: bool,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Eval {
        package: String,
        #[arg(long)]
        byok: String,
        #[command(flatten)]
        flags: CommonFlags,
    },
    Byok {
        #[command(subcommand)]
        command: ByokCommand,
    },
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum TrustCommand {
    /// Show the pinned registry signing key.
    Show {
        #[command(flatten)]
        flags: CommonFlags,
    },
    /// Forget the pinned key so the next command re-pins it.
    Reset {
        #[command(flatten)]
        flags: CommonFlags,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum ByokCommand {
    Add {
        provider: String,
        #[command(flatten)]
        flags: CommonFlags,
    },
    List {
        #[command(flatten)]
        flags: CommonFlags,
    },
}

#[derive(Debug, Clone, Default, clap::Args)]
pub struct CommonFlags {
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub events: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub plan: bool,
    #[arg(long)]
    pub non_interactive: bool,
    #[arg(long)]
    pub verbose: bool,
    #[arg(long)]
    pub quiet: bool,
    #[arg(long)]
    pub unsafe_allow_risk: bool,
    #[arg(long)]
    pub unsafe_allow_revoked: bool,
    /// Run install scripts of every package (inside the sandbox).
    #[arg(long)]
    pub allow_scripts: bool,
    /// Let the command use the network when run.
    #[arg(long)]
    pub allow_network: bool,
    /// Accept releases that have not passed a registry audit.
    #[arg(long)]
    pub allow_unverified: bool,
    /// Disable the release cooldown and accept freshly published versions.
    #[arg(long)]
    pub allow_fresh: bool,
    /// Override the cooldown (hours a release must be public before install).
    #[arg(long)]
    pub min_age_hours: Option<f64>,
    /// Refuse packages without verified Sigstore provenance.
    #[arg(long)]
    pub require_provenance: bool,
    /// Pass an extra environment variable through to the sandbox.
    #[arg(long = "allow-env", value_name = "NAME")]
    pub allow_env: Vec<String>,
    /// Grant write access to an extra path when running.
    #[arg(long = "allow-write", value_name = "PATH")]
    pub allow_write: Vec<std::path::PathBuf>,
    /// Run package code without OS isolation (not recommended).
    #[arg(long)]
    pub unsafe_no_sandbox: bool,
}

impl CommonFlags {
    pub fn output_mode(&self) -> OutputMode {
        if self.json {
            OutputMode::Json
        } else if self.events {
            OutputMode::Events
        } else {
            OutputMode::Human
        }
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { flags } => init::run(flags),
        Command::Add { package, flags } => add::run(package, flags),
        Command::Install { frozen, flags } => install::run(frozen, flags),
        Command::Import { spec, flags } => import::run(spec, flags),
        Command::Inspect { target, flags } => inspect::run(target, flags),
        Command::Run {
            project,
            command,
            args,
            flags,
        } => run::run(project, command, args, flags),
        Command::Verify {
            target,
            reaudit,
            flags,
        } => verify::run(target, reaudit, flags),
        Command::Publish { flags } => publish::run(flags),
        Command::Revoke {
            package,
            reason,
            replacement,
            security_evidence,
            flags,
        } => release::revoke(package, reason, replacement, security_evidence, flags),
        Command::Yank {
            package,
            reason,
            registry_approved,
            flags,
        } => release::yank(package, reason, registry_approved, flags),
        Command::Eval {
            package,
            byok,
            flags,
        } => eval::run(package, byok, flags),
        Command::Byok { command } => byok::run(command),
        Command::Trust { command } => trust::run(command),
    }
}
