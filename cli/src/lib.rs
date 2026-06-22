mod commands;
mod core;

use anyhow::Result;
use clap::Parser;
use commands::{add, byok, eval, import, init, inspect, install, publish, release, run};
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
        command: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
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
        #[command(flatten)]
        flags: CommonFlags,
    },
    Yank {
        package: String,
        #[arg(long)]
        reason: String,
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
    #[arg(long)]
    pub allow_scripts: bool,
    #[arg(long)]
    pub allow_network: bool,
    #[arg(long)]
    pub allow_unverified: bool,
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
        Command::Install { flags } => install::run(flags),
        Command::Import { spec, flags } => import::run(spec, flags),
        Command::Inspect { target, flags } => inspect::run(target, flags),
        Command::Run {
            command,
            args,
            flags,
        } => run::run(command, args, flags),
        Command::Publish { flags } => publish::run(flags),
        Command::Revoke {
            package,
            reason,
            replacement,
            flags,
        } => release::revoke(package, reason, replacement, flags),
        Command::Yank {
            package,
            reason,
            flags,
        } => release::yank(package, reason, flags),
        Command::Eval {
            package,
            byok,
            flags,
        } => eval::run(package, byok, flags),
        Command::Byok { command } => byok::run(command),
    }
}
