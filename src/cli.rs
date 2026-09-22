//! clap CLI definition.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "opsec-check",
    author = "r3dg0d",
    version,
    about = "Umbrella privacy/security audit — local checks plus optional sibling tools",
    long_about = "Run a read-only OPSEC audit of this machine. Findings are classified as \
informational, attention recommended, or configuration issue — never as a fake privacy score. \
When sibling tools (macrandom, mullvadctl, dnscheck, netidentity, metaclean, browserprivacy, \
fileshred) are on PATH, opsec-check may invoke them for deeper detail."
)]
pub struct Cli {
    /// Emit machine-readable JSON
    #[arg(long, global = true, conflicts_with_all = ["markdown", "html"])]
    pub json: bool,

    /// Emit Markdown report
    #[arg(long, global = true, conflicts_with_all = ["json", "html"])]
    pub markdown: bool,

    /// Emit a simple HTML report
    #[arg(long, global = true, conflicts_with_all = ["json", "markdown"])]
    pub html: bool,

    /// Increase logging verbosity (-v, -vv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-essential human output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Path to JSON config (overrides XDG config)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Do not invoke sibling tools (still runs built-in checks)
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Skip home-directory metadata sampling
    #[arg(long, global = true)]
    pub no_metadata_sample: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run the full audit (default when no subcommand is given)
    Audit,
    /// List detected sibling tools and built-in check inventory
    Tools,
    /// Generate shell completions
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    Powershell,
    Zsh,
}

impl From<Shell> for clap_complete::Shell {
    fn from(s: Shell) -> Self {
        match s {
            Shell::Bash => Self::Bash,
            Shell::Elvish => Self::Elvish,
            Shell::Fish => Self::Fish,
            Shell::Powershell => Self::PowerShell,
            Shell::Zsh => Self::Zsh,
        }
    }
}
