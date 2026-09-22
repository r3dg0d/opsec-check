//! opsec-check — umbrella privacy/security audit CLI

use clap::{CommandFactory, Parser};
use opsec_check::audit;
use opsec_check::cli::{Cli, Commands};
use opsec_check::config::Config;
use opsec_check::exit_codes;
use opsec_check::finding::Severity;
use opsec_check::output::{self, Format};
use opsec_check::tools;
use tracing_subscriber::EnvFilter;

fn main() {
    let code = match real_main() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            exit_codes::GENERAL_ERROR
        }
    };
    std::process::exit(code);
}

fn real_main() -> anyhow::Result<i32> {
    let cli = Cli::parse();

    let filter = match (cli.quiet, cli.verbose) {
        (true, _) => "error",
        (false, 0) => "warn",
        (false, 1) => "info",
        (false, _) => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    ctrlc::set_handler(|| {
        eprintln!("\ninterrupted");
        std::process::exit(exit_codes::INTERRUPTED);
    })?;

    let (cfg, cfg_path) = Config::load(cli.config.as_deref())?;
    if cli.verbose > 0 {
        if let Some(p) = &cfg_path {
            tracing::info!(path = %p.display(), "loaded config");
        }
    }

    let fmt = if cli.json {
        Format::Json
    } else if cli.markdown {
        Format::Markdown
    } else if cli.html {
        Format::Html
    } else {
        Format::Text
    };

    match cli.command.unwrap_or(Commands::Audit) {
        Commands::Audit => {
            let report = audit::run(&cfg, cli.dry_run, cli.no_metadata_sample);
            if !cli.quiet || matches!(fmt, Format::Json | Format::Markdown | Format::Html) {
                output::render(&report, fmt)?;
            }
            Ok(match report.worst_severity() {
                Some(Severity::ConfigurationIssue) => exit_codes::CONFIG_ISSUE,
                Some(Severity::AttentionRecommended) => exit_codes::ATTENTION,
                _ => exit_codes::SUCCESS,
            })
        }
        Commands::Tools => {
            let siblings = tools::detect_siblings();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&siblings)?);
            } else {
                println!("Sibling tools:");
                for t in &siblings {
                    if t.available {
                        println!("  [ok] {} ({})", t.name, t.path.as_deref().unwrap_or("?"));
                    } else {
                        println!("  [--] {} — not on PATH", t.name);
                    }
                }
                println!();
                println!("Built-in check groups:");
                for name in [
                    "hostname",
                    "network_identity",
                    "vpn",
                    "dns",
                    "mac",
                    "firewall",
                    "listening",
                    "ipv6",
                    "mdns",
                    "wifi",
                    "bluetooth",
                    "camera_mic",
                    "disk_encryption",
                    "swap_encryption",
                    "removable_storage",
                    "browser_privacy",
                    "file_metadata",
                    "nixos",
                ] {
                    println!("  - {name}");
                }
            }
            Ok(exit_codes::SUCCESS)
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(
                clap_complete::Shell::from(shell),
                &mut cmd,
                name,
                &mut std::io::stdout(),
            );
            Ok(exit_codes::SUCCESS)
        }
    }
}
