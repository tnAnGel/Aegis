use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Command-line interface for Aegis.
#[derive(Debug, Parser)]
#[command(name = "aegis", version, about = "Aegis edge gateway")]
pub struct Cli {
    /// Path to configuration file. `.conf` = nginx-style DSL,
    /// `.toml` = legacy TOML. Auto-detected for any other extension.
    #[arg(long, short = 'c', default_value = "/etc/aegis/aegis.conf")]
    pub config: PathBuf,

    /// Validate config and exit (alias for `config test`).
    #[arg(short = 't')]
    pub test_config: bool,

    /// Log level (for example: info, debug).
    // V230 — default to warn; debug/trace already stripped via tracing release_max_level_info, info-level adds dispatch overhead at high RPS without diagnostic value on a stable build.
    #[arg(long, default_value = "warn")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Supported CLI commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the proxy (default).
    Start,
    /// Send SIGTERM to a running aegis via PID file.
    Stop,
    /// Stop then start.
    Restart,
    /// Trigger admin /admin/reload (live-reload running aegis).
    Reload,
    /// Print accumulated per-domain metrics summary.
    Metrics,
    /// Rule maintenance.
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },
    /// Per-domain registry maintenance.
    Domain {
        #[command(subcommand)]
        command: DomainCommands,
    },
    /// Config inspection and conversion.
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Web admin panel control: enable/disable + credential reset.
    Web {
        #[command(subcommand)]
        command: WebCommands,
    },
    /// Update Aegis in place: snapshot /etc/aegis (config, sites,
    /// secrets, certs) to a backup tarball, then pull + rebuild +
    /// restart from your TRUSTED source repo via install.sh. Your data
    /// is preserved — only the source tree + binary are rebuilt.
    ///
    /// CLI-only (needs root). This is NOT reachable from the web panel:
    /// the in-panel auto-apply path was removed in V233 because it
    /// downloaded + executed an unverified binary (RCE-class). This
    /// command instead rebuilds from your own source — it never
    /// downloads a prebuilt binary — so it is safe for an operator to
    /// run on the host.
    Update {
        /// Only check whether a newer version is available on the
        /// configured remote; print the result and exit without changing
        /// anything.
        #[arg(long)]
        check: bool,
        /// Git ref (branch or tag) to update to.
        #[arg(long, default_value = "main")]
        r#ref: String,
        /// Skip the pre-update /etc/aegis backup (not recommended).
        #[arg(long)]
        no_backup: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum WebCommands {
    /// Reset the web panel password to a freshly-generated random
    /// string. Prints the new password to stdout. Email is reset to
    /// the installer default (admin@local.lcl). Forces a credential
    /// change on next login.
    ResetAdmin,
    /// Disable the web panel — /admin/ui and /admin/api/* return 503
    /// until `aegis web start`. Plain `/admin/*` ops endpoints
    /// (reload, health, …) remain reachable for CLI / systemctl.
    Stop,
    /// Re-enable the web panel after `aegis web stop`.
    Start,
    /// Print current panel state (enabled, current admin email,
    /// must_change flag, active session count, file path).
    Status,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommands {
    Validate,
}

#[derive(Debug, Subcommand)]
pub enum DomainCommands {
    Add { domain: String },
    List,
    Remove { domain: String },
    Rm { domain: String },
    Stats { domain: String },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// Parse + validate the config file, print a summary, exit non-zero
    /// on any error. Same as `aegis -t`.
    Test,
    /// Convert a legacy TOML config to the new DSL syntax.
    Migrate {
        /// Source TOML config.
        #[arg(long)]
        from: PathBuf,
        /// Destination .conf file (stdout if omitted).
        #[arg(long)]
        to: Option<PathBuf>,
    },
}
