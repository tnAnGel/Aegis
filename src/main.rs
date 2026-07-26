use std::path::Path;

use anyhow::Result;
use clap::Parser;

use aegis::{cli, config, control, domains, dsl, logging, server, web_admin};

// Swap glibc/musl allocator for mimalloc. Multi-threaded allocation is
// a hot path for any reverse proxy — every request allocates header
// maps, body buffers, and per-filter scratch. mimalloc's segment cache
// + thread-local slabs measurably outperform the default malloc on
// allocation-heavy server workloads (Microsoft benchmarks + Cloudflare
// and TiKV production experience).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Wrap the loader so callers don't care whether the config is DSL or
/// legacy TOML. `dsl::load_any` dispatches by extension and falls back
/// to TOML for unknown ones, so existing automation keeps working.
fn load_config(path: &Path) -> Result<config::AppConfig> {
    let (cfg, _summary) = dsl::load_any(path)?;
    Ok(cfg)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::Cli::parse();
    // CLI subcommands that don't run the proxy load the config purely
    // to look up filesystem paths — silence dsl loader warnings on
    // stdout for those so the user-facing output stays clean. The
    // server / reload paths still honour --log-level.
    let is_quiet_cli = matches!(
        args.command,
        Some(cli::Commands::Web { .. })
            | Some(cli::Commands::Stop)
            | Some(cli::Commands::Metrics)
            | Some(cli::Commands::Rules { .. })
            | Some(cli::Commands::Domain { .. })
            | Some(cli::Commands::Config { .. })
            | Some(cli::Commands::Update { .. })
    ) || args.test_config;
    let log_level = if is_quiet_cli {
        "error"
    } else {
        args.log_level.as_str()
    };
    logging::init_logging(log_level)?;

    // `-t` short-flag is a Nginx-ism — alias for `config test`.
    if args.test_config {
        return run_config_test(&args.config);
    }

    match args.command {
        Some(cli::Commands::Start) | None => {
            control::write_pid_file(control::default_pid_path())?;
            let cfg = load_config(&args.config)?;
            server::run_server(args.config, cfg).await
        }
        Some(cli::Commands::Stop) => control::stop(control::default_pid_path()),
        Some(cli::Commands::Restart) => {
            control::stop(control::default_pid_path())?;
            control::write_pid_file(control::default_pid_path())?;
            let cfg = load_config(&args.config)?;
            server::run_server(args.config, cfg).await
        }
        Some(cli::Commands::Reload) => {
            // Validate locally so misconfigs don't blast the running
            // proxy. The actual hot-swap happens via POST /admin/reload
            // — print the curl invocation so operators don't memorise it.
            let summary = dsl::validate_file(&args.config)?;
            println!("{}", dsl::render_summary(&summary));
            println!(
                "config is valid — to apply, POST /admin/reload on the running aegis admin port"
            );
            Ok(())
        }
        Some(cli::Commands::Metrics) => {
            let summary = domains::metrics_summary()?;
            println!("{}", summary);
            Ok(())
        }
        Some(cli::Commands::Rules { command }) => match command {
            cli::RulesCommands::Validate => {
                let summary = dsl::validate_file(&args.config)?;
                println!("Rules/config are valid: {}", args.config.display());
                println!("{}", dsl::render_summary(&summary));
                Ok(())
            }
        },
        Some(cli::Commands::Domain { command }) => match command {
            cli::DomainCommands::Add { domain } => domains::add_domain(&domain),
            cli::DomainCommands::List => domains::list_domains(),
            cli::DomainCommands::Remove { domain } | cli::DomainCommands::Rm { domain } => {
                domains::remove_domain(&domain)
            }
            cli::DomainCommands::Stats { domain } => domains::stats_domain(&domain),
        },
        Some(cli::Commands::Web { command }) => {
            // The CLI doesn't need a running daemon — it mutates the
            // state file directly and the daemon picks it up via mtime
            // poll on the next request. Resolve the path the same way
            // the daemon does: admin.web_state_path in the config,
            // otherwise the hard-coded default.
            let state_path = match load_config(&args.config) {
                Ok(cfg) => cfg
                    .admin
                    .as_ref()
                    .and_then(|a| a.web_state_path.clone())
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from(web_admin::DEFAULT_STATE_PATH)),
                Err(_) => std::path::PathBuf::from(web_admin::DEFAULT_STATE_PATH),
            };
            let store = web_admin::WebAdminStore::open(state_path.clone())?;
            match command {
                cli::WebCommands::ResetAdmin => {
                    let new_pwd = store.reset_admin()?;
                    println!("✓ web admin reset");
                    println!("  email:    {}", web_admin::DEFAULT_EMAIL);
                    println!("  password: {new_pwd}");
                    println!("  state:    {}", state_path.display());
                    println!();
                    println!("Log in once with these credentials — the panel will force you to");
                    println!("change both email and password before anything else.");
                }
                cli::WebCommands::Stop => {
                    store.set_enabled(false)?;
                    println!("✓ web panel stopped — /admin/ui and /admin/api/* now return 503");
                    println!("  state: {}", state_path.display());
                }
                cli::WebCommands::Start => {
                    store.set_enabled(true)?;
                    println!("✓ web panel started");
                    println!("  state: {}", state_path.display());
                }
                cli::WebCommands::Status => {
                    let snap = store.snapshot();
                    println!("enabled:      {}", snap.enabled);
                    println!("email:        {}", snap.email);
                    println!("must_change:  {}", snap.must_change);
                    println!("sessions:     {}", snap.sessions.len());
                    println!("state path:   {}", state_path.display());
                }
            }
            Ok(())
        }
        Some(cli::Commands::Update {
            check,
            r#ref,
            no_backup,
        }) => run_update(check, &r#ref, no_backup),
        Some(cli::Commands::Config { command }) => match command {
            cli::ConfigCommands::Test => run_config_test(&args.config),
            cli::ConfigCommands::Migrate { from, to } => {
                let cfg = config::AppConfig::from_path(&from)?;
                let text = dsl::migrate_from_toml(&cfg);
                match to {
                    Some(path) => {
                        std::fs::write(&path, text)?;
                        eprintln!("wrote {}", path.display());
                    }
                    None => print!("{text}"),
                }
                Ok(())
            }
        },
    }
}

/// `aegis update` — snapshot /etc/aegis (config, sites, secrets, certs),
/// then rebuild + restart from the TRUSTED source repo via install.sh.
/// CLI-only by design: the in-panel auto-apply path was removed in V233
/// (it downloaded + executed an unverified binary — RCE-class). This
/// command rebuilds from your own source and never downloads a prebuilt
/// binary, so it is safe for an operator to run on the host. Operator
/// data under /etc/aegis is preserved (install.sh only touches the source
/// tree + /usr/local/bin), and is additionally snapshotted first.
fn run_update(check: bool, git_ref: &str, no_backup: bool) -> Result<()> {
    use std::process::Command;
    let src = std::env::var("AEGIS_SRC").unwrap_or_else(|_| "/usr/local/src/aegis".to_string());
    let installer = format!("{src}/install.sh");

    // --- check mode: read-only, no privileges required ---
    if check {
        let _ = Command::new("git")
            .args(["-C", &src, "fetch", "--quiet", "origin"])
            .status();
        match (
            git_rev(&src, "HEAD"),
            git_rev(&src, &format!("origin/{git_ref}")),
        ) {
            (Some(l), Some(r)) if l == r => {
                println!("aegis is up to date (origin/{git_ref} @ {})", short(&l));
            }
            (Some(l), Some(r)) => {
                let behind = Command::new("git")
                    .args(["-C", &src, "rev-list", "--count", &format!("{l}..{r}")])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "?".into());
                println!(
                    "update available: {behind} commit(s) behind origin/{git_ref} ({} -> {})",
                    short(&l),
                    short(&r)
                );
                println!("apply with:  sudo aegis update");
            }
            _ => println!(
                "could not determine update status (is {src} a git checkout with a reachable remote?)"
            ),
        }
        return Ok(());
    }

    // --- apply mode: needs root (reinstalls the binary + restarts systemd) ---
    // SAFETY: geteuid() is always-succeeds and has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!(
            "aegis update must run as root (it rebuilds + reinstalls the binary and restarts \
             the service).\n    try:  sudo aegis update"
        );
    }
    if !Path::new(&installer).is_file() {
        anyhow::bail!(
            "installer not found at {installer}.\n    set AEGIS_SRC to your Aegis source tree, \
             or run install.sh manually."
        );
    }

    // 1. Snapshot /etc/aegis so config/sites/secrets/certs are recoverable.
    if !no_backup && Path::new("/etc/aegis").is_dir() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dir = "/var/backups/aegis";
        std::fs::create_dir_all(dir).ok();
        let tarball = format!("{dir}/aegis-etc-{ts}.tgz");
        let ok = Command::new("tar")
            .args(["czf", &tarball, "-C", "/etc", "aegis"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            println!("data backup:  {tarball}");
        } else {
            anyhow::bail!(
                "backup of /etc/aegis failed; aborting update (re-run with --no-backup to skip)"
            );
        }
    }

    // 2. Rebuild + restart from the trusted source. install.sh preserves
    //    /etc/aegis (it only touches the source tree + /usr/local/bin).
    println!(
        "updating to '{git_ref}' via install.sh (rebuilds from source — this can take several minutes)…"
    );
    let status = Command::new("bash")
        .arg(&installer)
        .arg("--update")
        .env("AEGIS_VERSION", git_ref)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()?;
    if !status.success() {
        anyhow::bail!(
            "install.sh --update failed ({status}). Your previous binary + data are unchanged; \
             the pre-update backup (if made) is under /var/backups/aegis."
        );
    }
    println!("aegis updated to '{git_ref}'.");
    Ok(())
}

/// Resolve a git ref to its full commit hash in `src`, or None.
fn git_rev(src: &str, refname: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["-C", src, "rev-parse", refname])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn short(rev: &str) -> &str {
    &rev[..rev.len().min(12)]
}

fn run_config_test(path: &Path) -> Result<()> {
    match dsl::validate_file(path) {
        Ok(summary) => {
            println!("{}", dsl::render_summary(&summary));
            Ok(())
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
