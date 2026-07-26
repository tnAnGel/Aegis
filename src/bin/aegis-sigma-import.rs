//! V196 — Sigma rule importer CLI.
//!
//! Walks a directory of `*.yml` Sigma rules, filters to the
//! `logsource.category: webserver` (and apache/nginx/iis/haproxy)
//! subset, and emits a consolidated TOML rule file ready to drop
//! into `waf.rule_files`.
//!
//! Usage:
//!
//! ```text
//! aegis-sigma-import \
//!     --input /path/to/sigma/rules \
//!     --output /etc/aegis/sigma-imported.toml \
//!     [--skipped-log /tmp/skipped.txt]
//! ```
//!
//! Exit code 0 even when some rules were skipped — the importer
//! tries best-effort. The skip log is the canonical record of
//! what didn't convert and why.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "aegis-sigma-import",
    about = "Convert SigmaHQ webserver rules → Aegis WAF rule TOML"
)]
struct Cli {
    /// Directory containing Sigma `*.yml` rules. Walked recursively.
    #[arg(short, long)]
    input: PathBuf,

    /// Output TOML file. Will be overwritten.
    #[arg(short, long)]
    output: PathBuf,

    /// Optional path to write the skip log (which rules didn't
    /// convert + why). Useful for triaging hand-port candidates.
    #[arg(long)]
    skipped_log: Option<PathBuf>,

    /// Verbose progress on stderr.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    if !args.input.is_dir() {
        anyhow::bail!("input {:?} is not a directory", args.input);
    }
    let started = std::time::Instant::now();
    eprintln!("aegis-sigma-import: walking {:?}", args.input);
    let out = aegis::sigma::convert_directory(&args.input)
        .with_context(|| format!("walk {:?}", args.input))?;

    let toml = aegis::sigma::render_toml(&out.rules);
    std::fs::write(&args.output, toml).with_context(|| format!("write {:?}", args.output))?;

    let total_seen = out.rules.len() + out.skipped.len();
    let pct = if total_seen == 0 {
        0.0
    } else {
        out.rules.len() as f32 * 100.0 / total_seen as f32
    };
    eprintln!(
        "aegis-sigma-import: converted {} rules, skipped {} ({}%) in {:.2}s",
        out.rules.len(),
        out.skipped.len(),
        pct as u32,
        started.elapsed().as_secs_f32(),
    );
    eprintln!("aegis-sigma-import: wrote {:?}", args.output);

    if let Some(skipped_path) = args.skipped_log {
        let mut log = String::with_capacity(out.skipped.len() * 200);
        log.push_str("# Sigma rules skipped during conversion.\n");
        log.push_str("# Format: <source_file> | <title> | <reason>\n\n");
        for n in &out.skipped {
            log.push_str(&format!("{} | {} | {}\n", n.source_file, n.title, n.reason));
        }
        std::fs::write(&skipped_path, log)
            .with_context(|| format!("write skip log {:?}", skipped_path))?;
        eprintln!("aegis-sigma-import: skip log → {:?}", skipped_path);
    }

    if args.verbose {
        let mut by_reason: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for n in &out.skipped {
            *by_reason.entry(n.reason.clone()).or_default() += 1;
        }
        let mut sorted: Vec<_> = by_reason.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!("aegis-sigma-import: skip reasons (top 10):");
        for (reason, n) in sorted.into_iter().take(10) {
            eprintln!("    {n:>5}  {reason}");
        }
    }

    Ok(())
}
