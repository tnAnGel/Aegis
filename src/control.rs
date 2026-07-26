use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};

/// Default path to process PID file.
pub fn default_pid_path() -> PathBuf {
    PathBuf::from("aegis.pid")
}

/// Write current process PID to a file.
pub fn write_pid_file(path: PathBuf) -> Result<()> {
    fs::write(&path, std::process::id().to_string())
        .with_context(|| format!("failed to write pid file: {}", path.display()))
}

/// Stop running process by PID file.
pub fn stop(path: PathBuf) -> Result<()> {
    if !Path::new(&path).exists() {
        println!("Aegis is not running (pid file not found)");
        return Ok(());
    }

    let pid = fs::read_to_string(&path)
        .with_context(|| format!("failed to read pid file: {}", path.display()))?;
    let pid = pid.trim();

    #[cfg(windows)]
    {
        let status = Command::new("taskkill")
            .args(["/PID", pid, "/T", "/F"])
            .status()
            .context("failed to execute taskkill")?;
        anyhow::ensure!(status.success(), "taskkill failed for PID {pid}");
    }

    #[cfg(not(windows))]
    {
        let status = Command::new("kill")
            .args(["-TERM", pid])
            .status()
            .context("failed to execute kill")?;
        anyhow::ensure!(status.success(), "kill failed for PID {pid}");
    }

    let _ = fs::remove_file(&path);
    println!("Stopped Aegis process PID {pid}");
    Ok(())
}
