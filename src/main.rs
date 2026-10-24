mod clash;
mod config;
mod core;
mod gen;
mod net;
mod parse;
mod platform;
mod ui;

use anyhow::Result;
use directories::ProjectDirs;
use std::path::{Path, PathBuf};
use tracing_appender::non_blocking::WorkerGuard;

pub fn data_dir() -> Result<PathBuf> {
    // On Linux: respect SUDO_USER so we use the real user's home, not root's.
    #[cfg(target_os = "linux")]
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            let home = PathBuf::from("/home").join(&sudo_user);
            let dir = home.join(".config").join("vpnt");
            std::fs::create_dir_all(&dir)?;
            return Ok(dir);
        }
    }

    let proj = ProjectDirs::from("", "", "vpnt")
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?;
    let dir = proj.config_dir().to_path_buf();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn setup_logging(data: &Path) -> Result<WorkerGuard> {
    let log_dir = data.join("logs");
    std::fs::create_dir_all(&log_dir)?;
    let file_appender = tracing_appender::rolling::daily(&log_dir, "vpnt.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .init();
    Ok(guard)
}

#[tokio::main]
async fn main() -> Result<()> {
    let data = data_dir()?;
    let _guard = setup_logging(&data)?;
    tracing::info!("vpnt starting");

    let supervisor = core::Supervisor::new(
        platform::singbox_bin(&data),
        data.join(gen::CONFIG_FILENAME),
    );
    ui::run(supervisor, data).await?;

    tracing::info!("vpnt exiting");
    Ok(())
}
