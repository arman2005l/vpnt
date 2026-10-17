//! Process supervision for sing-box.
//!
//! Spawns sing-box as a child process, pipes its stderr to the tracing log,
//! and watches for unexpected exits.  A `Supervisor` is the single owner of
//! the child: `start` / `stop` / `restart` are the only public operations.
//!
//! M1 scope: local spawn only (no systemd integration).

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, warn};

// ── Public types ──────────────────────────────────────────────────────────────

/// Current state of the managed sing-box process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// No process has been started yet (or it was cleanly stopped).
    Stopped,
    /// sing-box is running; field is the OS PID.
    Running(u32),
    /// sing-box exited with a non-zero code or a signal.
    Failed(String),
}

/// Owns and supervises a sing-box child process.
///
/// Clone-cheap: the inner state lives behind an `Arc<Mutex<...>>`.
#[derive(Clone)]
pub struct Supervisor {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    bin:         PathBuf,
    config_path: PathBuf,
    child:       Option<Child>,
    status:      Status,
}

// ── Supervisor impl ───────────────────────────────────────────────────────────

impl Supervisor {
    /// Create a new supervisor.  Nothing is spawned yet.
    ///
    /// * `bin`         – path to the sing-box binary (absolute or on PATH)
    /// * `config_path` – path to the generated `config.json`
    pub fn new(bin: PathBuf, config_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                bin,
                config_path,
                child: None,
                status: Status::Stopped,
            })),
        }
    }

    /// Start sing-box.  Returns an error if it is already running.
    pub async fn start(&self) -> Result<()> {
        let mut g = self.inner.lock().await;
        if matches!(g.status, Status::Running(_)) {
            bail!("sing-box is already running");
        }
        spawn_child(&mut g)?;
        Ok(())
    }

    /// Stop sing-box gracefully (SIGTERM → wait 3 s → SIGKILL).
    pub async fn stop(&self) -> Result<()> {
        let mut g = self.inner.lock().await;
        match g.child.take() {
            None => bail!("sing-box is not running"),
            Some(mut child) => {
                terminate_child(&mut child).await;
                g.status = Status::Stopped;
            }
        }
        Ok(())
    }

    /// Stop (if running) then start.
    pub async fn restart(&self) -> Result<()> {
        {
            let mut g = self.inner.lock().await;
            if let Some(mut child) = g.child.take() {
                terminate_child(&mut child).await;
            }
            g.status = Status::Stopped;
        }
        // Small gap so the OS releases the port.
        sleep(Duration::from_millis(200)).await;
        self.start().await
    }

    /// Return a snapshot of the current status.
    pub async fn status(&self) -> Status {
        self.inner.lock().await.status.clone()
    }

    /// Poll the child: if it has exited, update status and return `false`.
    /// Call this periodically from the UI event loop.
    pub async fn poll(&self) -> bool {
        let mut g = self.inner.lock().await;
        let Some(child) = g.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(exit)) => {
                let msg = if exit.success() {
                    "exited with status 0".into()
                } else {
                    format!("exited: {exit}")
                };
                warn!("sing-box {}", msg);
                g.child = None;
                g.status = Status::Failed(msg);
                false
            }
            Ok(None) => true,  // still running
            Err(e) => {
                error!("waitpid error: {e}");
                g.status = Status::Failed(e.to_string());
                false
            }
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn spawn_child(g: &mut Inner) -> Result<()> {
    let mut cmd = Command::new(&g.bin);
    cmd.arg("run")
        .arg("-c")
        .arg(&g.config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())   // sing-box writes logs itself
        .stderr(Stdio::piped()); // we capture stderr for tracing

    // Ensure the child process group dies with us on Linux.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                // Create a new process group so we can kill the whole group.
                libc::setsid();
                Ok(())
            });
        }
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn sing-box: {}", g.bin.display()))?;

    let pid = child.id().unwrap_or(0);
    info!("sing-box started (pid {pid})");

    // Pipe stderr to tracing in a background task.
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // sing-box lines are JSON; log them verbatim at debug level.
                tracing::debug!(target: "singbox", "{line}");
            }
        });
    }

    g.status = Status::Running(pid);
    g.child = Some(child);
    Ok(())
}

/// Best-effort graceful termination.
async fn terminate_child(child: &mut Child) {
    // Ask nicely first.
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            // SAFETY: kill(2) with SIGTERM is always safe to call.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        }
    }
    #[cfg(windows)]
    {
        let _ = child.kill().await;
    }

    // Wait up to 3 seconds, then force-kill.
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        child.wait(),
    )
    .await;

    if result.is_err() {
        warn!("sing-box did not exit after SIGTERM; sending SIGKILL");
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_supervisor() -> Supervisor {
        Supervisor::new(
            PathBuf::from("/nonexistent/sing-box"),
            PathBuf::from("/nonexistent/config.json"),
        )
    }

    #[tokio::test]
    async fn initial_status_is_stopped() {
        let sv = make_supervisor();
        assert_eq!(sv.status().await, Status::Stopped);
    }

    #[tokio::test]
    async fn stop_while_stopped_errors() {
        let sv = make_supervisor();
        assert!(sv.stop().await.is_err());
    }

    #[tokio::test]
    async fn start_with_missing_binary_errors() {
        let sv = make_supervisor();
        assert!(sv.start().await.is_err());
    }

    #[tokio::test]
    async fn poll_when_stopped_returns_false() {
        let sv = make_supervisor();
        assert!(!sv.poll().await);
    }

    #[tokio::test]
    async fn start_twice_errors() {
        // We can't actually spawn, so just verify the guard fires if we
        // manually inject a Running status.
        let sv = make_supervisor();
        {
            let mut g = sv.inner.lock().await;
            g.status = Status::Running(9999);
        }
        assert!(sv.start().await.is_err());
    }
}
