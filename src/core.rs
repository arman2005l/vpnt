//! Process supervision for sing-box.
//!
//! Spawns sing-box as a child process, pipes its stderr to the tracing log,
//! and watches for unexpected exits.  A `Supervisor` is the single owner of
//! the child: `start` / `stop` / `restart` are the only public operations.
//!
//! M1 scope: local spawn only (no systemd integration).

use std::path::{Path, PathBuf};
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

    /// Run `sing-box check -c <path>`; the error carries sing-box's message.
    pub async fn check_config(&self, path: &Path) -> Result<()> {
        let bin = self.inner.lock().await.bin.clone();
        let out = Command::new(&bin)
            .arg("check")
            .arg("--disable-color")
            .arg("-c")
            .arg(path)
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("run {} check", bin.display()))?;
        if out.status.success() {
            return Ok(());
        }
        let mut text = String::from_utf8_lossy(&out.stderr).to_string();
        text.push_str(&String::from_utf8_lossy(&out.stdout));
        bail!("{}", check_error_message(&text))
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

/// Pick the most useful line of `sing-box check` output.
fn check_error_message(output: &str) -> String {
    let lines: Vec<&str> = output.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let line = lines
        .iter()
        .find(|l| l.starts_with("FATAL") || l.starts_with("ERROR"))
        .or(lines.last())
        .copied()
        .unwrap_or("sing-box check failed");
    match line.split_once("] ") {
        Some((prefix, rest)) if prefix.starts_with("FATAL[") || prefix.starts_with("ERROR[") => {
            rest.to_string()
        }
        _ => line.to_string(),
    }
}

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
    async fn check_with_missing_binary_errors() {
        let sv = make_supervisor();
        assert!(sv.check_config(Path::new("/nonexistent/config.json")).await.is_err());
    }

    #[test]
    fn check_error_message_strips_prefix() {
        let out = "WARN[0000] something deprecated\nFATAL[0000] decode config: bad thing\n";
        assert_eq!(check_error_message(out), "decode config: bad thing");
        assert_eq!(check_error_message(""), "sing-box check failed");
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
