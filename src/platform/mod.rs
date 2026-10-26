//! Platform-specific helpers: data-directory resolution, sing-box binary path.
//!
//! On Linux, when the process is run under sudo, `SUDO_USER` is used to
//! resolve the real user's home directory so data never lands in /root.
//! The `directories` crate handles cross-platform XDG / AppData conventions.

use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;

const QUALIFIER: &str = "";
const ORG: &str = "";
const APP: &str = "vpnt";

// ── Data directory ────────────────────────────────────────────────────────────

/// Resolve (and create) the application data directory.
///
/// Priority on Linux:
///   1. `$SUDO_USER` home → `~/.local/share/vpnt`
///   2. `$XDG_DATA_HOME/vpnt`
///   3. `~/.local/share/vpnt`  (via `directories`)
///
/// On Windows: `%APPDATA%\vpnt`
pub fn data_dir() -> Result<PathBuf> {
    let dir = resolve()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create data dir: {}", dir.display()))?;
    Ok(dir)
}

#[cfg(target_os = "linux")]
fn resolve() -> Result<PathBuf> {
    // When invoked as `sudo vpnt`, write under the real user's home.
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            // Honour $HOME override first (e.g. `sudo -H`), then /home/<user>.
            let candidates: &[PathBuf] = &[
                std::env::var("HOME").ok().map(PathBuf::from).unwrap_or_default(),
                PathBuf::from("/home").join(&sudo_user),
            ];
            for base in candidates {
                if base.is_dir() {
                    return Ok(base.join(".local/share").join(APP));
                }
            }
        }
    }

    // Fall back to the XDG-aware `directories` crate.
    project_dirs().map(|d| d.data_dir().to_path_buf())
}

#[cfg(not(target_os = "linux"))]
fn resolve() -> Result<PathBuf> {
    project_dirs().map(|d| d.data_dir().to_path_buf())
}

fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from(QUALIFIER, ORG, APP)
        .context("cannot determine home directory")
}

// ── sing-box binary ───────────────────────────────────────────────────────────

/// Return the path to the sing-box binary.
///
/// Looks for a bundled binary in `data_dir` first; falls back to the system
/// PATH so a globally installed sing-box also works.
pub fn singbox_bin(data_dir: &std::path::Path) -> PathBuf {
    let local = data_dir.join(SINGBOX_BIN);
    if local.exists() {
        local
    } else {
        PathBuf::from(SINGBOX_BIN)
    }
}

#[cfg(windows)]
const SINGBOX_BIN: &str = "sing-box.exe";
#[cfg(not(windows))]
const SINGBOX_BIN: &str = "sing-box";

// ── Privilege helpers ─────────────────────────────────────────────────────────

/// True when the effective user is root (Linux/macOS) or an Administrator
/// (Windows stub — always false; TUN on Windows needs a separate elevation
/// flow that is not implemented).
#[cfg(not(windows))]
pub fn is_root() -> bool {
    effective_uid() == 0
}

#[cfg(windows)]
pub fn is_root() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn effective_uid() -> u32 {
    // Read euid from /proc/self/status — no libc dependency needed.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2)) // effective UID
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(u32::MAX)
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn effective_uid() -> u32 {
    u32::MAX // non-root on platforms we do not need TUN for in M1
}

// ── Process stop ──────────────────────────────────────────────────────────────

/// Ask process `pid` to exit gracefully.
///
/// Returns `true` if a graceful request was sent.  `false` means the caller
/// must force-kill (always the case on Windows, which has no SIGTERM).
#[cfg(unix)]
pub fn request_terminate(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: kill(2) only sends a signal; it touches no memory of ours.
    unsafe { libc::kill(pid, libc::SIGTERM) == 0 }
}

#[cfg(windows)]
pub fn request_terminate(_pid: u32) -> bool {
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_created() {
        // Smoke-test: must return without error and point to a real path.
        let d = data_dir().expect("data_dir failed");
        assert!(d.exists(), "data dir was not created");
    }

    #[test]
    fn singbox_bin_fallback() {
        let tmp = std::env::temp_dir().join("vpnt_test_no_such_dir_xyz");
        let _ = std::fs::create_dir_all(&tmp);
        // No binary placed in tmp → should fall back to bare name.
        let bin = singbox_bin(&tmp);
        assert_eq!(bin, PathBuf::from(SINGBOX_BIN));
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn singbox_bin_local_preferred() {
        let tmp = std::env::temp_dir().join("vpnt_test_singbox_local");
        let _ = std::fs::create_dir_all(&tmp);
        let fake = tmp.join(SINGBOX_BIN);
        std::fs::write(&fake, b"").unwrap();
        assert_eq!(singbox_bin(&tmp), fake);
        let _ = std::fs::remove_file(&fake);
        let _ = std::fs::remove_dir(&tmp);
    }
}
