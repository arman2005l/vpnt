//! Dashboard data and the background monitor that feeds it while connected.
//!
//! The monitor runs only between connect and disconnect.  It streams
//! `/traffic`, polls `/connections` every second and, on demand, measures
//! latency (Clash delay test) and the exit IP (via the local HTTP inbound).

use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::clash::{self, ClashApi, ConnectionsSummary, Traffic};
use crate::net;

/// Number of one-second samples kept for the sparklines.
pub const HISTORY_LEN: usize = 60;

const POLL_EVERY: Duration = Duration::from_secs(1);

/// A value that is being fetched, has been fetched, or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe<T> {
    Idle,
    Pending,
    Ok(T),
    Failed(String),
}

/// Message from the monitor tasks.  `generation` drops stale results that
/// arrive after a reconnect.
#[derive(Debug, Clone)]
pub struct DashUpdate {
    pub generation: u64,
    pub kind: DashUpdateKind,
}

#[derive(Debug, Clone)]
pub enum DashUpdateKind {
    Traffic(Traffic),
    Connections(ConnectionsSummary),
    ExitIp(Result<String, String>),
    Latency(Result<u64, String>),
}

/// Everything the Dashboard tab shows besides process status.
#[derive(Debug, Clone)]
pub struct DashboardState {
    pub connected_at: Option<Instant>,
    pub up_history: VecDeque<u64>,
    pub down_history: VecDeque<u64>,
    pub current: Traffic,
    pub connections: ConnectionsSummary,
    pub exit_ip: Probe<String>,
    pub latency_ms: Probe<u64>,
    generation: u64,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            connected_at: None,
            up_history: VecDeque::with_capacity(HISTORY_LEN),
            down_history: VecDeque::with_capacity(HISTORY_LEN),
            current: Traffic::default(),
            connections: ConnectionsSummary::default(),
            exit_ip: Probe::Idle,
            latency_ms: Probe::Idle,
            generation: 0,
        }
    }
}

impl DashboardState {
    /// Reset for a new session and return its generation number.
    pub fn begin_session(&mut self) -> u64 {
        let generation = self.generation + 1;
        *self = Self { generation, ..Self::default() };
        self.connected_at = Some(Instant::now());
        generation
    }

    /// Clear everything; late updates from old tasks are ignored.
    pub fn end_session(&mut self) {
        let generation = self.generation + 1;
        *self = Self { generation, ..Self::default() };
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn uptime(&self) -> Option<Duration> {
        self.connected_at.map(|t| t.elapsed())
    }

    pub fn apply(&mut self, update: DashUpdate) {
        if update.generation != self.generation || self.connected_at.is_none() {
            return;
        }
        match update.kind {
            DashUpdateKind::Traffic(sample) => {
                self.current = sample;
                push_capped(&mut self.up_history, sample.up);
                push_capped(&mut self.down_history, sample.down);
            }
            DashUpdateKind::Connections(summary) => self.connections = summary,
            DashUpdateKind::ExitIp(res) => {
                self.exit_ip = match res {
                    Ok(ip) => Probe::Ok(ip),
                    Err(e) => Probe::Failed(e),
                }
            }
            DashUpdateKind::Latency(res) => {
                self.latency_ms = match res {
                    Ok(ms) => Probe::Ok(ms),
                    Err(e) => Probe::Failed(e),
                }
            }
        }
    }
}

fn push_capped(buf: &mut VecDeque<u64>, value: u64) {
    if buf.len() >= HISTORY_LEN {
        buf.pop_front();
    }
    buf.push_back(value);
}

/// `1536` → `"1.5 KiB"`.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// `3725 s` → `"01:02:05"`.
pub fn format_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs / 60) % 60, secs % 60)
}

// ── Monitor ───────────────────────────────────────────────────────────────────

/// Endpoints read back from the generated sing-box config.
#[derive(Debug, Clone)]
pub struct MonitorTargets {
    pub api: ClashApi,
    pub proxy_url: Option<String>,
}

impl MonitorTargets {
    pub fn from_config_file(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let config: serde_json::Value = serde_json::from_str(&text)?;
        let api = ClashApi::from_config(&config)?;
        let proxy_url = net::local_http_proxy_url(&config);
        Ok(Self { api, proxy_url })
    }
}

/// Background tasks for one connected session.  Aborted on drop.
pub struct Monitor {
    targets: MonitorTargets,
    generation: u64,
    tx: mpsc::UnboundedSender<DashUpdate>,
    tasks: Vec<JoinHandle<()>>,
}

impl Monitor {
    /// Start traffic streaming and connection polling, plus one probe round.
    pub fn start(
        targets: MonitorTargets,
        generation: u64,
        tx: mpsc::UnboundedSender<DashUpdate>,
    ) -> Self {
        let mut monitor = Self { targets, generation, tx, tasks: Vec::new() };
        monitor.tasks.push(spawn_traffic(
            monitor.targets.api.clone(),
            generation,
            monitor.tx.clone(),
        ));
        monitor.tasks.push(spawn_connections(
            monitor.targets.api.clone(),
            generation,
            monitor.tx.clone(),
        ));
        monitor.refresh();
        monitor
    }

    /// Re-measure exit IP and latency.
    pub fn refresh(&mut self) {
        self.tasks.retain(|t| !t.is_finished());
        let api = self.targets.api.clone();
        let proxy_url = self.targets.proxy_url.clone();
        let generation = self.generation;
        let tx = self.tx.clone();
        self.tasks.push(tokio::spawn(async move {
            // Give sing-box a moment to bind its inbounds after start.
            wait_for_api(&api).await;
            let latency = api.delay(clash::PROXY_TAG).await.map_err(|e| format!("{e:#}"));
            let _ = tx.send(DashUpdate { generation, kind: DashUpdateKind::Latency(latency) });
        }));

        let api = self.targets.api.clone();
        let tx = self.tx.clone();
        self.tasks.push(tokio::spawn(async move {
            let res = match proxy_url {
                Some(url) => {
                    wait_for_api(&api).await;
                    net::fetch_exit_ip(&url).await.map_err(|e| format!("{e:#}"))
                }
                None => Err("no local HTTP inbound in config".to_string()),
            };
            let _ = tx.send(DashUpdate { generation, kind: DashUpdateKind::ExitIp(res) });
        }));
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Wait (up to ~5 s) until the Clash API answers, i.e. sing-box is up.
async fn wait_for_api(api: &ClashApi) {
    for _ in 0..10 {
        if api.connections().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn spawn_traffic(
    api: ClashApi,
    generation: u64,
    tx: mpsc::UnboundedSender<DashUpdate>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (sample_tx, mut sample_rx) = mpsc::unbounded_channel();
            let api_clone = api.clone();
            let stream = tokio::spawn(async move { api_clone.stream_traffic(sample_tx).await });
            while let Some(sample) = sample_rx.recv().await {
                if tx
                    .send(DashUpdate { generation, kind: DashUpdateKind::Traffic(sample) })
                    .is_err()
                {
                    stream.abort();
                    return;
                }
            }
            if let Ok(Err(e)) = stream.await {
                tracing::debug!("traffic stream: {e:#}; retrying");
            }
            if tx.is_closed() {
                return;
            }
            tokio::time::sleep(POLL_EVERY).await;
        }
    })
}

fn spawn_connections(
    api: ClashApi,
    generation: u64,
    tx: mpsc::UnboundedSender<DashUpdate>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match api.connections().await {
                Ok(summary) => {
                    let update =
                        DashUpdate { generation, kind: DashUpdateKind::Connections(summary) };
                    if tx.send(update).is_err() {
                        return;
                    }
                }
                Err(e) => tracing::debug!("connections poll: {e:#}"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_capped_and_stale_updates_ignored() {
        let mut d = DashboardState::default();
        let generation = d.begin_session();
        for i in 0..(HISTORY_LEN as u64 + 5) {
            d.apply(DashUpdate {
                generation,
                kind: DashUpdateKind::Traffic(Traffic { up: i, down: i * 2 }),
            });
        }
        assert_eq!(d.down_history.len(), HISTORY_LEN);
        assert_eq!(d.up_history.front(), Some(&5));
        assert_eq!(d.current.down, (HISTORY_LEN as u64 + 4) * 2);

        d.apply(DashUpdate {
            generation: generation - 1,
            kind: DashUpdateKind::Latency(Ok(10)),
        });
        assert_eq!(d.latency_ms, Probe::Idle);

        d.end_session();
        d.apply(DashUpdate { generation, kind: DashUpdateKind::Latency(Ok(10)) });
        assert_eq!(d.latency_ms, Probe::Idle);
        assert!(d.up_history.is_empty());
    }

    #[test]
    fn formatting() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(format_uptime(Duration::from_secs(3725)), "01:02:05");
    }
}
