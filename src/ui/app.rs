//! Application state and the actions that mutate it.
//!
//! `AppState` is the single source of truth for the TUI.  It is not
//! async-aware itself; callers in the event loop drive it with `.handle()`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::config::{ProxyConfig, Store};
use crate::core::{Status, Supervisor};
use crate::gen;
use crate::net;
use crate::parse;
use crate::ui::dashboard::{DashUpdate, DashboardState, Monitor, MonitorTargets, Probe};

/// How long a status-line notice stays visible.
const NOTICE_TTL: Duration = Duration::from_secs(6);

// ── Actions ───────────────────────────────────────────────────────────────────

/// Every user gesture maps to one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Tick,
    Redraw,
    Quit,
    ToggleProxy,
    Restart,
    SelectNext,
    SelectPrev,
    Confirm,
    NextTab,
    PrevTab,
    ToggleHelp,
    /// Dashboard: re-measure exit IP and latency.
    Refresh,
    /// Configs tab: open the "add config" prompt.
    AddConfig,
    /// Configs tab: open the rename prompt for the selected config.
    RenameConfig,
    /// Configs tab: ask to delete the selected config.
    DeleteConfig,
    /// Configs tab: TCP-ping every config.
    PingAll,
    /// Text input while a prompt is open.
    InputChar(char),
    InputBackspace,
    InputSubmit,
    InputCancel,
    /// Bracketed paste payload.
    Paste(String),
}

/// Modal input state for the Configs tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Adding(String),
    Renaming(String),
    ConfirmDelete,
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Status,
    Proxies,
    Settings,
    Logs,
}

impl Tab {
    pub const ALL: &'static [Tab] = &[Tab::Status, Tab::Proxies, Tab::Settings, Tab::Logs];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Status   => "Dashboard",
            Tab::Proxies  => "Configs",
            Tab::Settings => "Settings",
            Tab::Logs     => "Logs",
        }
    }

    fn next(self) -> Tab {
        let pos = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL[(pos + 1) % Self::ALL.len()]
    }

    fn prev(self) -> Tab {
        let pos = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL[(pos + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

// ── AppState ──────────────────────────────────────────────────────────────────

/// All runtime state the TUI needs.
pub type App = AppState;
pub struct AppState {
    // ── Supervision ───────────────────────────────────────────────────────
    pub supervisor: Supervisor,
    pub proc_status: Status,

    // ── Persistent data ───────────────────────────────────────────────────
    pub store: Store,
    pub data_dir: PathBuf,

    // ── UI state ──────────────────────────────────────────────────────────
    pub active_tab: Tab,
    pub proxy_cursor: usize,
    pub show_help: bool,

    /// Ring-buffer of log lines forwarded from the tracing layer (M2).
    pub log_lines: Vec<String>,

    /// Non-fatal notices shown in the status bar (cleared on next tick).
    pub notice: Option<String>,

    /// When `notice` was set; it is cleared after `NOTICE_TTL`.
    pub notice_at: Option<Instant>,
    /// Configs tab modal state.
    pub input_mode: InputMode,
    /// True while a ping-all is in flight.
    pub pinging: bool,
    ping_tx: mpsc::UnboundedSender<Vec<(String, Option<u64>)>>,
    ping_rx: mpsc::UnboundedReceiver<Vec<(String, Option<u64>)>>,
    /// Live dashboard data; reset on every connect/disconnect.
    pub dashboard: DashboardState,
    monitor: Option<Monitor>,
    dash_tx: mpsc::UnboundedSender<DashUpdate>,
    dash_rx: mpsc::UnboundedReceiver<DashUpdate>,
}

impl AppState {
    pub fn new(supervisor: Supervisor, data_dir: PathBuf) -> Self {
        let mut store = Store::load(&data_dir).unwrap_or_else(|e| {
            tracing::warn!("could not load store: {e}; using defaults");
            Store::default()
        });
        store.dir = data_dir.clone();
        let mut changed = false;
        for p in store.proxies.iter_mut() {
            if p.id.is_empty() {
                p.id = uuid::Uuid::new_v4().to_string();
                changed = true;
            }
        }
        if changed {
            if let Err(e) = store.save(&data_dir) {
                tracing::warn!("could not save config ids: {e}");
            }
        }
        let (ping_tx, ping_rx) = mpsc::unbounded_channel();
        let (dash_tx, dash_rx) = mpsc::unbounded_channel();

        Self {
            supervisor,
            proc_status: Status::Stopped,
            store,
            data_dir,
            active_tab: Tab::Status,
            proxy_cursor: 0,
            show_help: false,
            log_lines: Vec::new(),
            notice: None,
            notice_at: None,
            input_mode: InputMode::Normal,
            pinging: false,
            ping_tx,
            ping_rx,
            dashboard: DashboardState::default(),
            monitor: None,
            dash_tx,
            dash_rx,
        }
    }

    // ── Action handler ────────────────────────────────────────────────────

    pub async fn handle(&mut self, action: Action) {
        match action {
            Action::Tick   => self.on_tick().await,
            Action::Redraw => {}  // terminal.draw is unconditional

            Action::ToggleProxy => self.toggle_proxy().await,
            Action::Restart     => self.restart_proxy().await,

            Action::SelectNext => self.move_cursor(1),
            Action::SelectPrev => self.move_cursor(-1),
            Action::Confirm    => self.confirm().await,

            Action::NextTab => self.active_tab = self.active_tab.next(),
            Action::PrevTab => self.active_tab = self.active_tab.prev(),

            Action::ToggleHelp => self.show_help = !self.show_help,
            Action::Refresh => self.refresh_dashboard(),

            Action::AddConfig => {
                if self.active_tab == Tab::Proxies {
                    self.input_mode = InputMode::Adding(String::new());
                }
            }
            Action::RenameConfig => {
                if self.active_tab == Tab::Proxies {
                    if let Some(p) = self.store.proxies.get(self.proxy_cursor) {
                        self.input_mode = InputMode::Renaming(p.name.clone());
                    }
                }
            }
            Action::DeleteConfig => {
                if self.active_tab == Tab::Proxies && !self.store.proxies.is_empty() {
                    self.input_mode = InputMode::ConfirmDelete;
                }
            }
            Action::PingAll => self.start_ping_all(),
            Action::InputChar(c) => self.input_char(c),
            Action::InputBackspace => {
                if let InputMode::Adding(buf) | InputMode::Renaming(buf) = &mut self.input_mode {
                    buf.pop();
                }
            }
            Action::InputSubmit => self.input_submit(),
            Action::InputCancel => self.input_mode = InputMode::Normal,
            Action::Paste(text) => {
                if let InputMode::Adding(buf) | InputMode::Renaming(buf) = &mut self.input_mode {
                    buf.push_str(text.trim());
                }
            }

            // Quit is handled in the event loop before reaching here.
            Action::Quit => {}
        }
    }

    // ── Tick ──────────────────────────────────────────────────────────────

    async fn on_tick(&mut self) {
        self.supervisor.poll().await;
        self.proc_status = self.supervisor.status().await;
        if self.monitor.is_some() && !matches!(self.proc_status, Status::Running(_)) {
            self.stop_monitor();
        }
        while let Ok(update) = self.dash_rx.try_recv() {
            self.dashboard.apply(update);
        }
        while let Ok(results) = self.ping_rx.try_recv() {
            self.apply_ping_results(results);
        }
        if let Some(at) = self.notice_at {
            if at.elapsed() >= NOTICE_TTL {
                self.notice = None;
                self.notice_at = None;
            }
        }
    }

    fn set_notice(&mut self, msg: impl Into<String>) {
        self.notice = Some(msg.into());
        self.notice_at = Some(Instant::now());
    }

    fn persist(&mut self) -> bool {
        if let Err(e) = self.store.save(&self.data_dir) {
            self.set_notice(format!("Save failed: {e}"));
            return false;
        }
        true
    }

    // ── Configs tab ───────────────────────────────────────────────────────

    fn input_char(&mut self, c: char) {
        match &mut self.input_mode {
            InputMode::Adding(buf) | InputMode::Renaming(buf) => buf.push(c),
            InputMode::ConfirmDelete => match c {
                'y' | 'Y' => self.delete_selected(),
                _ => {
                    self.input_mode = InputMode::Normal;
                    self.set_notice("Delete cancelled.");
                }
            },
            InputMode::Normal => {}
        }
    }

    fn input_submit(&mut self) {
        let mode = std::mem::replace(&mut self.input_mode, InputMode::Normal);
        match mode {
            InputMode::Adding(text) => self.add_config(&text),
            InputMode::Renaming(text) => self.rename_selected(&text),
            InputMode::ConfirmDelete => self.input_mode = InputMode::ConfirmDelete,
            InputMode::Normal => {}
        }
    }

    fn add_config(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            self.set_notice("Nothing to add.");
            return;
        }
        match proxy_from_link(text) {
            Ok(proxy) => {
                let name = proxy.name.clone();
                self.store.proxies.push(proxy);
                self.proxy_cursor = self.store.proxies.len() - 1;
                if self.persist() {
                    self.set_notice(format!("Added {name}"));
                }
            }
            Err(e) => self.set_notice(format!("Parse error: {e:#}")),
        }
    }

    fn rename_selected(&mut self, text: &str) {
        let new_name = text.trim().to_string();
        if new_name.is_empty() {
            self.set_notice("Name cannot be empty.");
            return;
        }
        if let Some(p) = self.store.proxies.get_mut(self.proxy_cursor) {
            p.name = new_name.clone();
            if self.persist() {
                self.set_notice(format!("Renamed to {new_name}"));
            }
        }
    }

    fn delete_selected(&mut self) {
        self.input_mode = InputMode::Normal;
        if self.proxy_cursor >= self.store.proxies.len() {
            return;
        }
        let removed = self.store.proxies.remove(self.proxy_cursor);
        if self.store.settings.active_config_id.as_deref() == Some(removed.id.as_str())
            || self.store.settings.active_config_id.as_deref() == Some(removed.name.as_str())
        {
            self.store.settings.active_config_id = None;
        }
        if self.proxy_cursor > 0 && self.proxy_cursor >= self.store.proxies.len() {
            self.proxy_cursor -= 1;
        }
        if self.persist() {
            self.set_notice(format!("Deleted {}", removed.name));
        }
    }

    fn start_ping_all(&mut self) {
        if self.active_tab != Tab::Proxies {
            return;
        }
        if self.pinging {
            self.set_notice("Ping already running…");
            return;
        }
        let targets: Vec<net::PingTarget> = self
            .store
            .proxies
            .iter()
            .map(|p| net::PingTarget { id: p.id.clone(), host: p.address.clone(), port: p.port })
            .collect();
        if targets.is_empty() {
            self.set_notice("No configs to ping.");
            return;
        }
        self.pinging = true;
        self.set_notice(format!("Pinging {} configs…", targets.len()));
        let tx = self.ping_tx.clone();
        tokio::spawn(async move {
            let results = net::ping_all(targets, net::PING_TIMEOUT).await;
            let _ = tx.send(results);
        });
    }

    fn apply_ping_results(&mut self, results: Vec<(String, Option<u64>)>) {
        self.pinging = false;
        let mut ok = 0;
        for (id, ms) in &results {
            if let Some(p) = self.store.proxies.iter_mut().find(|p| &p.id == id) {
                p.last_tcp_ms = *ms;
                if ms.is_some() {
                    ok += 1;
                }
            }
        }
        if self.persist() {
            self.set_notice(format!("Ping done: {ok}/{} reachable", results.len()));
        }
    }

    // ── Proxy control ─────────────────────────────────────────────────────

    async fn toggle_proxy(&mut self) {
        match self.proc_status {
            Status::Running(_) => self.stop_proxy().await,
            _                  => self.start_proxy().await,
        }
    }

    async fn start_proxy(&mut self) {
        let Some(proxy) = self.active_proxy() else {
            self.notice = Some("No proxy selected.".into());
            return;
        };

        match gen::write_config(&self.data_dir, proxy, &self.store.settings) {
            Err(e) => {
                self.notice = Some(format!("Config error: {e}"));
                return;
            }
            Ok(path) => tracing::info!("wrote config to {}", path.display()),
        }

        if let Err(e) = self.supervisor.start().await {
            self.notice = Some(format!("Start failed: {e}"));
        } else {
            self.proc_status = self.supervisor.status().await;
            self.start_monitor();
        }
    }

    async fn stop_proxy(&mut self) {
        self.stop_monitor();
        if let Err(e) = self.supervisor.stop().await {
            self.notice = Some(format!("Stop failed: {e}"));
        } else {
            self.proc_status = Status::Stopped;
        }
    }

    async fn restart_proxy(&mut self) {
        self.stop_monitor();
        if let Err(e) = self.supervisor.restart().await {
            self.notice = Some(format!("Restart failed: {e}"));
        } else {
            self.proc_status = self.supervisor.status().await;
            self.start_monitor();
        }
    }

    /// Disconnect before quitting so the monitor tasks and sing-box stop.
    pub async fn shutdown(&mut self) {
        self.stop_proxy().await;
    }

    // ── Dashboard monitor ─────────────────────────────────────────────────

    fn start_monitor(&mut self) {
        self.stop_monitor();
        if !matches!(self.proc_status, Status::Running(_)) {
            return;
        }
        let generation = self.dashboard.begin_session();
        let path = self.data_dir.join(gen::CONFIG_FILENAME);
        match MonitorTargets::from_config_file(&path) {
            Ok(targets) => {
                self.monitor = Some(Monitor::start(targets, generation, self.dash_tx.clone()));
                self.dashboard.exit_ip = Probe::Pending;
                self.dashboard.latency_ms = Probe::Pending;
            }
            Err(e) => self.set_notice(format!("Dashboard unavailable: {e:#}")),
        }
    }

    fn stop_monitor(&mut self) {
        self.monitor = None;
        self.dashboard.end_session();
    }

    fn refresh_dashboard(&mut self) {
        match self.monitor.as_mut() {
            Some(monitor) => {
                self.dashboard.exit_ip = Probe::Pending;
                self.dashboard.latency_ms = Probe::Pending;
                monitor.refresh();
                self.set_notice("Refreshing exit IP and latency…");
            }
            None => self.set_notice("Not connected."),
        }
    }

    // ── Cursor / confirm ──────────────────────────────────────────────────

    fn move_cursor(&mut self, delta: i32) {
        let len = self.store.proxies.len();
        if len == 0 { return; }
        let c = self.proxy_cursor as i32 + delta;
        self.proxy_cursor = c.rem_euclid(len as i32) as usize;
    }

    async fn confirm(&mut self) {
        // On the Configs tab, Enter activates the selected config.
        if self.active_tab == Tab::Proxies {
            if let Some(proxy) = self.store.proxies.get(self.proxy_cursor) {
                let name = proxy.name.clone();
                self.store.settings.active_config_id = Some(proxy.id.clone());
                if self.persist() {
                    self.set_notice(format!("Active config → {name}"));
                }
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Return the currently active proxy, if one is configured.
    pub fn active_proxy(&self) -> Option<&ProxyConfig> {
        let key = self.store.settings.active_config_id.as_deref()?;
        self.store
            .proxies
            .iter()
            .find(|p| p.id == key)
            .or_else(|| self.store.proxies.iter().find(|p| p.name == key))
    }

    /// Human-readable status string for the status bar.
    pub fn status_line(&self) -> String {
        match &self.proc_status {
            Status::Stopped       => "Stopped".into(),
            Status::Running(pid)  => format!("Running  (pid {pid})"),
            Status::Failed(msg)   => format!("Failed: {msg}"),
        }
    }
}

/// Build a stored config from a share link or raw sing-box outbound JSON.
pub fn proxy_from_link(text: &str) -> anyhow::Result<ProxyConfig> {
    let (name, mut outbound) = parse::parse_link(text)?;
    if !outbound.is_object() {
        anyhow::bail!("outbound must be a JSON object");
    }
    let protocol = outbound
        .get("type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("outbound has no \"type\""))?
        .to_string();
    let address = outbound
        .get("server")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let port = outbound
        .get("server_port")
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(0);
    let id = uuid::Uuid::new_v4().to_string();
    outbound["tag"] = serde_json::json!(name.clone());
    Ok(ProxyConfig {
        id,
        name,
        protocol,
        address,
        port,
        outbound,
        ..ProxyConfig::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_from_hy2_link() {
        let p = proxy_from_link("hy2://pw@example.com:8443#node").unwrap();
        assert_eq!(p.name, "node");
        assert_eq!(p.protocol, "hysteria2");
        assert_eq!(p.address, "example.com");
        assert_eq!(p.port, 8443);
        assert!(!p.id.is_empty());
        assert_eq!(p.last_tcp_ms, None);
    }

    #[test]
    fn proxy_from_bad_link_is_error() {
        assert!(proxy_from_link("garbage").is_err());
        assert!(proxy_from_link("{\"server\":\"x\"}").is_err());
    }
}

// ── draw ──────────────────────────────────────────────────────────────────────

use ratatui::Frame;
use anyhow::Result;

/// Top-level draw function called every frame.
pub fn draw(frame: &mut Frame, state: &AppState) -> Result<()> {
    use ratatui::layout::{Constraint, Direction, Layout};
    use crate::ui::widgets;

    let area = frame.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar
            Constraint::Min(0),    // body
            Constraint::Length(1), // status bar
        ])
        .split(area);

    // Tab bar
    widgets::tab_bar(frame, chunks[0], state);

    // Body
    match state.active_tab {
        Tab::Status   => widgets::status_panel(frame, chunks[1], state),
        Tab::Proxies  => widgets::proxy_list(frame, chunks[1], state),
        Tab::Settings => widgets::settings_panel(frame, chunks[1], state),
        Tab::Logs     => widgets::log_panel(frame, chunks[1], state),
    }

    // Status bar / help overlay
    if state.show_help {
        widgets::help_overlay(frame, area);
    } else {
        widgets::status_bar(frame, chunks[2], state);
    }

    Ok(())
}
