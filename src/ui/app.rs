//! Application state and the actions that mutate it.
//!
//! `AppState` is the single source of truth for the TUI.  It is not
//! async-aware itself; callers in the event loop drive it with `.handle()`.

use std::path::PathBuf;

use crate::config::{ProxyConfig, Store};
use crate::core::{Status, Supervisor};
use crate::gen;

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
            Tab::Status   => "Status",
            Tab::Proxies  => "Proxies",
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
}

impl AppState {
    pub fn new(supervisor: Supervisor, data_dir: PathBuf) -> Self {
        let store = Store::load(&data_dir).unwrap_or_else(|e| {
            tracing::warn!("could not load store: {e}; using defaults");
            Store::default()
        });

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

            // Quit is handled in the event loop before reaching here.
            Action::Quit => {}
        }
    }

    // ── Tick ──────────────────────────────────────────────────────────────

    async fn on_tick(&mut self) {
        self.proc_status = self.supervisor.status().await;
        self.supervisor.poll().await;
        self.notice = None; // clear transient messages
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
        }
    }

    async fn stop_proxy(&mut self) {
        if let Err(e) = self.supervisor.stop().await {
            self.notice = Some(format!("Stop failed: {e}"));
        } else {
            self.proc_status = Status::Stopped;
        }
    }

    async fn restart_proxy(&mut self) {
        if let Err(e) = self.supervisor.restart().await {
            self.notice = Some(format!("Restart failed: {e}"));
        } else {
            self.proc_status = self.supervisor.status().await;
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
        // On the Proxies tab, Enter activates the selected proxy.
        if self.active_tab == Tab::Proxies {
            if let Some(proxy) = self.store.proxies.get(self.proxy_cursor) {
                let name = proxy.name.clone();
                self.store.settings.active_proxy = Some(name.clone());
                if let Err(e) = self.store.save(&self.data_dir) {
                    self.notice = Some(format!("Save failed: {e}"));
                } else {
                    self.notice = Some(format!("Active proxy → {name}"));
                }
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Return the currently active proxy, if one is configured.
    pub fn active_proxy(&self) -> Option<&ProxyConfig> {
        let name = self.store.settings.active_proxy.as_deref()?;
        self.store.proxies.iter().find(|p| p.name == name)
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
