//! Reusable ratatui widget helpers for vpnt.
//!
//! Each function renders one logical region of the TUI.  They are pure:
//! they take a `Frame`, an `Area`, and read-only `AppState`, then render.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, List, ListItem, ListState,
        Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, TableState,
        Sparkline, Table, Tabs, Wrap,
    },
};

use crate::core::Status;
use crate::ui::app::{AppState, InputMode, Tab};
use crate::ui::dashboard::{format_bytes, format_uptime, Probe};

// ── Palette ───────────────────────────────────────────────────────────────────
// A single accent hue (teal-ish) plus a neutral ramp.  All colours are named
// by role so they can be swapped in one place.

mod palette {
    use ratatui::style::Color;

    pub const SURFACE:       Color = Color::Rgb(18,  22,  28);   // ~2% L
    pub const RAISED:        Color = Color::Rgb(26,  31,  40);   // ~5% L
    pub const BORDER:        Color = Color::Rgb(48,  56,  68);
    pub const MUTED:         Color = Color::Rgb(100, 112, 130);
    pub const BODY:          Color = Color::Rgb(210, 218, 228);  // ~86% L
    pub const ACCENT:        Color = Color::Rgb(56,  189, 166);  // teal
    pub const ACCENT_DIM:    Color = Color::Rgb(38,  130, 115);
    pub const SUCCESS:       Color = Color::Rgb(72,  199, 116);
    pub const WARNING:       Color = Color::Rgb(230, 180,  60);
    pub const DANGER:        Color = Color::Rgb(220,  80,  80);
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn accent_block(title: &str) -> Block<'_> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(palette::ACCENT)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(palette::BORDER))
        .style(Style::default().bg(palette::SURFACE))
        .padding(Padding::horizontal(1))
}

fn status_color(s: &Status) -> Color {
    match s {
        Status::Running(_) => palette::SUCCESS,
        Status::Stopped    => palette::MUTED,
        Status::Failed(_)  => palette::DANGER,
    }
}

// ── Tab bar ───────────────────────────────────────────────────────────────────

pub fn tab_bar(frame: &mut Frame, area: Rect, state: &AppState) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| {
            Line::from(Span::styled(
                format!(" {} ", t.title()),
                Style::default().fg(palette::BODY),
            ))
        })
        .collect();

    let selected = Tab::ALL
        .iter()
        .position(|t| *t == state.active_tab)
        .unwrap_or(0);

    let tabs = Tabs::new(titles)
        .select(selected)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(palette::BORDER))
                .style(Style::default().bg(palette::RAISED)),
        )
        .highlight_style(
            Style::default()
                .fg(palette::ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::styled("│", Style::default().fg(palette::BORDER)));

    frame.render_widget(tabs, area);
}

// ── Status panel ──────────────────────────────────────────────────────────────

pub fn status_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = accent_block("Dashboard");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let dash = &state.dashboard;
    let connected = matches!(state.proc_status, Status::Running(_)) && dash.connected_at.is_some();

    let [info_area, body_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .areas(inner);

    let label = |s: &'static str| Span::styled(format!("{s:<10}"), Style::default().fg(palette::MUTED));
    let value = |s: String| Span::styled(s, Style::default().fg(palette::BODY));

    let sc = status_color(&state.proc_status);
    let status_text = if connected { "Connected".to_string() } else { match &state.proc_status {
        Status::Failed(msg) => format!("Disconnected ({msg})"),
        _ => "Disconnected".to_string(),
    }};
    let config_name = state
        .active_proxy()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "(none, select one on Configs)".into());
    let uptime = dash
        .uptime()
        .filter(|_| connected)
        .map(format_uptime)
        .unwrap_or_else(|| "-".into());

    let info = vec![
        Line::from(vec![
            label("Status"),
            Span::styled(status_text, Style::default().fg(sc).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![label("Config"), value(config_name)]),
        Line::from(vec![label("Uptime"), value(uptime)]),
    ];
    frame.render_widget(Paragraph::new(info), info_area);

    if !connected {
        frame.render_widget(
            Paragraph::new("Disconnected.  Press s to connect.")
                .style(Style::default().fg(palette::MUTED))
                .alignment(Alignment::Center),
            body_area,
        );
        return;
    }

    let [spark_area, stats_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .areas(body_area);
    let [down_area, up_area] = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .areas(spark_area);

    let down: Vec<u64> = dash.down_history.iter().copied().collect();
    let up: Vec<u64> = dash.up_history.iter().copied().collect();
    render_spark(
        frame,
        down_area,
        &format!("↓ {}/s", format_bytes(dash.current.down)),
        &down,
        palette::ACCENT,
    );
    render_spark(
        frame,
        up_area,
        &format!("↑ {}/s", format_bytes(dash.current.up)),
        &up,
        palette::WARNING,
    );

    let [stats_left, stats_right] = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .areas(stats_area);

    let latency = match &dash.latency_ms {
        Probe::Ok(ms) => format!("{ms} ms"),
        Probe::Pending => "measuring…".into(),
        Probe::Failed(e) => format!("failed: {e}"),
        Probe::Idle => "-".into(),
    };
    let exit_ip = match &dash.exit_ip {
        Probe::Ok(ip) => ip.clone(),
        Probe::Pending => "fetching…".into(),
        Probe::Failed(e) => format!("failed: {e}"),
        Probe::Idle => "-".into(),
    };
    let conns = &dash.connections;
    let stats = vec![
        Line::from(vec![
            label("Session"),
            value(format!(
                "↓ {}  ↑ {}",
                format_bytes(conns.download_total),
                format_bytes(conns.upload_total)
            )),
        ]),
        Line::from(vec![label("Exit IP"), value(exit_ip)]),
        Line::from(vec![label("Latency"), value(latency)]),
        Line::from(vec![label("Conns"), value(conns.count.to_string())]),
        Line::from(""),
        Line::from(Span::styled("r refresh exit IP / latency", Style::default().fg(palette::MUTED))),
    ];
    frame.render_widget(
        Paragraph::new(stats)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(palette::BORDER))),
        stats_left,
    );

    let rows: Vec<Row> = conns
        .per_process
        .iter()
        .take(5)
        .map(|(name, count)| {
            Row::new(vec![
                Cell::from(name.clone()).style(Style::default().fg(palette::BODY)),
                Cell::from(count.to_string()).style(Style::default().fg(palette::ACCENT)),
            ])
        })
        .collect();
    let table = Table::new(rows, [Constraint::Min(10), Constraint::Length(6)])
        .header(
            Row::new(vec!["Top apps", "Conns"])
                .style(Style::default().fg(palette::MUTED).add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(palette::BORDER)))
        .column_spacing(1);
    frame.render_widget(table, stats_right);
}

fn render_spark(frame: &mut Frame, area: Rect, title: &str, data: &[u64], color: Color) {
    let max = data.iter().copied().max().unwrap_or(0).max(1);
    let spark = Sparkline::default()
        .block(
            Block::default()
                .title(Span::styled(format!(" {title} "), Style::default().fg(color)))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(palette::BORDER)),
        )
        .data(data)
        .max(max)
        .style(Style::default().fg(color));
    frame.render_widget(spark, area);
}

// ── Proxy list ────────────────────────────────────────────────────────────────

pub fn proxy_list(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = accent_block("Configs");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let prompt_height = if state.input_mode == InputMode::Normal { 1 } else { 3 };
    let [list_area, prompt_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(prompt_height)])
        .areas(inner);
    config_prompt(frame, prompt_area, state);

    if state.store.proxies.is_empty() {
        frame.render_widget(
            Paragraph::new("No configs yet.  Press a to add a share link or outbound JSON.")
                .style(Style::default().fg(palette::MUTED))
                .alignment(Alignment::Center),
            list_area,
        );
        return;
    }

    let active_id = state.active_proxy().map(|p| p.id.clone()).unwrap_or_default();

    let header = Row::new(vec!["", "Name", "Protocol", "Host:Port", "TCP"])
        .style(Style::default().fg(palette::MUTED).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = state
        .store
        .proxies
        .iter()
        .map(|p| {
            let is_active = !active_id.is_empty() && p.id == active_id;
            let bullet = if is_active { "●" } else { "○" };
            let bullet_color = if is_active { palette::ACCENT } else { palette::BORDER };
            let ping = p
                .last_tcp_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "-".into());
            Row::new(vec![
                Cell::from(bullet).style(Style::default().fg(bullet_color)),
                Cell::from(p.name.clone()).style(Style::default().fg(palette::BODY)),
                Cell::from(proxy_protocol_label(p)).style(Style::default().fg(palette::MUTED)),
                Cell::from(format!("{}:{}", p.address, p.port))
                    .style(Style::default().fg(palette::MUTED)),
                Cell::from(ping).style(Style::default().fg(palette::BODY)),
            ])
        })
        .collect();

    let mut table_state = TableState::default();
    table_state.select(Some(state.proxy_cursor));

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Percentage(35),
            Constraint::Length(12),
            Constraint::Percentage(35),
            Constraint::Length(9),
        ],
    )
    .header(header)
    .highlight_style(
        Style::default()
            .fg(palette::ACCENT)
            .bg(palette::RAISED)
            .add_modifier(Modifier::BOLD),
    )
    .style(Style::default().bg(palette::SURFACE))
    .column_spacing(1);

    frame.render_stateful_widget(table, list_area, &mut table_state);
}

fn config_prompt(frame: &mut Frame, area: Rect, state: &AppState) {
    let (title, body) = match &state.input_mode {
        InputMode::Normal => {
            let hint = if state.pinging { "pinging…  " } else { "" };
            frame.render_widget(
                Paragraph::new(format!(
                    "{hint}a add  e rename  d delete  t ping all  Enter set active"
                ))
                .style(Style::default().fg(palette::MUTED)),
                area,
            );
            return;
        }
        InputMode::Adding(buf) => (
            " Add: paste link or outbound JSON (Enter save, Esc cancel) ",
            format!("{buf}▏"),
        ),
        InputMode::Renaming(buf) => (" Rename (Enter save, Esc cancel) ", format!("{buf}▏")),
        InputMode::ConfirmDelete => {
            let name = state
                .store
                .proxies
                .get(state.proxy_cursor)
                .map(|p| p.name.clone())
                .unwrap_or_default();
            (" Confirm delete ", format!("Delete \"{name}\"? y = yes, any other key = no"))
        }
    };

    let width = area.width.saturating_sub(2) as usize;
    let chars: Vec<char> = body.chars().collect();
    let shown: String = if chars.len() > width && width > 0 {
        chars[chars.len() - width..].iter().collect()
    } else {
        body
    };

    frame.render_widget(
        Paragraph::new(shown)
            .style(Style::default().fg(palette::BODY))
            .block(
                Block::default()
                    .title(Span::styled(title, Style::default().fg(palette::WARNING)))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(palette::ACCENT_DIM)),
            ),
        area,
    );
}

fn proxy_protocol_label(p: &crate::config::ProxyConfig) -> &'static str {
    use crate::config::ProxyConfig;
    // Discriminate on the tag stored in the config.
    match p.protocol.as_str() {
        "vless"  => "VLESS",
        "vmess"  => "VMess",
        "trojan" => "Trojan",
        "ss"     => "Shadowsocks",
        "shadowsocks" => "Shadowsocks",
        "hysteria2" => "Hysteria2",
        "tuic"   => "TUIC",
        _        => "Unknown",
    }
}

// ── Settings panel ────────────────────────────────────────────────────────────

pub fn settings_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = accent_block("Settings");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let s = &state.store.settings;

    let rows = vec![
        Row::new(vec![
            Cell::from("SOCKS5 port").style(Style::default().fg(palette::MUTED)),
            Cell::from(
                s.socks_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "off".into()),
            )
            .style(Style::default().fg(palette::BODY)),
        ]),
        Row::new(vec![
            Cell::from("HTTP port").style(Style::default().fg(palette::MUTED)),
            Cell::from(
                s.http_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "off".into()),
            )
            .style(Style::default().fg(palette::BODY)),
        ]),
        Row::new(vec![
            Cell::from("Log level").style(Style::default().fg(palette::MUTED)),
            Cell::from(s.log_level.clone()).style(Style::default().fg(palette::BODY)),
        ]),
        Row::new(vec![
            Cell::from("Auto-connect").style(Style::default().fg(palette::MUTED)),
            Cell::from(if s.auto_connect { "yes" } else { "no" })
                .style(Style::default().fg(palette::BODY)),
        ]),
        Row::new(vec![
            Cell::from("Routing mode").style(Style::default().fg(palette::MUTED)),
            Cell::from(format!("{:?}", s.default_mode))
                .style(Style::default().fg(palette::BODY)),
        ]),
    ];

    let table = Table::new(
        rows,
        [Constraint::Percentage(40), Constraint::Percentage(60)],
    )
    .style(Style::default().bg(palette::SURFACE))
    .column_spacing(2);

    frame.render_widget(table, inner);
}

// ── Log panel ─────────────────────────────────────────────────────────────────

pub fn log_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = accent_block("Logs");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let height = inner.height as usize;
    let lines: Vec<Line> = state
        .log_lines
        .iter()
        .rev()
        .take(height)
        .rev()
        .map(|l| {
            // Colour lines that start with known level prefixes.
            let style = if l.contains("ERROR") || l.contains("error") {
                Style::default().fg(palette::DANGER)
            } else if l.contains("WARN") || l.contains("warn") {
                Style::default().fg(palette::WARNING)
            } else {
                Style::default().fg(palette::BODY)
            };
            Line::from(Span::styled(l.clone(), style))
        })
        .collect();

    let total = state.log_lines.len();
    let offset = total.saturating_sub(height);

    let para = Paragraph::new(Text::from(lines))
        .style(Style::default().bg(palette::SURFACE))
        .wrap(Wrap { trim: false });

    // Scrollbar only when content overflows.
    if total > height {
        let scroll_area = inner;
        let [text_area, bar_area] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .areas(scroll_area);

        frame.render_widget(para, text_area);

        let mut sb_state = ScrollbarState::new(total).position(offset);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(palette::BORDER)),
            bar_area,
            &mut sb_state,
        );
    } else {
        frame.render_widget(para, inner);
    }
}

// ── Status bar ────────────────────────────────────────────────────────────────

pub fn status_bar(frame: &mut Frame, area: Rect, state: &AppState) {
    let text = if let Some(notice) = &state.notice {
        Line::from(Span::styled(notice.as_str(), Style::default().fg(palette::WARNING)))
    } else {
        let running = matches!(state.proc_status, Status::Running(_));
        Line::from(vec![
            Span::styled(" q", Style::default().fg(palette::ACCENT)),
            Span::styled(" quit", Style::default().fg(palette::MUTED)),
            Span::styled("  s", Style::default().fg(palette::ACCENT)),
            Span::styled(
                if running { " stop" } else { " start" },
                Style::default().fg(palette::MUTED),
            ),
            Span::styled("  r", Style::default().fg(palette::ACCENT)),
            Span::styled(" restart", Style::default().fg(palette::MUTED)),
            Span::styled("  ?", Style::default().fg(palette::ACCENT)),
            Span::styled(" help", Style::default().fg(palette::MUTED)),
        ])
    };

    frame.render_widget(
        Paragraph::new(text)
            .style(Style::default().bg(palette::RAISED))
            .alignment(Alignment::Left),
        area,
    );
}

// ── Help overlay ──────────────────────────────────────────────────────────────

pub fn help_overlay(frame: &mut Frame, area: Rect) {
    // Centre a fixed-size popup.
    let popup = centered_rect(50, 14, area);

    // Clear the background first so the popup sits on top.
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            " Help ",
            Style::default()
                .fg(palette::ACCENT)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(palette::ACCENT_DIM))
        .style(Style::default().bg(palette::RAISED));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let bindings: &[(&str, &str)] = &[
        ("q / Ctrl-q / Ctrl-c", "Quit"),
        ("Tab / Shift-Tab",      "Switch tabs"),
        ("j / ↓  k / ↑",        "Move cursor"),
        ("Enter",                "Set selected config active"),
        ("a / e / d / t",        "Configs: add/rename/delete/ping"),
        ("s",                    "Start / stop proxy"),
        ("r",                    "Dashboard: refresh IP/latency"),
        ("R / r (other tabs)",   "Restart proxy"),
        ("?  / F1",              "Toggle this help"),
    ];

    let rows: Vec<Row> = bindings
        .iter()
        .map(|(key, desc)| {
            Row::new(vec![
                Cell::from(*key).style(
                    Style::default()
                        .fg(palette::ACCENT)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(*desc).style(Style::default().fg(palette::BODY)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Percentage(50), Constraint::Percentage(50)],
    )
    .style(Style::default().bg(palette::RAISED))
    .column_spacing(2);

    frame.render_widget(table, inner.inner(Margin { horizontal: 1, vertical: 0 }));
}

// ── Layout helpers ────────────────────────────────────────────────────────────

/// Return a `Rect` centred in `r` with the given percentage width and fixed
/// row height.
fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let w = r.width * percent_x / 100;
    let x = r.x + (r.width.saturating_sub(w)) / 2;
    let y = r.y + (r.height.saturating_sub(height)) / 2;
    Rect::new(x, y, w.min(r.width), height.min(r.height))
}
