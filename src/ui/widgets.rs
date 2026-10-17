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
        Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, Tabs, Wrap,
    },
};

use crate::core::Status;
use crate::ui::app::{AppState, Tab};

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
    let block = accent_block("Status");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    // Process status
    let sc = status_color(&state.proc_status);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Process  ", Style::default().fg(palette::MUTED)),
            Span::styled(state.status_line(), Style::default().fg(sc).add_modifier(Modifier::BOLD)),
        ])),
        rows[0],
    );

    // Active proxy
    let proxy_name = state
        .active_proxy()
        .map(|p| p.name.as_str())
        .unwrap_or("—");
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Proxy    ", Style::default().fg(palette::MUTED)),
            Span::styled(proxy_name, Style::default().fg(palette::BODY)),
        ])),
        rows[1],
    );

    // SOCKS / HTTP ports from settings
    let socks = state
        .store
        .settings
        .socks_port
        .map(|p| p.to_string())
        .unwrap_or_else(|| "off".into());
    let http = state
        .store
        .settings
        .http_port
        .map(|p| p.to_string())
        .unwrap_or_else(|| "off".into());
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("SOCKS5   ", Style::default().fg(palette::MUTED)),
            Span::styled(format!("127.0.0.1:{socks}"), Style::default().fg(palette::BODY)),
        ])),
        rows[2],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("HTTP     ", Style::default().fg(palette::MUTED)),
            Span::styled(format!("127.0.0.1:{http}"), Style::default().fg(palette::BODY)),
        ])),
        rows[3],
    );
}

// ── Proxy list ────────────────────────────────────────────────────────────────

pub fn proxy_list(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = accent_block("Proxies");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if state.store.proxies.is_empty() {
        frame.render_widget(
            Paragraph::new("No proxies loaded.  Paste a link on the Settings tab.")
                .style(Style::default().fg(palette::MUTED))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let active_name = state
        .store
        .settings
        .active_proxy
        .as_deref()
        .unwrap_or("");

    let items: Vec<ListItem> = state
        .store
        .proxies
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let is_active = p.name == active_name;
            let is_cursor = i == state.proxy_cursor;

            let bullet = if is_active { "● " } else { "○ " };
            let bullet_color = if is_active { palette::ACCENT } else { palette::BORDER };

            let name_style = if is_cursor {
                Style::default()
                    .fg(palette::ACCENT)
                    .add_modifier(Modifier::BOLD)
                    .bg(palette::RAISED)
            } else {
                Style::default().fg(palette::BODY)
            };

            ListItem::new(Line::from(vec![
                Span::styled(bullet, Style::default().fg(bullet_color)),
                Span::styled(p.name.clone(), name_style),
                Span::styled(
                    format!("  {}", proxy_protocol_label(p)),
                    Style::default().fg(palette::MUTED),
                ),
            ]))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(state.proxy_cursor));

    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default().bg(palette::RAISED))
            .style(Style::default().bg(palette::SURFACE)),
        inner,
        &mut list_state,
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
        ("Enter",                "Activate selected proxy"),
        ("s",                    "Start / stop proxy"),
        ("r",                    "Restart proxy"),
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
