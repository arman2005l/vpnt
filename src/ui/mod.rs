//! TUI entry point – wires together the terminal, the event loop, and the
//! application state.  The module tree is kept flat for M1:
//!
//!   ui/
//!   ├── mod.rs      – this file: App struct, run loop, input dispatch
//!   ├── app.rs      – application state + actions
//!   └── widgets.rs  – reusable ratatui widget helpers

pub mod app;
pub use app::App;
pub mod widgets;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste,
        EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use tracing::error;

use crate::core::Supervisor;

use self::app::{Action, AppState, InputMode, Tab};

/// Tick rate: how often we redraw even without an input event.
const TICK_MS: u64 = 250;

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the terminal, run the event loop, then restore the terminal.
///
/// This function owns the terminal for its entire duration; the caller must
/// not write to stdout/stderr while it is running.
pub async fn run(supervisor: Supervisor, data_dir: std::path::PathBuf) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let result = event_loop(&mut terminal, supervisor, data_dir).await;
    restore_terminal(&mut terminal)?;
    result
}

// ── Terminal lifecycle ────────────────────────────────────────────────────────

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        DisableBracketedPaste,
    )?;
    terminal.show_cursor()?;
    Ok(())
}

// ── Event loop ────────────────────────────────────────────────────────────────

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    supervisor: Supervisor,
    data_dir: std::path::PathBuf,
) -> Result<()> {
    let mut state = AppState::new(supervisor, data_dir);
    let tick = Duration::from_millis(TICK_MS);

    loop {
        // ── Draw ──────────────────────────────────────────────────────────
        terminal.draw(|frame| {
            if let Err(e) = app::draw(frame, &state) {
                error!("draw error: {e}");
            }
        })?;

        // ── Poll for input or tick ────────────────────────────────────────
        let action = if event::poll(tick)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => map_key(key, &state),
                Event::Paste(text) => Some(Action::Paste(text)),
                Event::Resize(_, _) => Some(Action::Redraw),
                _ => None,
            }
        } else {
            // Tick: let the state machine check the child process, etc.
            Some(Action::Tick)
        };

        // ── Update ────────────────────────────────────────────────────────
        if let Some(act) = action {
            if act == Action::Quit {
                // Attempt clean shutdown; ignore errors here.
                let _ = state.supervisor.stop().await;
                break;
            }
            state.handle(act).await;
        }
    }

    Ok(())
}

// ── Key → Action mapping ──────────────────────────────────────────────────────

fn map_key(key: event::KeyEvent, state: &AppState) -> Option<Action> {
    // Ctrl-C / Ctrl-Q / q always quit.
    if matches!(key.modifiers, KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q'))
    {
        return Some(Action::Quit);
    }

    match state.input_mode {
        InputMode::Adding(_) | InputMode::Renaming(_) => {
            return match key.code {
                KeyCode::Enter => Some(Action::InputSubmit),
                KeyCode::Esc => Some(Action::InputCancel),
                KeyCode::Backspace => Some(Action::InputBackspace),
                KeyCode::Char(c) => Some(Action::InputChar(c)),
                _ => None,
            };
        }
        InputMode::ConfirmDelete => {
            return match key.code {
                KeyCode::Esc => Some(Action::InputCancel),
                KeyCode::Char(c) => Some(Action::InputChar(c)),
                _ => Some(Action::InputChar('n')),
            };
        }
        InputMode::Normal => {}
    }

    if state.active_tab == Tab::Proxies {
        match key.code {
            KeyCode::Char('a') => return Some(Action::AddConfig),
            KeyCode::Char('e') => return Some(Action::RenameConfig),
            KeyCode::Char('d') => return Some(Action::DeleteConfig),
            KeyCode::Char('t') => return Some(Action::PingAll),
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => Some(Action::Quit),
        KeyCode::Char('s') | KeyCode::Char('S') => Some(Action::ToggleProxy),
        KeyCode::Char('r') | KeyCode::Char('R') => Some(Action::Restart),
        KeyCode::Up | KeyCode::Char('k')        => Some(Action::SelectPrev),
        KeyCode::Down | KeyCode::Char('j')      => Some(Action::SelectNext),
        KeyCode::Enter                           => Some(Action::Confirm),
        KeyCode::Tab                             => Some(Action::NextTab),
        KeyCode::BackTab                         => Some(Action::PrevTab),
        KeyCode::Char('?') | KeyCode::F(1)      => Some(Action::ToggleHelp),
        _                                        => None,
    }
}
