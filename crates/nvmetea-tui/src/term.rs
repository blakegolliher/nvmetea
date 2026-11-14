//! Terminal loop: raw mode + alternate screen, input polled every 80 ms,
//! the newest view drawn. A panic hook restores the terminal first.

use crate::app::{App, Control};
use crate::model::View;
use crate::ui::draw;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::stdout;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::Duration;

fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
}

/// Run until the user quits, `stop()` returns true (a termination signal), or
/// the sampler goes away.
pub fn run(
    views: Receiver<View>,
    control: Sender<Control>,
    interval_s: f64,
    stop: fn() -> bool,
) -> std::io::Result<()> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        prev(info);
    }));
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut app = App::new(interval_s);
    let res = (|| -> std::io::Result<()> {
        loop {
            loop {
                match views.try_recv() {
                    Ok(v) => app.update(v),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return Ok(()),
                }
            }
            term.draw(|f| draw(f, &app))?;
            if event::poll(Duration::from_millis(80))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        if let Some(c) = app.key(k) {
                            let _ = control.send(c);
                        }
                    }
                }
            }
            if app.quit {
                return Ok(());
            }
            if stop() {
                let _ = control.send(Control::Quit);
                return Ok(());
            }
        }
    })();
    restore();
    res
}
