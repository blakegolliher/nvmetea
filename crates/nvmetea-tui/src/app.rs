//! TUI state and key handling (keys follow the specification: q, h/l, ←/→,
//! j/k, ↑/↓, Enter, Esc, Space, r, s, f, ?, +/-, plus p for stage profiling).

use crate::model::View;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub const TABS: [&str; 9] =
    ["Overview", "Subsystems", "Controllers", "Queues", "Latency", "Breakdown", "TCP", "Events", "Help"];

/// Messages from the UI to the sampler.
#[derive(Debug, Clone, PartialEq)]
pub enum Control {
    SetInterval(f64),
    /// Start or stop Level 2 stage profiling.
    Profile(bool),
    /// Restart the stage aggregates.
    ResetProfile,
    /// Cycle the controller filter: `None` = all controllers.
    Filter(Option<String>),
    Quit,
}

#[derive(Debug, Default)]
pub struct App {
    pub tab: usize,
    pub selected: [usize; 9],
    /// Sort column per tab (None = as produced).
    pub sort: [Option<usize>; 9],
    pub detail: bool,
    pub paused: bool,
    pub view: Option<View>,
    /// A newer view that arrived while paused.
    pub pending: Option<View>,
    pub interval_s: f64,
    pub profiling: bool,
    pub filter: Option<String>,
    pub quit: bool,
    /// One-shot message for the status line (cleared on the next key).
    pub flash: Option<String>,
}

impl App {
    pub fn new(interval_s: f64) -> App {
        App { interval_s, ..Default::default() }
    }

    pub fn update(&mut self, v: View) {
        if self.paused {
            self.pending = Some(v);
        } else {
            self.view = Some(v);
        }
    }

    fn rows(&self) -> usize {
        let Some(v) = &self.view else { return 0 };
        match self.tab {
            0 => v.overview.rows.len(),
            1 => v.subsystems.rows.len(),
            2 => v.controllers.rows.len(),
            3 => v.queues.rows.len(),
            4 => v.latency.rows.len(),
            5 => v.breakdown.as_ref().map(|b| b.slowest.len()).unwrap_or(0),
            6 => v.tcp.rows.len(),
            7 => v.events.len(),
            _ => 0,
        }
    }

    fn controllers(&self) -> Vec<String> {
        self.view.as_ref().map(|v| v.details.keys().cloned().collect()).unwrap_or_default()
    }

    /// Handle a key; returns a control message for the sampler, if any.
    pub fn key(&mut self, k: KeyEvent) -> Option<Control> {
        self.flash = None;
        let n = self.rows();
        let sel = &mut self.selected[self.tab];
        match k.code {
            KeyCode::Char('q') => {
                self.quit = true;
                return Some(Control::Quit);
            }
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                self.quit = true;
                return Some(Control::Quit);
            }
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Tab => {
                self.tab = (self.tab + 1) % TABS.len();
                self.detail = false;
            }
            KeyCode::Char('h') | KeyCode::Left | KeyCode::BackTab => {
                self.tab = (self.tab + TABS.len() - 1) % TABS.len();
                self.detail = false;
            }
            KeyCode::Char(c @ '1'..='9') => {
                self.tab = (c as usize - '1' as usize).min(TABS.len() - 1);
                self.detail = false;
            }
            KeyCode::Char('?') => self.tab = TABS.len() - 1,
            KeyCode::Char('j') | KeyCode::Down if n > 0 => *sel = (*sel + 1).min(n - 1),
            KeyCode::Char('k') | KeyCode::Up => *sel = sel.saturating_sub(1),
            KeyCode::Char('g') | KeyCode::Home => *sel = 0,
            KeyCode::Char('G') | KeyCode::End if n > 0 => *sel = n - 1,
            KeyCode::PageDown if n > 0 => *sel = (*sel + 10).min(n - 1),
            KeyCode::PageUp => *sel = sel.saturating_sub(10),
            KeyCode::Enter => self.detail = !self.detail,
            KeyCode::Esc => self.detail = false,
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                if !self.paused {
                    if let Some(v) = self.pending.take() {
                        self.view = Some(v);
                    }
                }
            }
            KeyCode::Char('s') => {
                let cols = self.columns();
                if cols > 0 {
                    self.sort[self.tab] = match self.sort[self.tab] {
                        None => Some(0),
                        Some(c) if c + 1 < cols => Some(c + 1),
                        Some(_) => None,
                    };
                }
            }
            KeyCode::Char('f') => {
                let cs = self.controllers();
                self.filter = match &self.filter {
                    None => cs.first().cloned(),
                    Some(cur) => cs.iter().position(|c| c == cur).and_then(|i| cs.get(i + 1)).cloned(),
                };
                self.flash = Some(format!("filter: {}", self.filter.as_deref().unwrap_or("all controllers")));
                return Some(Control::Filter(self.filter.clone()));
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                self.interval_s = next_interval(self.interval_s, true);
                return Some(Control::SetInterval(self.interval_s));
            }
            KeyCode::Char('-') => {
                self.interval_s = next_interval(self.interval_s, false);
                return Some(Control::SetInterval(self.interval_s));
            }
            KeyCode::Char('p') => {
                self.profiling = !self.profiling;
                self.flash = Some(if self.profiling {
                    "stage profiling starting (1 in 100 commands)".into()
                } else {
                    "stage profiling stopped".into()
                });
                return Some(Control::Profile(self.profiling));
            }
            KeyCode::Char('r') => {
                self.flash = Some("stage aggregates reset".into());
                return Some(Control::ResetProfile);
            }
            _ => {}
        }
        None
    }

    fn columns(&self) -> usize {
        let Some(v) = &self.view else { return 0 };
        match self.tab {
            0 => v.overview.headers.len(),
            2 => v.controllers.headers.len(),
            3 => v.queues.headers.len(),
            4 => v.latency.headers.len(),
            6 => v.tcp.headers.len(),
            _ => 0,
        }
    }
}

/// 0.25 s … 60 s in steps.
pub fn next_interval(cur: f64, up: bool) -> f64 {
    const STEPS: [f64; 9] = [0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 15.0, 30.0, 60.0];
    if up {
        STEPS.iter().copied().find(|&s| s > cur + 1e-9).unwrap_or(60.0)
    } else {
        STEPS.iter().rev().copied().find(|&s| s < cur - 1e-9).unwrap_or(0.25)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventKind;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent {
            code: c,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    #[test]
    fn navigation_and_controls() {
        let mut a = App::new(2.0);
        a.key(key(KeyCode::Char('l')));
        assert_eq!(a.tab, 1);
        a.key(key(KeyCode::Left));
        a.key(key(KeyCode::Left));
        assert_eq!(a.tab, 8);
        assert_eq!(a.key(key(KeyCode::Char('+'))), Some(Control::SetInterval(5.0)));
        assert_eq!(a.key(key(KeyCode::Char('-'))), Some(Control::SetInterval(2.0)));
        assert_eq!(a.key(key(KeyCode::Char('p'))), Some(Control::Profile(true)));
        a.key(key(KeyCode::Char(' ')));
        assert!(a.paused);
        a.update(View::default());
        assert!(a.view.is_none() && a.pending.is_some());
        a.key(key(KeyCode::Char(' ')));
        assert!(a.view.is_some());
        assert_eq!(a.key(key(KeyCode::Char('q'))), Some(Control::Quit));
        assert!(a.quit);
        assert_eq!(next_interval(60.0, true), 60.0);
        assert_eq!(next_interval(0.25, false), 0.25);
    }
}
