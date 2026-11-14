//! Rendering (pure: a function of the app state, testable with TestBackend).

use crate::app::{App, TABS};
use crate::model::{Breakdown, Cell, TableData, TimelineView, View};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap};

const DIM: Style = Style::new().fg(Color::DarkGray);
const HEAD: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
const SEL: Style = Style::new().add_modifier(Modifier::REVERSED);
const WARN: Style = Style::new().fg(Color::Yellow);

fn family_color(f: char) -> Color {
    match f {
        'A' => Color::Blue,
        'B' => Color::Magenta,
        'C' => Color::Red,
        'D' => Color::Green,
        'E' => Color::Cyan,
        _ => Color::DarkGray,
    }
}

/// Numeric sort key of a rendered value ("1.44ms", "850us", "12.3k", "45%").
pub fn sort_key(s: &str) -> Option<f64> {
    let s = s.trim().trim_start_matches('~');
    let (num, mult) = [("us", 1e-6), ("ms", 1e-3), ("s", 1.0), ("k", 1e3), ("M", 1e6), ("%", 1.0), ("GiB", 1e9)]
        .iter()
        .find_map(|(u, m)| s.strip_suffix(u).map(|n| (n, *m)))
        .unwrap_or((s, 1.0));
    num.trim().parse::<f64>().ok().map(|v| v * mult)
}

fn sorted(t: &TableData, col: Option<usize>) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..t.rows.len()).collect();
    if let Some(c) = col {
        idx.sort_by(|&a, &b| {
            let (x, y) = (t.rows[a].get(c).map(|c| c.text.as_str()), t.rows[b].get(c).map(|c| c.text.as_str()));
            match (x.and_then(sort_key), y.and_then(sort_key)) {
                (Some(p), Some(q)) => q.total_cmp(&p), // numbers: largest first
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                _ => x.cmp(&y),
            }
        });
    }
    idx
}

fn cell_span(c: &Cell) -> ratatui::widgets::Cell<'static> {
    let style = if c.reason.is_some() || c.dim { DIM } else { Style::default() };
    ratatui::widgets::Cell::from(c.shown()).style(style)
}

fn table(f: &mut Frame, area: Rect, t: &TableData, selected: usize, sort: Option<usize>, title: &str) {
    let order = sorted(t, sort);
    let ncol = t.headers.len();
    let mut widths: Vec<u16> = t.headers.iter().map(|h| h.chars().count() as u16).collect();
    for r in &t.rows {
        for (i, c) in r.iter().enumerate().take(ncol) {
            widths[i] = widths[i].max(c.shown().chars().count() as u16).min(48);
        }
    }
    let header = Row::new(t.headers.iter().enumerate().map(|(i, h)| {
        let mark = if sort == Some(i) { "↓" } else { "" };
        ratatui::widgets::Cell::from(format!("{h}{mark}"))
    }))
    .style(HEAD);
    let rows: Vec<Row> = order.iter().map(|&i| Row::new(t.rows[i].iter().take(ncol).map(cell_span))).collect();
    let mut state = TableState::default();
    if !t.rows.is_empty() {
        state.select(Some(selected.min(t.rows.len() - 1)));
    }
    let block = Block::default().borders(Borders::ALL).title(title.to_string());
    let (block, area) = match &t.note {
        Some(n) => {
            let ch = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(1)])
                .split(area);
            f.render_widget(Paragraph::new(Span::styled(n.clone(), DIM)), ch[0]);
            (block, ch[1])
        }
        None => (block, area),
    };
    let w = Table::new(rows, widths.iter().map(|&w| Constraint::Length(w + 1)).collect::<Vec<_>>())
        .header(header)
        .block(block)
        .row_highlight_style(SEL);
    f.render_stateful_widget(w, area, &mut state);
}

/// The row under the cursor, in display order.
fn selected_row(t: &TableData, selected: usize, sort: Option<usize>) -> Option<usize> {
    let order = sorted(t, sort);
    order.get(selected.min(order.len().saturating_sub(1))).copied()
}

fn detail_panel(f: &mut Frame, area: Rect, title: &str, kv: &[(String, String)]) {
    let w = area.width.min(90);
    let h = (kv.len() as u16 + 2).min(area.height);
    let r = Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let lines: Vec<Line> = kv
        .iter()
        .map(|(k, v)| Line::from(vec![Span::styled(format!("{k:<22}"), HEAD), Span::raw(v.clone())]))
        .collect();
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(title.to_string())),
        r,
    );
}

/// Detail of a generic row: every column, with reasons of unavailable values.
fn row_detail(t: &TableData, i: usize) -> Vec<(String, String)> {
    t.headers
        .iter()
        .zip(&t.rows[i])
        .map(|(h, c)| {
            let v = match &c.reason {
                Some(r) => format!("- (unavailable: {r})"),
                None => c.shown(),
            };
            (h.clone(), v)
        })
        .collect()
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    f.render_widget(Clear, area);
    f.render_widget(Block::default().style(Style::default()), area);
    let ch = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Min(3), Constraint::Length(2)])
        .split(area);
    let Some(v) = &app.view else {
        f.render_widget(Paragraph::new("nvmetea: collecting the first sample…"), ch[2]);
        status(f, ch[3], app, None);
        return;
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("nvmetea ", HEAD),
            Span::raw(format!("{}  {}  every {:.2}s  ", v.host, v.taken, app.interval_s)),
            Span::styled(v.levels.clone(), DIM),
        ])),
        ch[0],
    );
    let titles: Vec<Line> = TABS.iter().enumerate().map(|(i, t)| Line::from(format!("{} {t}", i + 1))).collect();
    f.render_widget(Tabs::new(titles).select(app.tab).highlight_style(SEL).divider("│"), ch[1]);
    let body = ch[2];
    let sel = app.selected[app.tab];
    let sort = app.sort[app.tab];
    match app.tab {
        0 => {
            // size the tables to their rows; events take the rest
            let want = |t: &TableData| t.rows.len() as u16 + 3 + u16::from(t.note.is_some());
            let h = body.height;
            let c = want(&v.overview).min(h / 2).max(4);
            let n = want(&v.namespaces).min(h.saturating_sub(c) / 2).max(3);
            let parts = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(c), Constraint::Length(n), Constraint::Min(3)])
                .split(body);
            table(f, parts[0], &v.overview, sel, sort, "Controllers");
            table(f, parts[1], &v.namespaces, 0, None, "Namespaces");
            events(f, parts[2], v, usize::MAX, "Recent events");
            if app.detail {
                if let Some(i) = selected_row(&v.overview, sel, sort) {
                    let key = &v.overview.keys[i];
                    let kv = v.details.get(key).cloned().unwrap_or_else(|| row_detail(&v.overview, i));
                    detail_panel(f, body, key, &kv);
                }
            }
        }
        1 => table(f, body, &v.subsystems, sel, None, "Subsystems → namespaces → paths"),
        2 | 3 | 4 | 6 => {
            let (t, title) = match app.tab {
                2 => (&v.controllers, "Controllers"),
                3 => (&v.queues, "Queues (Level 1; TCP from Level 3)"),
                4 => (&v.latency, "Latency (Level 1, interval percentiles)"),
                _ => (&v.tcp, "Queue connections"),
            };
            table(f, body, t, sel, sort, title);
            if app.detail {
                if let Some(i) = selected_row(t, sel, sort) {
                    let key = &t.keys[i];
                    let kv = if app.tab == 2 { v.details.get(key).cloned() } else { None }
                        .unwrap_or_else(|| row_detail(t, i));
                    detail_panel(f, body, key, &kv);
                }
            }
        }
        5 => match &v.breakdown {
            Some(b) => breakdown(f, body, b, sel),
            None => {
                f.render_widget(
                    Paragraph::new(v.breakdown_hint.clone())
                        .wrap(Wrap { trim: true })
                        .block(Block::default().borders(Borders::ALL).title("Breakdown")),
                    body,
                );
            }
        },
        7 => events(f, body, v, sel, "Events"),
        _ => help(f, body),
    }
    status(f, ch[3], app, Some(v));
}

fn events(f: &mut Frame, area: Rect, v: &View, selected: usize, title: &str) {
    let h = area.height.saturating_sub(2) as usize;
    let n = v.events.len();
    // follow the newest unless the cursor is above the last page
    let end = if selected >= n.saturating_sub(1) { n } else { (selected + 1).max(h.min(n)) };
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = v.events[start..end]
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let st = if start + i == selected { SEL } else { Style::default() };
            let kc = match e.kind.as_str() {
                "slow" => Color::Yellow,
                "tcp" => Color::Red,
                "state" | "transition" => Color::Magenta,
                _ => Color::Gray,
            };
            Line::from(vec![
                Span::styled(format!("{} ", e.at), DIM),
                Span::styled(format!("{:<10}", e.kind), Style::default().fg(kc)),
                Span::styled(e.text.clone(), st),
            ])
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(format!("{title} ({n})"))),
        area,
    );
}

fn timeline(f: &mut Frame, area: Rect, t: &TimelineView) {
    let total: f64 = t.spans.iter().map(|s| s.us).sum();
    let w = area.width.saturating_sub(2) as f64;
    let mut bar: Vec<Span> = Vec::new();
    for s in &t.spans {
        let cells = if total > 0.0 { (s.us / total * w).round() as usize } else { 0 };
        if cells > 0 {
            bar.push(Span::styled("█".repeat(cells), Style::default().fg(family_color(s.family))));
        }
    }
    let mut lines = vec![Line::from(Span::styled(t.detail.clone(), DIM)), Line::from(bar), Line::from("")];
    for s in &t.spans {
        let mark = match s.bound.as_deref() {
            Some("upper bound") => " ^",
            Some("lower bound") => " v",
            _ => "",
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:<4}", s.stage), Style::default().fg(family_color(s.family))),
            Span::raw(format!("{:>10}  ", fmt_us(s.us))),
            Span::raw(format!("{}{mark}", s.label)),
        ]));
    }
    f.render_widget(Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(t.title.clone())), area);
}

pub fn fmt_us(v: f64) -> String {
    if v < 10.0 {
        format!("{v:.1}us")
    } else if v < 1000.0 {
        format!("{v:.0}us")
    } else if v < 1e6 {
        format!("{:.2}ms", v / 1e3)
    } else {
        format!("{:.2}s", v / 1e6)
    }
}

fn breakdown(f: &mut Frame, area: Rect, b: &Breakdown, sel: usize) {
    let ch = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Percentage(55), Constraint::Min(6)])
        .split(area);
    f.render_widget(Paragraph::new(Span::styled(b.header.clone(), DIM)), ch[0]);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(ch[1]);
    match b.groups.first() {
        Some((title, t)) => table(f, top[0], t, usize::MAX, None, title),
        None => f.render_widget(
            Paragraph::new("no complete records yet").block(Block::default().borders(Borders::ALL)),
            top[0],
        ),
    }
    table(f, top[1], &b.per_controller, usize::MAX, None, "Per queue (stage family means)");
    match b.slowest.get(sel.min(b.slowest.len().saturating_sub(1))) {
        Some(t) => timeline(f, ch[2], t),
        None => f.render_widget(
            Paragraph::new("no sampled commands yet").block(Block::default().borders(Borders::ALL)),
            ch[2],
        ),
    }
}

fn help(f: &mut Frame, area: Rect) {
    let keys = [
        ("q, Ctrl-C", "quit"),
        ("h/l, ←/→, Tab, 1-9", "switch tab"),
        ("j/k, ↑/↓, g/G, PgUp/PgDn", "move the selection"),
        ("Enter / Esc", "open / close the detail panel (shows why a value is unavailable)"),
        ("Space", "pause / resume the display (sampling continues)"),
        ("s", "sort by the next column (largest first); again to cycle, off after the last"),
        ("f", "cycle the controller filter"),
        ("+ / -", "sampling interval (0.25 s … 60 s)"),
        ("p", "start / stop stage profiling (Level 2, 1 in 100 commands) for the Breakdown tab"),
        ("r", "reset the stage aggregates"),
        ("?", "this help"),
    ];
    let mut lines: Vec<Line> =
        keys.iter().map(|(k, d)| Line::from(vec![Span::styled(format!("{k:<28}"), HEAD), Span::raw(*d)])).collect();
    lines.push(Line::from(""));
    for l in [
        "-      unavailable (select the row and press Enter to see why); never shown as 0",
        "~      estimated value",
        "dim    low sample count",
        "^ / v  C stages end at the first receive notification: C is an upper bound, the wakeup after it a lower bound",
        "Stages: A block submission · B transmit · C remote/transport (network + target) · D receive · E completion",
    ] {
        lines.push(Line::from(Span::styled(l, DIM)));
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(Block::default().borders(Borders::ALL).title("Help")),
        area,
    );
}

fn status(f: &mut Frame, area: Rect, app: &App, v: Option<&View>) {
    let mut first: Vec<Span> = Vec::new();
    if app.paused {
        first.push(Span::styled("PAUSED  ", Style::default().fg(Color::Black).bg(Color::Yellow)));
    }
    if let Some(fl) = &app.flash {
        first.push(Span::raw(format!("{fl}  ")));
    }
    if let Some(v) = v {
        if let Some(w) = v.warnings.first() {
            let more = if v.warnings.len() > 1 { format!(" (+{} more)", v.warnings.len() - 1) } else { String::new() };
            first.push(Span::styled(format!("{w}{more}"), WARN));
        }
    }
    let hint = Line::from(Span::styled(
        format!(
            "q quit · h/l tabs · j/k select · Enter detail · Space pause · s sort · f filter ({}) · +/- interval · p profile{} · ? help",
            app.filter.as_deref().unwrap_or("all"),
            if app.profiling { " (on)" } else { "" }
        ),
        DIM,
    ));
    f.render_widget(Paragraph::new(vec![Line::from(first), hint]), area);
}
