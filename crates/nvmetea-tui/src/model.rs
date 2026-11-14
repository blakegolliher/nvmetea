//! View model: what the TUI shows, prepared by the CLI's sampler from the
//! telemetry engine. The TUI never touches collectors.

use std::collections::BTreeMap;

/// One table cell.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cell {
    pub text: String,
    /// Why the value is unavailable (rendered as `-`; shown when selected).
    pub reason: Option<String>,
    /// Estimated value: rendered with a `~` prefix.
    pub estimated: bool,
    /// Low sample count: rendered dimmed.
    pub dim: bool,
}

impl Cell {
    pub fn new(t: impl Into<String>) -> Cell {
        Cell { text: t.into(), ..Default::default() }
    }
    pub fn unavailable(reason: impl Into<String>) -> Cell {
        Cell { text: "-".into(), reason: Some(reason.into()), ..Default::default() }
    }
    pub fn dim(mut self, d: bool) -> Cell {
        self.dim = d;
        self
    }
    pub fn shown(&self) -> String {
        if self.estimated { format!("~{}", self.text) } else { self.text.clone() }
    }
}

impl From<String> for Cell {
    fn from(s: String) -> Cell {
        Cell::new(s)
    }
}
impl From<&str> for Cell {
    fn from(s: &str) -> Cell {
        Cell::new(s)
    }
}

/// A table: headers, rows, and a key per row (for the detail panel).
#[derive(Debug, Clone, Default)]
pub struct TableData {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<Cell>>,
    pub keys: Vec<String>,
    /// Columns that are left-aligned (the rest right-aligned).
    pub left: usize,
    /// Shown above the table.
    pub note: Option<String>,
}

impl TableData {
    pub fn new(headers: &[&str], left: usize) -> TableData {
        TableData { headers: headers.iter().map(|h| h.to_string()).collect(), left, ..Default::default() }
    }
    pub fn push(&mut self, key: impl Into<String>, row: Vec<Cell>) {
        self.keys.push(key.into());
        self.rows.push(row);
    }
}

/// One span of a command timeline.
#[derive(Debug, Clone)]
pub struct SpanView {
    pub stage: String,
    pub label: String,
    pub us: f64,
    /// 'A'..'E' or '?'.
    pub family: char,
    pub bound: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TimelineView {
    pub title: String,
    pub detail: String,
    pub spans: Vec<SpanView>,
}

#[derive(Debug, Clone, Default)]
pub struct Breakdown {
    /// e.g. "since 10:42:01, 12,345 sampled commands (1 in 100, fentry)".
    pub header: String,
    /// One stage table per variant group (all controllers).
    pub groups: Vec<(String, TableData)>,
    pub per_controller: TableData,
    pub slowest: Vec<TimelineView>,
}

#[derive(Debug, Clone)]
pub struct EventView {
    pub at: String,
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct View {
    /// "host · kernel · nvmetea version".
    pub host: String,
    /// Wall-clock time of the sample.
    pub taken: String,
    pub interval_s: f64,
    /// Collector levels in use, e.g. "L0 sysfs+diskstats · L1 BPF · L3 TCP".
    pub levels: String,
    /// Persistent warnings (collector problems); stay until resolved.
    pub warnings: Vec<String>,
    pub overview: TableData,
    pub namespaces: TableData,
    pub subsystems: TableData,
    pub controllers: TableData,
    /// Controller name → (label, value) pairs for the detail panel.
    pub details: BTreeMap<String, Vec<(String, String)>>,
    pub queues: TableData,
    pub latency: TableData,
    /// `None` until stage profiling is started (key `p`).
    pub breakdown: Option<Breakdown>,
    /// Why the Breakdown tab is empty.
    pub breakdown_hint: String,
    pub tcp: TableData,
    pub events: Vec<EventView>,
}
