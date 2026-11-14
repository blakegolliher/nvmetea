//! nvmetea terminal UI (`docs/architecture.md` §11.2).
//!
//! Tabs: Overview, Subsystems, Controllers, Queues, Latency, Breakdown, TCP,
//! Events, Help.
//!
//! - **Threads.** A sampler thread in the CLI builds [`model::View`]s from the
//!   telemetry engine. [`term::run`] draws the newest one and polls input every
//!   80 ms. The TUI never touches collectors.
//! - **Values.** Unavailable values render as `-`, and the detail panel shows
//!   why. Estimated values carry `~`; low-sample values are dimmed.
//! - **Status line.** Collector warnings stay on it until they are resolved.

pub mod app;
pub mod model;
pub mod term;
pub mod ui;

pub use app::{App, Control};
pub use model::View;

/// Render one frame of `app` into plain text (a `width` × `height` cell grid).
pub fn render_text(app: &App, width: u16, height: u16) -> String {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    let Ok(mut t) = Terminal::new(TestBackend::new(width, height)) else { return String::new() };
    if t.draw(|f| ui::draw(f, app)).is_err() {
        return String::new();
    }
    let buf = t.backend().buffer().clone();
    let mut s = String::new();
    for y in 0..buf.area.height {
        let mut line = String::new();
        for x in 0..buf.area.width {
            line.push_str(buf[(x, y)].symbol());
        }
        s.push_str(line.trim_end());
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn view() -> View {
        let mut ov = TableData::new(&["CTRL", "STATE", "R IOPS", "REQ p99"], 2);
        ov.push("nvme2", vec!["nvme2".into(), "live".into(), "12.3k".into(), "1.44ms".into()]);
        ov.push("nvme3", vec!["nvme3".into(), "connecting".into(), Cell::unavailable("first_interval"), "-".into()]);
        let mut d = std::collections::BTreeMap::new();
        d.insert("nvme2".to_string(), vec![("address".to_string(), "192.0.2.1:4420".to_string())]);
        let mut st = TableData::new(&["STAGE", "WHAT", "MEAN", "SHARE"], 2);
        st.push("C1", vec!["C1".into(), "remote/transport ^".into(), "1.41ms".into(), "98.7%".into()]);
        View {
            host: "h · 6.12".into(),
            taken: "10:00:00".into(),
            interval_s: 2.0,
            levels: "L0 · L1 BPF · L3 TCP".into(),
            warnings: vec!["stage profiling off: press p".into()],
            overview: ov,
            details: d,
            breakdown: Some(Breakdown {
                header: "since 10:00:00".into(),
                groups: vec![("READ 8KiB".into(), st)],
                per_controller: TableData::new(&["CTRL"], 1),
                slowest: vec![TimelineView {
                    title: "nvme2/q4 read 8KiB 7.43ms".into(),
                    detail: "cpu 91->28".into(),
                    spans: vec![
                        SpanView {
                            stage: "A".into(),
                            label: "block submission".into(),
                            us: 3.8,
                            family: 'A',
                            bound: None,
                        },
                        SpanView {
                            stage: "C1".into(),
                            label: "remote".into(),
                            us: 7410.0,
                            family: 'C',
                            bound: Some("upper bound".into()),
                        },
                    ],
                }],
            }),
            events: vec![EventView {
                at: "10:00:00".into(),
                kind: "state".into(),
                text: "nvme3 live -> connecting".into(),
            }],
            ..Default::default()
        }
    }

    fn render(app: &App) -> String {
        let mut t = Terminal::new(TestBackend::new(120, 30)).expect("term");
        t.draw(|f| ui::draw(f, app)).expect("draw");
        let buf = t.backend().buffer().clone();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn overview_renders_unavailable_as_dash_and_persistent_warning() {
        let mut a = App::new(2.0);
        a.update(view());
        let s = render(&a);
        assert!(s.contains("nvme2") && s.contains("12.3k") && s.contains("1.44ms"), "{s}");
        assert!(s.contains("stage profiling off: press p"), "{s}");
        assert!(s.contains("nvme3 live -> connecting"), "{s}");
        // detail panel shows the reason of an unavailable value
        a.selected[0] = 1;
        a.detail = true;
        let s = render(&a);
        assert!(s.contains("unavailable: first_interval"), "{s}");
    }

    #[test]
    fn breakdown_and_help_render() {
        let mut a = App::new(2.0);
        a.update(view());
        a.tab = 5;
        let s = render(&a);
        assert!(s.contains("remote/transport ^") && s.contains("98.7%"), "{s}");
        assert!(s.contains("nvme2/q4 read 8KiB 7.43ms") && s.contains("7.41ms"), "{s}");
        a.tab = 8;
        let s = render(&a);
        assert!(s.contains("never shown as 0"), "{s}");
    }

    #[test]
    fn sort_keys_understand_units() {
        assert!(ui::sort_key("1.44ms").expect("ms") > ui::sort_key("850us").expect("us"));
        assert_eq!(ui::sort_key("12.3k"), Some(12300.0));
        assert_eq!(ui::sort_key("-"), None);
    }
}
