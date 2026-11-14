//! Table rendering and value formatting. Unavailable values print as `-`.

use nvmetea_core::Obs;
use std::fmt::Display;
use std::io::Write;

pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    left: usize,
    indent: usize,
}

impl Table {
    /// The first `left` columns are left-aligned, the rest right-aligned.
    pub fn new(headers: &[&str], left: usize) -> Table {
        Table { headers: headers.iter().map(|h| h.to_string()).collect(), rows: Vec::new(), left, indent: 0 }
    }
    pub fn indent(mut self, n: usize) -> Table {
        self.indent = n;
        self
    }
    pub fn push(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn render(&self) -> String {
        let n = self.headers.len();
        let mut w: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();
        for r in &self.rows {
            for (i, c) in r.iter().enumerate().take(n) {
                w[i] = w[i].max(c.chars().count());
            }
        }
        let pad = " ".repeat(self.indent);
        let line = |cells: &[String]| {
            let mut s = pad.clone();
            for (i, wi) in w.iter().enumerate() {
                let c = cells.get(i).map(String::as_str).unwrap_or("");
                let fill = wi.saturating_sub(c.chars().count());
                if i < self.left {
                    s.push_str(c);
                    if i + 1 < n {
                        s.push_str(&" ".repeat(fill));
                    }
                } else {
                    s.push_str(&" ".repeat(fill));
                    s.push_str(c);
                }
                if i + 1 < n {
                    s.push_str("  ");
                }
            }
            s.trim_end().to_string()
        };
        let mut out = line(&self.headers);
        out.push('\n');
        for r in &self.rows {
            out.push_str(&line(r));
            out.push('\n');
        }
        out
    }
}

pub fn dash() -> String {
    "-".to_string()
}

pub fn opt<T: Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(dash)
}

/// Counts and rates: 0.0 … 9999 as integers, then k/M.
pub fn count(o: &Obs<f64>) -> String {
    match o.value {
        None => dash(),
        Some(v) if v < 10.0 && v.fract() != 0.0 => format!("{v:.1}"),
        Some(v) if v < 10_000.0 => format!("{v:.0}"),
        Some(v) if v < 10_000_000.0 => format!("{:.1}k", v / 1e3),
        Some(v) => format!("{:.1}M", v / 1e6),
    }
}

/// Bytes per second in MiB/s.
pub fn mib_s(o: &Obs<f64>) -> String {
    match o.value {
        None => dash(),
        Some(v) => format!("{:.1}", v / 1048576.0),
    }
}

pub fn ms(o: &Obs<f64>) -> String {
    match o.value {
        None => dash(),
        Some(v) if v < 10.0 => format!("{v:.2}"),
        Some(v) => format!("{v:.1}"),
    }
}

pub fn pct(o: &Obs<f64>) -> String {
    match o.value {
        None => dash(),
        Some(v) => format!("{v:.1}"),
    }
}

pub fn obs<T: Display + Copy>(o: &Obs<T>) -> String {
    opt(o.value)
}

pub fn bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < U.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

/// Write to stdout; a closed pipe (`| head`) ends the program quietly.
pub fn emit(s: &str) {
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(s.as_bytes()).and_then(|_| out.flush()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("nvmetea: write error: {e}");
        std::process::exit(1);
    }
}

pub fn emit_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    let mut s = serde_json::to_string_pretty(v)?;
    s.push('\n');
    emit(&s);
    Ok(())
}

pub fn is_tty() -> bool {
    // SAFETY: isatty has no preconditions.
    unsafe { libc::isatty(1) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvmetea_core::Reason;

    #[test]
    fn table_alignment() {
        let mut t = Table::new(&["NAME", "N"], 1);
        t.push(vec!["a".into(), "1".into()]);
        t.push(vec!["long".into(), "100".into()]);
        assert_eq!(t.render(), "NAME    N\na       1\nlong  100\n");
    }

    #[test]
    fn unavailable_is_dash_never_zero() {
        let u: Obs<f64> = Obs::unavailable(Reason::FirstInterval);
        assert_eq!(count(&u), "-");
        assert_eq!(mib_s(&u), "-");
        assert_eq!(ms(&u), "-");
        assert_eq!(count(&Obs::derived(0.0, &[])), "0");
        assert_eq!(count(&Obs::derived(12_345.0, &[])), "12.3k");
        assert_eq!(bytes(1_000_000_000_000), "931.3 GiB");
    }
}

/// A latency given in µs, printed with an explicit unit ("850us", "1.44ms").
pub fn lat(o: &Obs<f64>) -> String {
    match o.value {
        None => dash(),
        Some(v) if v < 10.0 => format!("{v:.1}us"),
        Some(v) if v < 1000.0 => format!("{v:.0}us"),
        Some(v) if v < 1e6 => format!("{:.2}ms", v / 1e3),
        Some(v) => format!("{:.2}s", v / 1e6),
    }
}

#[cfg(test)]
mod lat_tests {
    use super::*;

    #[test]
    fn latency_units() {
        assert_eq!(lat(&Obs::derived(4.25, &[])), "4.2us");
        assert_eq!(lat(&Obs::derived(850.0, &[])), "850us");
        assert_eq!(lat(&Obs::derived(1440.5, &[])), "1.44ms");
        assert_eq!(lat(&Obs::derived(2_500_000.0, &[])), "2.50s");
        assert_eq!(lat(&Obs::unavailable(nvmetea_core::Reason::NoSamples)), "-");
    }
}
