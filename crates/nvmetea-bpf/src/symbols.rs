//! `/proc/kallsyms` and tracefs `available_filter_functions` scanning.
//!
//! kallsyms names are readable unprivileged (addresses are zeroed by
//! `kptr_restrict`). `available_filter_functions` needs tracefs access (root).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Text symbols per module (`""` = vmlinux), restricted to the requested set
/// for vmlinux to keep memory small, complete for the requested modules.
#[derive(Debug, Clone, Default)]
pub struct SymbolSet {
    pub by_module: BTreeMap<String, BTreeSet<String>>,
}

impl SymbolSet {
    pub fn has(&self, module: &str, name: &str) -> bool {
        self.by_module.get(module).is_some_and(|s| s.contains(name))
    }
    /// Compiler clones (`name.constprop.0`, `.isra.0`, `.part.0`; not `.cold`).
    pub fn clones(&self, module: &str, name: &str) -> Vec<String> {
        let prefix = format!("{name}.");
        self.by_module
            .get(module)
            .map(|s| {
                s.range(prefix.clone()..)
                    .take_while(|n| n.starts_with(&prefix))
                    .filter(|n| !n.ends_with(".cold"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn module_of(tok: Option<&str>) -> &str {
    tok.map(|m| m.trim_start_matches('[').trim_end_matches(']')).unwrap_or("")
}

/// Parse kallsyms-formatted text: `addr type name [module]`. Only text symbols.
pub fn parse_kallsyms<R: BufRead>(r: R, modules: &[&str], vmlinux_wanted: &BTreeSet<String>) -> SymbolSet {
    let mut s = SymbolSet::default();
    for line in r.lines().map_while(Result::ok) {
        let mut it = line.split_whitespace();
        let (Some(_addr), Some(ty), Some(name)) = (it.next(), it.next(), it.next()) else { continue };
        if !matches!(ty, "t" | "T") {
            continue;
        }
        let m = module_of(it.next());
        let base = name.split('.').next().unwrap_or(name);
        if (m.is_empty() && vmlinux_wanted.contains(base)) || (!m.is_empty() && modules.contains(&m)) {
            s.by_module.entry(m.to_string()).or_default().insert(name.to_string());
        }
    }
    s
}

/// Parse `available_filter_functions`: `name [module]` per line (some kernels
/// append an address column, which is ignored).
pub fn parse_filter_functions<R: BufRead>(r: R, modules: &[&str], vmlinux_wanted: &BTreeSet<String>) -> SymbolSet {
    let mut s = SymbolSet::default();
    for line in r.lines().map_while(Result::ok) {
        let mut it = line.split_whitespace();
        let Some(name) = it.next() else { continue };
        let m = module_of(it.find(|t| t.starts_with('[')));
        if (m.is_empty() && vmlinux_wanted.contains(name)) || (!m.is_empty() && modules.contains(&m)) {
            s.by_module.entry(m.to_string()).or_default().insert(name.to_string());
        }
    }
    s
}

pub fn read_kallsyms(
    proc_root: &Path,
    modules: &[&str],
    vmlinux_wanted: &BTreeSet<String>,
) -> std::io::Result<SymbolSet> {
    let f = std::fs::File::open(proc_root.join("kallsyms"))?;
    Ok(parse_kallsyms(BufReader::new(f), modules, vmlinux_wanted))
}

/// `Ok(None)` when tracefs is not accessible (permission or not mounted).
pub fn read_filter_functions(modules: &[&str], vmlinux_wanted: &BTreeSet<String>) -> Result<SymbolSet, std::io::Error> {
    let mut last = None;
    for p in ["/sys/kernel/tracing/available_filter_functions", "/sys/kernel/debug/tracing/available_filter_functions"]
    {
        match std::fs::File::open(p) {
            Ok(f) => return Ok(parse_filter_functions(BufReader::new(f), modules, vmlinux_wanted)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kallsyms_modules_and_clones() {
        let text = "\
0000000000000000 t nvme_tcp_io_work\t[nvme_tcp]
0000000000000000 t nvme_tcp_handle_r2t.constprop.0\t[nvme_tcp]
0000000000000000 t nvme_tcp_recv_skb.cold\t[nvme_tcp]
0000000000000000 t nvme_tcp_recv_skb\t[nvme_tcp]
0000000000000000 d nvme_tcp_ctrl_list\t[nvme_tcp]
0000000000000000 T skb_copy_datagram_iter
0000000000000000 T schedule
0000000000000000 t nvme_keep_alive_end_io\t[nvme_core]
";
        let want: BTreeSet<String> = ["skb_copy_datagram_iter".to_string()].into();
        let s = parse_kallsyms(text.as_bytes(), &["nvme_tcp"], &want);
        assert!(s.has("nvme_tcp", "nvme_tcp_io_work"));
        assert!(!s.has("nvme_tcp", "nvme_tcp_handle_r2t"));
        assert_eq!(s.clones("nvme_tcp", "nvme_tcp_handle_r2t"), ["nvme_tcp_handle_r2t.constprop.0"]);
        assert!(s.clones("nvme_tcp", "nvme_tcp_recv_skb").is_empty());
        assert!(!s.has("nvme_tcp", "nvme_tcp_ctrl_list")); // data, not text
        assert!(s.has("", "skb_copy_datagram_iter"));
        assert!(!s.has("", "schedule"));
        assert!(!s.has("nvme_core", "nvme_keep_alive_end_io")); // module not requested
    }

    #[test]
    fn filter_functions_format() {
        let text = "nvme_tcp_io_work [nvme_tcp]\nskb_copy_datagram_iter\nfoo [bar]\n";
        let want: BTreeSet<String> = ["skb_copy_datagram_iter".to_string()].into();
        let s = parse_filter_functions(text.as_bytes(), &["nvme_tcp"], &want);
        assert!(s.has("nvme_tcp", "nvme_tcp_io_work"));
        assert!(s.has("", "skb_copy_datagram_iter"));
        assert!(!s.has("bar", "foo"));
    }
}
