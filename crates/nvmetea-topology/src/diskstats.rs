//! `/proc/diskstats` parsing. Namespace/controller accounting lives in
//! `nvmetea_core::engine` (it only needs model types).

use nvmetea_core::model::{DiskCounters, ScanIssue};
use std::collections::BTreeMap;
use std::path::Path;

/// Parse `/proc/diskstats` text. Only whole NVMe block devices are kept;
/// partitions and other disks are skipped. Malformed lines become issues.
pub fn parse(text: &str) -> (BTreeMap<String, DiskCounters>, Vec<ScanIssue>) {
    let mut out = BTreeMap::new();
    let mut issues = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let name = f[2];
        if !crate::names::is_nvme_block(name) {
            continue;
        }
        let nums: Result<Vec<u64>, _> = f[3..].iter().map(|s| s.parse::<u64>()).collect();
        let nums = match nums {
            Ok(n) if n.len() >= 11 => n,
            _ => {
                issues.push(ScanIssue {
                    path: format!("/proc/diskstats:{}", lineno + 1),
                    problem: format!("unexpected line for {name}"),
                });
                continue;
            }
        };
        let g = |i: usize| nums.get(i).copied();
        let c = DiskCounters {
            major: f[0].parse().unwrap_or(0),
            minor: f[1].parse().unwrap_or(0),
            reads: nums[0],
            reads_merged: nums[1],
            read_sectors: nums[2],
            read_ms: nums[3],
            writes: nums[4],
            writes_merged: nums[5],
            write_sectors: nums[6],
            write_ms: nums[7],
            in_flight: nums[8],
            io_ms: nums[9],
            weighted_ms: nums[10],
            discards: if nums.len() >= 15 { g(11) } else { None },
            discard_sectors: if nums.len() >= 15 { g(13) } else { None },
            discard_ms: if nums.len() >= 15 { g(14) } else { None },
            flushes: if nums.len() >= 17 { g(15) } else { None },
            flush_ms: if nums.len() >= 17 { g(16) } else { None },
        };
        out.insert(name.to_string(), c);
    }
    (out, issues)
}

pub fn read(proc_root: &Path) -> std::io::Result<(BTreeMap<String, DiskCounters>, Vec<ScanIssue>)> {
    let text = std::fs::read_to_string(proc_root.join("diskstats"))?;
    Ok(parse(&text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::tcp_multipath_host;
    use crate::scan::scan;
    use crate::sysfs::SysRoot;
    use nvmetea_core::engine::{controller_totals, namespace_totals};
    use nvmetea_core::model::NsAccounting;

    const SAMPLE: &str = "\
 259       0 nvme0n1 32213 1026 3522384 5509 82080 36863 8933034 247482 0 5185 252991 0 0 0 0 0 0
 259       1 nvme0n1p1 455 962 16102 150 2 0 2 0 0 19 150 0 0 0 0 0 0
 259       5 nvme2c2n1 5384477 429 436475308 9427432 2744200 3362 558161779 10911589 3 9500733 20776474 0 0 0 0 387146 437451
 259       6 nvme2n1 34597147 0 2622334389 56866874 14081172 0 3350770745 61094765 0 18648383 117961639 0 0 0 0 0 0
   8       0 sda 1 2 3 4 5 6 7 8 9 10 11
 259       9 nvme2c3n1 10 0 80 5 0 0 0 0 0 5 5
 259      10 nvme2c4n1 garbage
";

    #[test]
    fn parse_formats() {
        let (m, issues) = parse(SAMPLE);
        assert_eq!(m.len(), 4, "{m:?}");
        assert!(!m.contains_key("nvme0n1p1") && !m.contains_key("sda"));
        let p = m["nvme2c2n1"];
        assert_eq!(p.reads, 5384477);
        assert_eq!((p.major, p.minor), (259, 5));
        assert_eq!(p.in_flight, 3);
        assert_eq!(p.flushes, Some(387146));
        assert_eq!(p.flush_ms, Some(437451));
        let old = m["nvme2c3n1"]; // 11-field (pre-4.18) line
        assert_eq!(old.discards, None);
        assert_eq!(old.flushes, None);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn head_accounting_vs_sum_of_paths() {
        let f = tcp_multipath_host("ds", 2, 1);
        let topo = scan(&SysRoot::new(f.as_path()));
        let ns = topo.namespace("nvme2n1").expect("ns");
        let path = |r| DiskCounters { reads: r, read_sectors: r * 8, ..Default::default() };
        let mut m = BTreeMap::new();
        m.insert("nvme2c2n1".to_string(), path(10));
        m.insert("nvme2c3n1".to_string(), path(5));
        // head counts its own I/O (6.3+ / RHEL 9)
        m.insert("nvme2n1".to_string(), path(15));
        let t = namespace_totals(ns, &m);
        assert_eq!(t.accounting, NsAccounting::Device);
        assert_eq!(t.counters.map(|c| c.reads), Some(15));
        // head stays at zero while paths count (Ubuntu 5.15)
        m.insert("nvme2n1".to_string(), DiskCounters::default());
        let t = namespace_totals(ns, &m);
        assert_eq!(t.accounting, NsAccounting::SumOfPaths);
        assert_eq!(t.counters.map(|c| c.reads), Some(15));
        // all idle: the head's own (zero) counters are a real answer
        let mut idle = BTreeMap::new();
        idle.insert("nvme2n1".to_string(), DiskCounters::default());
        idle.insert("nvme2c2n1".to_string(), DiskCounters::default());
        assert_eq!(namespace_totals(ns, &idle).accounting, NsAccounting::Device);
        assert_eq!(namespace_totals(ns, &BTreeMap::new()).accounting, NsAccounting::Unavailable);
        assert_eq!(controller_totals(&topo, "nvme3", &m).map(|c| c.reads), Some(5));
        assert_eq!(controller_totals(&topo, "nvme9", &m), None);
    }
}
