//! Block-layer counters (`/proc/diskstats`) and interval rates derived from them.
//!
//! diskstats time fields are milliseconds and include queueing; they give
//! aggregate means only, never percentiles.

use crate::quality::{Obs, Reason};
use serde::Serialize;

/// One `/proc/diskstats` row. Sector counts are in 512-byte units.
/// Discard (4.18+) and flush (5.5+) fields are optional.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DiskCounters {
    /// Device number from /proc/diskstats (hidden multipath path disks have no
    /// sysfs `dev` attribute, so this is their only source).
    pub major: u32,
    pub minor: u32,
    pub reads: u64,
    pub reads_merged: u64,
    pub read_sectors: u64,
    pub read_ms: u64,
    pub writes: u64,
    pub writes_merged: u64,
    pub write_sectors: u64,
    pub write_ms: u64,
    pub in_flight: u64,
    pub io_ms: u64,
    pub weighted_ms: u64,
    pub discards: Option<u64>,
    pub discard_sectors: Option<u64>,
    pub discard_ms: Option<u64>,
    pub flushes: Option<u64>,
    pub flush_ms: Option<u64>,
}

impl DiskCounters {
    /// True if every cumulative I/O counter is zero.
    pub fn is_idle_since_boot(&self) -> bool {
        self.reads == 0 && self.writes == 0 && self.discards.unwrap_or(0) == 0 && self.flushes.unwrap_or(0) == 0
    }

    /// Element-wise sum (used to derive namespace totals from paths).
    pub fn add(&mut self, o: &DiskCounters) {
        self.reads += o.reads;
        self.reads_merged += o.reads_merged;
        self.read_sectors += o.read_sectors;
        self.read_ms += o.read_ms;
        self.writes += o.writes;
        self.writes_merged += o.writes_merged;
        self.write_sectors += o.write_sectors;
        self.write_ms += o.write_ms;
        self.in_flight += o.in_flight;
        self.io_ms = self.io_ms.max(o.io_ms); // busy time does not add across devices
        self.weighted_ms += o.weighted_ms;
        self.discards = add_opt(self.discards, o.discards);
        self.discard_sectors = add_opt(self.discard_sectors, o.discard_sectors);
        self.discard_ms = add_opt(self.discard_ms, o.discard_ms);
        self.flushes = add_opt(self.flushes, o.flushes);
        self.flush_ms = add_opt(self.flush_ms, o.flush_ms);
    }
}

fn add_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x + y),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Per-interval rates for one device (or an aggregate of devices).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BlockRates {
    pub read_iops: Obs<f64>,
    pub write_iops: Obs<f64>,
    pub read_bytes_per_s: Obs<f64>,
    pub write_bytes_per_s: Obs<f64>,
    /// Mean time per completed read in the interval (diskstats ms; includes queueing).
    pub read_await_ms: Obs<f64>,
    pub write_await_ms: Obs<f64>,
    /// Instantaneous in-flight count at the end of the interval.
    pub in_flight: Obs<u64>,
}

const SRC: &[&str] = &["diskstats"];

impl BlockRates {
    pub fn unavailable(reason: Reason) -> Self {
        BlockRates {
            read_iops: Obs::unavailable(reason),
            write_iops: Obs::unavailable(reason),
            read_bytes_per_s: Obs::unavailable(reason),
            write_bytes_per_s: Obs::unavailable(reason),
            read_await_ms: Obs::unavailable(reason),
            write_await_ms: Obs::unavailable(reason),
            in_flight: Obs::unavailable(reason),
        }
    }

    /// Rates over `dt_s` seconds. A counter that decreased makes the dependent
    /// values unavailable (`counter_reset`) instead of negative or zero.
    pub fn between(prev: &DiskCounters, cur: &DiskCounters, dt_s: f64) -> BlockRates {
        if dt_s.is_nan() || dt_s <= 0.0 {
            return BlockRates::unavailable(Reason::FirstInterval);
        }
        let d = |a: u64, b: u64| b.checked_sub(a);
        let rate = |x: Option<u64>, scale: f64| match x {
            Some(v) => Obs::derived(v as f64 * scale / dt_s, SRC),
            None => Obs::unavailable(Reason::CounterReset),
        };
        let mean = |ms: Option<u64>, n: Option<u64>| match (ms, n) {
            (Some(_), Some(0)) => Obs::unavailable(Reason::NoSamples),
            (Some(ms), Some(n)) => Obs::derived(ms as f64 / n as f64, SRC),
            _ => Obs::unavailable(Reason::CounterReset),
        };
        let dr = d(prev.reads, cur.reads);
        let dw = d(prev.writes, cur.writes);
        BlockRates {
            read_iops: rate(dr, 1.0),
            write_iops: rate(dw, 1.0),
            read_bytes_per_s: rate(d(prev.read_sectors, cur.read_sectors), 512.0),
            write_bytes_per_s: rate(d(prev.write_sectors, cur.write_sectors), 512.0),
            read_await_ms: mean(d(prev.read_ms, cur.read_ms), dr),
            write_await_ms: mean(d(prev.write_ms, cur.write_ms), dw),
            in_flight: Obs::measured(cur.in_flight, SRC),
        }
    }
}

/// How a namespace's totals were obtained (finding F7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NsAccounting {
    /// The multipath head (or direct namespace) device counts its own I/O.
    Device,
    /// Head counters stay at zero while paths count I/O (e.g. Ubuntu 5.15):
    /// totals are the sum of the per-path devices.
    SumOfPaths,
    /// No counters found.
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(reads: u64, read_sectors: u64, read_ms: u64) -> DiskCounters {
        DiskCounters { reads, read_sectors, read_ms, ..Default::default() }
    }

    #[test]
    fn rates_and_await() {
        let r = BlockRates::between(&c(100, 800, 50), &c(300, 2400, 150), 2.0);
        assert_eq!(r.read_iops.value, Some(100.0));
        assert_eq!(r.read_bytes_per_s.value, Some(1600.0 * 512.0 / 2.0));
        assert_eq!(r.read_await_ms.value, Some(0.5));
        assert_eq!(r.write_await_ms.reason, Some(Reason::NoSamples));
        assert_eq!(r.write_iops.value, Some(0.0)); // a real zero: no writes happened
    }

    #[test]
    fn counter_decrease_is_reset_not_negative() {
        let r = BlockRates::between(&c(300, 0, 0), &c(10, 0, 0), 1.0);
        assert_eq!(r.read_iops.value, None);
        assert_eq!(r.read_iops.reason, Some(Reason::CounterReset));
    }

    #[test]
    fn zero_dt_is_first_interval() {
        let r = BlockRates::between(&c(1, 0, 0), &c(2, 0, 0), 0.0);
        assert_eq!(r.read_iops.reason, Some(Reason::FirstInterval));
    }

    #[test]
    fn sum_keeps_optional_fields() {
        let mut a = DiskCounters { reads: 1, io_ms: 10, flushes: Some(2), ..Default::default() };
        let b = DiskCounters { reads: 2, io_ms: 30, flushes: None, discards: Some(5), ..Default::default() };
        a.add(&b);
        assert_eq!(a.reads, 3);
        assert_eq!(a.io_ms, 30);
        assert_eq!(a.flushes, Some(2));
        assert_eq!(a.discards, Some(5));
    }
}
