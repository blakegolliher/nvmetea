//! NVMe command telemetry from the Level 1 BPF collector.
//!
//! Histograms use the log-linear scheme of `bpf/nvmetea.h`: bucket 0 is
//! < 256 ns, buckets 1..=224 split each power of two from 2^8 to 2^36 ns into
//! 8 linear sub-buckets, bucket 225 is ≥ 2^36 ns. Bucket width is at most 12.5 %
//! of its lower edge.

use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Instant;

pub const HIST_USED: usize = 226;
/// Resolution of histogram-derived percentiles (upper-edge estimator).
pub const PERCENTILE_RESOLUTION: f64 = 0.125;

/// Bucket index of a value in ns; identical to `nvt_bucket()` in `bpf/hist.bpf.h`.
pub fn bucket_index(v: u64) -> usize {
    if v < 256 {
        return 0;
    }
    if v >= 1u64 << 36 {
        return HIST_USED - 1;
    }
    let k = 63 - v.leading_zeros() as usize; // 8..=35
    1 + (k - 8) * 8 + ((v >> (k - 3)) & 7) as usize
}

/// `[lower, upper)` in ns; `upper` is `None` for the overflow bucket.
pub fn bucket_bounds(i: usize) -> (u64, Option<u64>) {
    match i {
        0 => (0, Some(256)),
        i if i >= HIST_USED - 1 => (1u64 << 36, None),
        i => {
            let k = 8 + (i - 1) / 8;
            let sub = ((i - 1) % 8) as u64;
            let step = 1u64 << (k - 3);
            let lower = (1u64 << k) + sub * step;
            (lower, Some(lower + step))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Histogram {
    /// Counts per bucket (length [`HIST_USED`]).
    pub buckets: Vec<u64>,
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram { buckets: vec![0; HIST_USED] }
    }
}

impl Histogram {
    pub fn from_slice(b: &[u64]) -> Histogram {
        let mut h = Histogram::default();
        for (d, s) in h.buckets.iter_mut().zip(b.iter()) {
            *d = *s;
        }
        h
    }
    pub fn count(&self) -> u64 {
        self.buckets.iter().sum()
    }
    pub fn record(&mut self, v: u64) {
        self.buckets[bucket_index(v)] += 1;
    }
    pub fn add(&mut self, o: &Histogram) {
        for (a, b) in self.buckets.iter_mut().zip(o.buckets.iter()) {
            *a += *b;
        }
    }
    /// `self - prev`, or `None` if any bucket decreased (the series was reset).
    pub fn since(&self, prev: &Histogram) -> Option<Histogram> {
        let mut out = Histogram::default();
        for (i, (c, p)) in self.buckets.iter().zip(prev.buckets.iter()).enumerate() {
            out.buckets[i] = c.checked_sub(*p)?;
        }
        Some(out)
    }
    /// Upper edge (ns) of the bucket that holds rank ⌈p·N⌉; `None` without
    /// samples. For the overflow bucket the lower edge is returned and
    /// `saturated` is true.
    pub fn percentile(&self, p: f64) -> Option<Percentile> {
        let n = self.count();
        if n == 0 || !(0.0..=1.0).contains(&p) {
            return None;
        }
        let rank = ((p * n as f64).ceil() as u64).max(1);
        let mut acc = 0;
        for (i, c) in self.buckets.iter().enumerate() {
            acc += c;
            if acc >= rank {
                let (lo, hi) = bucket_bounds(i);
                return Some(match hi {
                    Some(h) => Percentile { ns: h, saturated: false },
                    None => Percentile { ns: lo, saturated: true },
                });
            }
        }
        None
    }
    /// Upper edge of the highest non-empty bucket.
    pub fn max_bound(&self) -> Option<Percentile> {
        let i = self.buckets.iter().rposition(|&c| c > 0)?;
        let (lo, hi) = bucket_bounds(i);
        Some(match hi {
            Some(h) => Percentile { ns: h, saturated: false },
            None => Percentile { ns: lo, saturated: true },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Percentile {
    pub ns: u64,
    /// The value lies in the overflow bucket: `ns` is a lower bound.
    pub saturated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Read,
    Write,
    Flush,
    Other,
    Admin,
}

impl Op {
    pub const ALL: [Op; 5] = [Op::Read, Op::Write, Op::Flush, Op::Other, Op::Admin];
    pub fn from_index(i: usize) -> Option<Op> {
        Op::ALL.get(i).copied()
    }
    pub fn index(self) -> usize {
        self as usize
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Read => "read",
            Op::Write => "write",
            Op::Flush => "flush",
            Op::Other => "other",
            Op::Admin => "admin",
        }
    }
}

/// Which interval a histogram measures (`docs/latency-model.md` §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatMetric {
    /// `nvme_setup_cmd` → `nvme_complete_rq` (per dispatch).
    Command,
    /// `rq->start_time_ns` → `block_rq_complete`.
    Request,
    /// Stage A: `rq->start_time_ns` → first `nvme_setup_cmd`.
    StageA,
    /// Stage E2: `nvme_complete_rq` → `block_rq_complete`.
    StageE2,
}

impl LatMetric {
    pub fn from_index(i: u8) -> Option<LatMetric> {
        match i {
            0 => Some(LatMetric::Command),
            1 => Some(LatMetric::Request),
            2 => Some(LatMetric::StageA),
            3 => Some(LatMetric::StageE2),
            _ => None,
        }
    }
}

/// Cumulative per-queue counters (one BPF `qstats` entry), indexed by [`Op`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct QueueCounters {
    pub dispatched: [u64; 5],
    pub bytes: [u64; 5],
    pub completed: [u64; 5],
    pub nvme_errors: [u64; 5],
    pub cmd_lat_sum_ns: [u64; 5],
    pub cmd_lat_cnt: [u64; 5],
    pub req_lat_sum_ns: [u64; 5],
    pub req_lat_cnt: [u64; 5],
    pub status_type: [u64; 8],
    pub retries: u64,
    pub requeues: u64,
    pub failovers: u64,
    pub retried_completed: u64,
    pub error_completed: u64,
    pub inflight: i64,
    pub inflight_max: u64,
    pub inflight_epoch: u64,
}

/// Collector-health counters (BPF per-CPU, summed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BpfCounters {
    pub dispatches_tcp: u64,
    pub untracked_completions: u64,
    pub cid_mismatches: u64,
    pub stale_replaced: u64,
    pub map_full_inflight: u64,
    pub map_full_qstats: u64,
    pub map_full_hist: u64,
    pub events_lost: u64,
    pub slow_suppressed: u64,
    pub start_missing: u64,
    pub order_violations: u64,
    pub async_events: u64,
}

/// One read of the Level 1 BPF maps.
#[derive(Debug, Clone)]
pub struct NvmeSample {
    pub taken: Instant,
    /// (controller instance, qid) → counters.
    pub queues: BTreeMap<(u32, u16), QueueCounters>,
    /// (instance, qid, op, metric) → histogram.
    pub hists: BTreeMap<(u32, u16, Op, LatMetric), Histogram>,
    /// (dev_t, op) → request-latency histogram of a path / namespace device.
    pub path_hists: BTreeMap<(u32, Op), Histogram>,
    pub counters: BpfCounters,
    /// The high-watermark epoch in effect when this sample was taken.
    pub epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared with the BPF implementation (bpf/hist.bpf.h): value → bucket.
    pub const VECTORS: &[(u64, usize)] = &[
        (0, 0),
        (255, 0),
        (256, 1),
        (287, 1),
        (288, 2),
        (511, 8),
        (512, 9),
        (1_000, 16),
        (1_024, 17),
        (100_000, 69),
        (1_000_000, 96),
        ((1u64 << 36) - 1, 224),
        (1u64 << 36, 225),
        (u64::MAX, 225),
    ];

    #[test]
    fn bucket_vectors_and_bounds() {
        for &(v, b) in VECTORS {
            assert_eq!(bucket_index(v), b, "value {v}");
            let (lo, hi) = bucket_bounds(b);
            assert!(v >= lo, "{v} >= {lo}");
            if let Some(h) = hi {
                assert!(v < h, "{v} < {h}");
            }
        }
        // contiguous, increasing, and width ≤ 12.5 % of the lower edge
        let mut prev_hi = 0;
        for i in 0..HIST_USED - 1 {
            let (lo, hi) = bucket_bounds(i);
            let hi = hi.expect("bounded");
            assert_eq!(lo, prev_hi, "bucket {i}");
            if i > 0 {
                assert!((hi - lo) as f64 <= lo as f64 * PERCENTILE_RESOLUTION + 1e-9);
            }
            prev_hi = hi;
        }
        assert_eq!(prev_hi, 1u64 << 36);
    }

    #[test]
    fn exhaustive_against_bounds() {
        // every bucket edge maps into its own bucket
        for i in 1..HIST_USED - 1 {
            let (lo, hi) = bucket_bounds(i);
            assert_eq!(bucket_index(lo), i);
            assert_eq!(bucket_index(hi.expect("bounded") - 1), i);
        }
    }

    #[test]
    fn percentiles() {
        let mut h = Histogram::default();
        assert_eq!(h.percentile(0.5), None);
        for _ in 0..90 {
            h.record(100_000); // 100 µs
        }
        for _ in 0..10 {
            h.record(2_000_000); // 2 ms
        }
        let p50 = h.percentile(0.5).expect("p50").ns;
        assert!((100_000..=112_500).contains(&p50), "{p50}");
        let p90 = h.percentile(0.9).expect("p90").ns;
        assert!(p90 < 2_000_000);
        let p99 = h.percentile(0.99).expect("p99").ns;
        assert!((2_000_000..=2_250_000).contains(&p99), "{p99}");
        assert_eq!(h.max_bound().map(|p| p.ns), Some(p99));
        h.record(u64::MAX);
        assert!(h.max_bound().expect("max").saturated);
    }

    #[test]
    fn since_detects_reset() {
        let mut a = Histogram::default();
        a.record(1000);
        let mut b = a.clone();
        b.record(1000);
        b.record(5000);
        let d = b.since(&a).expect("monotonic");
        assert_eq!(d.count(), 2);
        assert!(a.since(&b).is_none());
    }
}
