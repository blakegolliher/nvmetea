//! Aggregation of sampled command partitions (`docs/latency-model.md` §6):
//! - R3: stage tables use complete records only (every stage of the variant
//!   classified); the end-to-end mean is over the same set, so stage shares
//!   add up to 100 %. Complete and partial counts are always reported.
//! - R5: stage percentiles describe each stage alone; nothing sums them.
//! - R6: groups are (controller, operation, variant, size class); retried,
//!   timed-out and failed commands are counted separately, never mixed in.
//! - R7: these are sampled counts; totals come from Level 1.

use crate::partition::{Partition, Span, Stage, Variant, partition};
use nvmetea_core::model::stage::flag;
use nvmetea_core::model::{Histogram, Op, StageRecord};
use serde::Serialize;
use std::collections::BTreeMap;

/// Floor of log2 of the transfer size (bytes); 0 for no data.
pub fn size_class(bytes: u32) -> u32 {
    if bytes == 0 { 0 } else { 31 - bytes.leading_zeros() }
}

pub fn size_class_label(c: u32) -> String {
    if c == 0 {
        return "0".into();
    }
    let lo = 1u64 << c;
    let f = |v: u64| {
        if v >= 1 << 20 {
            format!("{}MiB", v >> 20)
        } else if v >= 1 << 10 {
            format!("{}KiB", v >> 10)
        } else {
            format!("{v}B")
        }
    };
    format!("{}-{}", f(lo), f(lo << 1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct GroupKey {
    /// Controller instance (nvmeN); `None` = all controllers.
    pub instance: Option<u32>,
    pub op: Op,
    pub variant: Variant,
    pub size_class: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Dist {
    pub samples: u64,
    pub sum_ns: u128,
    #[serde(skip)]
    pub hist: Histogram,
}

impl Dist {
    pub fn add(&mut self, ns: u64) {
        self.samples += 1;
        self.sum_ns += u128::from(ns);
        self.hist.record(ns);
    }
    pub fn mean_ns(&self) -> Option<f64> {
        (self.samples > 0).then(|| self.sum_ns as f64 / self.samples as f64)
    }
    pub fn merge(&mut self, o: &Dist) {
        self.samples += o.samples;
        self.sum_ns += o.sum_ns;
        self.hist.add(&o.hist);
    }
}

/// Why a record was left out of the stage tables.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Excluded {
    /// A boundary missing or out of order (stages merged).
    pub partial: u64,
    pub retried: u64,
    pub timed_out: u64,
    pub error_status: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Group {
    /// Complete records (in the stage table).
    pub complete: u64,
    pub excluded: Excluded,
    /// Request latency (E_START → E_BLK_DONE) of the complete records.
    pub e2e: Dist,
    pub stages: BTreeMap<Stage, Dist>,
    /// B4 split for R2T writes: time in send calls (the rest is transmit wait).
    pub b4_busy: Dist,
    /// Partial records' merged spans, keyed by (from, to).
    pub unclassified: BTreeMap<(String, String), Dist>,
}

/// One command's timeline, kept for the slowest-commands view.
#[derive(Debug, Clone, Serialize)]
pub struct Timeline {
    pub instance: u32,
    pub qid: u16,
    pub op: Op,
    pub variant: Variant,
    pub bytes: u32,
    pub e2e_ns: u64,
    pub flags: Vec<&'static str>,
    pub io_cpu: Option<u32>,
    pub cpu_submit: u16,
    pub cpu_complete: u16,
    pub spans: Vec<Span>,
}

/// Complete records of one queue, by stage family (A, B, C, D, E).
#[derive(Debug, Clone, Default, Serialize)]
pub struct QueueAgg {
    pub io_cpu: Option<u32>,
    pub complete: u64,
    pub e2e_sum_ns: u128,
    /// Summed span time per family, in the order A, B, C, D, E.
    pub family_sum_ns: [u128; 5],
}

impl QueueAgg {
    pub fn mean_ns(&self, family: usize) -> Option<f64> {
        (self.complete > 0 && family < 5).then(|| self.family_sum_ns[family] as f64 / self.complete as f64)
    }
    pub fn e2e_mean_ns(&self) -> Option<f64> {
        (self.complete > 0).then(|| self.e2e_sum_ns as f64 / self.complete as f64)
    }
}

pub const FAMILIES: [char; 5] = ['A', 'B', 'C', 'D', 'E'];

#[derive(Debug, Clone, Default, Serialize)]
pub struct Profile {
    pub records: u64,
    /// Records without E_START or E_BLK_DONE (no end-to-end interval).
    pub no_e2e: u64,
    /// Records whose spans did not add up to the request latency. Must be 0.
    pub sum_check_failures: u64,
    pub order_violations: u64,
    pub groups: BTreeMap<GroupKey, Group>,
    /// Complete, successful, single-dispatch records per (controller instance, qid).
    pub queues: BTreeMap<(u32, u16), QueueAgg>,
    /// Slowest complete or partial records (by request latency).
    pub slowest: Vec<Timeline>,
    #[serde(skip)]
    keep_slowest: usize,
}

impl Profile {
    pub fn new(keep_slowest: usize) -> Profile {
        Profile { keep_slowest, ..Default::default() }
    }

    pub fn add(&mut self, r: &StageRecord) {
        self.records += 1;
        let Some(p) = partition(r) else {
            self.no_e2e += 1;
            return;
        };
        let Some(e2e) = r.e2e_ns() else {
            self.no_e2e += 1;
            return;
        };
        if p.total_ns() != e2e {
            self.sum_check_failures += 1;
        }
        if p.order_violation {
            self.order_violations += 1;
        }
        let key =
            GroupKey { instance: Some(r.instance), op: r.op(), variant: p.variant, size_class: size_class(r.bytes) };
        self.add_to(key, r, &p, e2e);
        self.add_to(GroupKey { instance: None, ..key }, r, &p, e2e);
        if p.classified && r.status == 0 && !r.has(flag::RETRIED) && !r.has(flag::TIMED_OUT) {
            let q = self.queues.entry((r.instance, r.qid)).or_default();
            q.io_cpu = r.io_cpu;
            q.complete += 1;
            q.e2e_sum_ns += u128::from(e2e);
            for s in &p.spans {
                if let Some(i) = FAMILIES.iter().position(|&f| f == s.stage.family()) {
                    q.family_sum_ns[i] += u128::from(s.ns);
                }
            }
        }
        self.keep(r, &p, e2e);
    }

    fn add_to(&mut self, key: GroupKey, r: &StageRecord, p: &Partition, e2e: u64) {
        let g = self.groups.entry(key).or_default();
        if r.has(flag::RETRIED) {
            g.excluded.retried += 1;
            return;
        }
        if r.has(flag::TIMED_OUT) {
            g.excluded.timed_out += 1;
            return;
        }
        if r.status != 0 {
            g.excluded.error_status += 1;
            return;
        }
        if !p.classified {
            g.excluded.partial += 1;
            for s in p.spans.iter().filter(|s| s.stage == Stage::Unclassified) {
                g.unclassified.entry((s.from.to_string(), s.to.to_string())).or_default().add(s.ns);
            }
            return;
        }
        g.complete += 1;
        g.e2e.add(e2e);
        // a stage that occurs twice in one record (it cannot today) would be summed
        let mut per: BTreeMap<Stage, u64> = BTreeMap::new();
        for s in &p.spans {
            *per.entry(s.stage).or_default() += s.ns;
        }
        for (st, ns) in per {
            g.stages.entry(st).or_default().add(ns);
        }
        if matches!(p.variant, Variant::WriteR2t) {
            let b4 = p.spans.iter().find(|s| s.stage == Stage::B4).map(|s| s.ns).unwrap_or(0);
            g.b4_busy.add(r.busy_h2c_ns.min(b4));
        }
    }

    fn keep(&mut self, r: &StageRecord, p: &Partition, e2e: u64) {
        if self.keep_slowest == 0 {
            return;
        }
        if self.slowest.len() >= self.keep_slowest && self.slowest.last().is_some_and(|t| t.e2e_ns >= e2e) {
            return;
        }
        let t = Timeline {
            instance: r.instance,
            qid: r.qid,
            op: r.op(),
            variant: p.variant,
            bytes: r.bytes,
            e2e_ns: e2e,
            flags: flag::names(r.flags),
            io_cpu: r.io_cpu,
            cpu_submit: r.cpu_submit,
            cpu_complete: r.cpu_complete,
            spans: p.spans.clone(),
        };
        let i = self.slowest.partition_point(|x| x.e2e_ns >= e2e);
        self.slowest.insert(i, t);
        self.slowest.truncate(self.keep_slowest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvmetea_core::model::Boundaries;

    fn write(start: u64, c3: u64) -> StageRecord {
        StageRecord {
            instance: 4,
            opcode: 1,
            bytes: 32768,
            flags: flag::R2T,
            busy_h2c_ns: 20,
            t: Boundaries {
                start: Some(start),
                setup: Some(start + 3),
                tx_start: Some(start + 10),
                cmd_sent: Some(start + 20),
                r2t_notify: Some(start + 300),
                r2t_start: Some(start + 305),
                r2t_proc: Some(start + 310),
                h2c_start: Some(start + 320),
                h2c_sent: Some(start + 350),
                rsp_notify: Some(start + 350 + c3),
                rsp_start: Some(start + 358 + c3),
                rsp_parsed: Some(start + 360 + c3),
                nvme: Some(start + 362 + c3),
                blk: Some(start + 363 + c3),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn complete_set_means_and_shares() {
        let mut p = Profile::new(2);
        p.add(&write(0, 1000));
        p.add(&write(10_000, 3000));
        let mut partial = write(20_000, 1000);
        partial.t.r2t_notify = None;
        p.add(&partial);
        let mut retried = write(30_000, 1000);
        retried.flags |= flag::RETRIED;
        p.add(&retried);
        assert_eq!(p.sum_check_failures, 0);
        let k = GroupKey { instance: Some(4), op: Op::Write, variant: Variant::WriteR2t, size_class: 15 };
        let g = &p.groups[&k];
        assert_eq!(g.complete, 2);
        assert_eq!(g.excluded.partial, 1);
        assert_eq!(g.excluded.retried, 1);
        assert_eq!(g.stages[&Stage::C3].mean_ns(), Some(2000.0));
        // stage means add up to the end-to-end mean over the same set
        let sum: f64 = g.stages.values().filter_map(Dist::mean_ns).sum();
        assert!((sum - g.e2e.mean_ns().expect("e2e")).abs() < 1e-9);
        assert_eq!(g.unclassified.len(), 1);
        // the all-controllers group mirrors it
        assert_eq!(p.groups[&GroupKey { instance: None, ..k }].complete, 2);
        // slowest kept in order
        assert_eq!(p.slowest.len(), 2);
        assert!(p.slowest[0].e2e_ns >= p.slowest[1].e2e_ns);
        assert_eq!(p.slowest[0].e2e_ns, 3363);
    }

    #[test]
    fn size_classes() {
        assert_eq!(size_class(32768), 15);
        assert_eq!(size_class(8192), 13);
        assert_eq!(size_class(12288), 13);
        assert_eq!(size_class(0), 0);
        assert_eq!(size_class_label(15), "32KiB-64KiB");
        assert_eq!(size_class_label(13), "8KiB-16KiB");
    }
}
