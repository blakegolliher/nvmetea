//! Interval views of Level 1 BPF data: per queue, per controller, per namespace.
//!
//! Cumulative BPF counters and histograms are differenced between two samples.
//! Means come from exact ns sums; percentiles from interval histograms (upper
//! bucket edge, ≤ 12.5 % overstatement). Nothing is zero-filled: no samples
//! means `no_samples`; a changed controller generation means `counter_reset`.

use crate::model::nvme::PERCENTILE_RESOLUTION;
use crate::model::{Histogram, LatMetric, NvmeSample, Op, QueueCounters, Topology};
use crate::quality::{Obs, Reason};
use serde::Serialize;
use std::collections::BTreeMap;

const SRC_CMD: &[&str] = &["bpf:P1", "bpf:P2"];
const SRC_REQ: &[&str] = &["bpf:P1", "bpf:P3"];
const SRC_STAGE: &[&str] = &["bpf:P1", "bpf:P2", "bpf:P3"];
const SRC_CNT: &[&str] = &["bpf:P1-P3"];

#[derive(Debug, Clone, Serialize)]
pub struct LatencySummary {
    pub samples: u64,
    /// Exact mean (ns sum ÷ count), µs.
    pub mean_us: Obs<f64>,
    pub p50_us: Obs<f64>,
    pub p90_us: Obs<f64>,
    pub p99_us: Obs<f64>,
    pub p999_us: Obs<f64>,
    /// Upper edge of the highest non-empty bucket, µs.
    pub max_us: Obs<f64>,
    /// Relative resolution of the percentile values (upper-edge estimator).
    pub resolution: f64,
}

impl LatencySummary {
    pub fn unavailable(r: Reason) -> LatencySummary {
        LatencySummary {
            samples: 0,
            mean_us: Obs::unavailable(r),
            p50_us: Obs::unavailable(r),
            p90_us: Obs::unavailable(r),
            p99_us: Obs::unavailable(r),
            p999_us: Obs::unavailable(r),
            max_us: Obs::unavailable(r),
            resolution: PERCENTILE_RESOLUTION,
        }
    }

    pub fn from_hist(h: &Histogram, mean_ns: Option<f64>, src: &'static [&'static str]) -> LatencySummary {
        let n = h.count();
        if n == 0 {
            return LatencySummary::unavailable(Reason::NoSamples);
        }
        let pct = |p: f64| match h.percentile(p) {
            Some(v) => Obs::derived(v.ns as f64 / 1e3, src),
            None => Obs::unavailable(Reason::NoSamples),
        };
        LatencySummary {
            samples: n,
            mean_us: match mean_ns {
                Some(m) => Obs::derived(m / 1e3, src),
                None => Obs::unavailable(Reason::MissingInterface),
            },
            p50_us: pct(0.5),
            p90_us: pct(0.9),
            p99_us: pct(0.99),
            p999_us: pct(0.999),
            max_us: match h.max_bound() {
                Some(v) => Obs::derived(v.ns as f64 / 1e3, src),
                None => Obs::unavailable(Reason::NoSamples),
            },
            resolution: PERCENTILE_RESOLUTION,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OpStats {
    pub op: Op,
    pub completed_per_s: Obs<f64>,
    pub dispatched_per_s: Obs<f64>,
    pub bytes_per_s: Obs<f64>,
    pub nvme_errors_per_s: Obs<f64>,
    /// `nvme_setup_cmd` → `nvme_complete_rq`.
    pub command: LatencySummary,
    /// `rq->start_time_ns` → `block_rq_complete` (not for admin commands).
    pub request: LatencySummary,
    /// Stage A: block submission.
    pub stage_a: LatencySummary,
    /// Stage E2: NVMe completion → block completion.
    pub stage_e2: LatencySummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueStats {
    pub controller: String,
    pub instance: u32,
    pub generation: Option<u64>,
    pub qid: u16,
    pub depth: Option<u32>,
    pub inflight: Obs<i64>,
    /// Maximum tracked in-flight commands during the interval.
    pub inflight_max: Obs<u64>,
    pub retries_per_s: Obs<f64>,
    pub requeues_per_s: Obs<f64>,
    pub failovers_per_s: Obs<f64>,
    pub error_completions_per_s: Obs<f64>,
    pub ops: Vec<OpStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControllerNvmeStats {
    pub controller: String,
    pub instance: u32,
    pub generation: Option<u64>,
    pub inflight: Obs<i64>,
    /// Largest per-queue maximum in the interval (not a sum).
    pub busiest_queue_inflight_max: Obs<u64>,
    pub busiest_queue: Option<u16>,
    pub io_queues_active: usize,
    pub ops: Vec<OpStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NamespaceLatency {
    pub namespace: String,
    pub op: Op,
    pub request: LatencySummary,
    /// Path devices that contributed.
    pub paths: usize,
}

/// Collector-health deltas for the interval.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BpfHealth {
    pub untracked_completions: u64,
    pub cid_mismatches: u64,
    pub stale_replaced: u64,
    pub map_full: u64,
    pub events_lost: u64,
    pub slow_suppressed: u64,
    pub start_missing: u64,
    pub order_violations: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NvmeIntervals {
    pub interval_s: f64,
    pub queues: Vec<QueueStats>,
    pub controllers: Vec<ControllerNvmeStats>,
    pub namespaces: Vec<NamespaceLatency>,
    pub health: BpfHealth,
}

fn ctrl_name(inst: u32) -> String {
    format!("nvme{inst}")
}

fn d(a: u64, b: u64) -> Option<u64> {
    b.checked_sub(a)
}

fn rate(prev: u64, cur: u64, dt: f64) -> Obs<f64> {
    match d(prev, cur) {
        Some(x) => Obs::derived(x as f64 / dt, SRC_CNT),
        None => Obs::unavailable(Reason::CounterReset),
    }
}

/// Sum of per-op counters and histograms for a set of queues.
#[derive(Default, Clone)]
struct Acc {
    c: QueueCounters,
    h: BTreeMap<(Op, LatMetric), Histogram>,
}

impl Acc {
    fn add(&mut self, q: &QueueCounters, hists: impl Iterator<Item = ((Op, LatMetric), Histogram)>) {
        let c = &mut self.c;
        for i in 0..5 {
            c.dispatched[i] += q.dispatched[i];
            c.bytes[i] += q.bytes[i];
            c.completed[i] += q.completed[i];
            c.nvme_errors[i] += q.nvme_errors[i];
            c.cmd_lat_sum_ns[i] += q.cmd_lat_sum_ns[i];
            c.cmd_lat_cnt[i] += q.cmd_lat_cnt[i];
            c.req_lat_sum_ns[i] += q.req_lat_sum_ns[i];
            c.req_lat_cnt[i] += q.req_lat_cnt[i];
        }
        c.retries += q.retries;
        c.requeues += q.requeues;
        c.failovers += q.failovers;
        c.error_completed += q.error_completed;
        c.inflight += q.inflight;
        for (k, h) in hists {
            self.h.entry(k).or_default().add(&h);
        }
    }
}

/// Per-controller accumulation across its queues.
#[derive(Default)]
struct CtrlAcc {
    prev: Acc,
    cur: Acc,
    maxes: Vec<(u16, Obs<u64>)>,
    active: usize,
}

fn hists_of(s: &NvmeSample, inst: u32, qid: u16) -> impl Iterator<Item = ((Op, LatMetric), Histogram)> + '_ {
    s.hists
        .range((inst, qid, Op::Read, LatMetric::Command)..=(inst, qid, Op::Admin, LatMetric::StageE2))
        .map(|((_, _, o, m), h)| ((*o, *m), h.clone()))
}

fn op_stats(prev: &Acc, cur: &Acc, dt: f64) -> Vec<OpStats> {
    let mut out = Vec::new();
    for op in Op::ALL {
        let i = op.index();
        let (p, c) = (&prev.c, &cur.c);
        if c.dispatched[i] == p.dispatched[i] && c.completed[i] == p.completed[i] {
            continue; // no activity for this op in the interval
        }
        let lat = |m: LatMetric, sum: Option<(u64, u64)>, src: &'static [&'static str]| -> LatencySummary {
            let empty = Histogram::default();
            let ch = cur.h.get(&(op, m)).unwrap_or(&empty);
            let ph = prev.h.get(&(op, m)).unwrap_or(&empty);
            match ch.since(ph) {
                None => LatencySummary::unavailable(Reason::CounterReset),
                Some(h) => {
                    let mean = sum.and_then(|(s, n)| (n > 0).then(|| s as f64 / n as f64));
                    LatencySummary::from_hist(&h, mean, src)
                }
            }
        };
        let cmd_sum = d(p.cmd_lat_sum_ns[i], c.cmd_lat_sum_ns[i]).zip(d(p.cmd_lat_cnt[i], c.cmd_lat_cnt[i]));
        let req_sum = d(p.req_lat_sum_ns[i], c.req_lat_sum_ns[i]).zip(d(p.req_lat_cnt[i], c.req_lat_cnt[i]));
        let stage_mean = |m: LatMetric| -> LatencySummary {
            // stages have no separate sums: the mean is the histogram's, so it is
            // reported as unavailable rather than approximated from buckets
            let mut s = lat(m, None, SRC_STAGE);
            if s.samples > 0 {
                s.mean_us = Obs::unavailable(Reason::NotImplemented);
            }
            s
        };
        out.push(OpStats {
            op,
            completed_per_s: rate(p.completed[i], c.completed[i], dt),
            dispatched_per_s: rate(p.dispatched[i], c.dispatched[i], dt),
            bytes_per_s: rate(p.bytes[i], c.bytes[i], dt),
            nvme_errors_per_s: rate(p.nvme_errors[i], c.nvme_errors[i], dt),
            command: lat(LatMetric::Command, cmd_sum, SRC_CMD),
            request: if op == Op::Admin {
                LatencySummary::unavailable(Reason::NotApplicable)
            } else {
                lat(LatMetric::Request, req_sum, SRC_REQ)
            },
            stage_a: if op == Op::Admin {
                LatencySummary::unavailable(Reason::NotApplicable)
            } else {
                stage_mean(LatMetric::StageA)
            },
            stage_e2: if op == Op::Admin {
                LatencySummary::unavailable(Reason::NotApplicable)
            } else {
                stage_mean(LatMetric::StageE2)
            },
        });
    }
    out
}

/// kernel dev_t (major << 20 | minor) from a sysfs `dev` attribute ("259:5").
pub fn kernel_dev_t(dev: &str) -> Option<u32> {
    let (ma, mi) = dev.trim().split_once(':')?;
    let (ma, mi): (u32, u32) = (ma.parse().ok()?, mi.parse().ok()?);
    (mi < (1 << 20) && ma < (1 << 12)).then_some((ma << 20) | mi)
}

pub fn nvme_intervals(prev: &NvmeSample, prev_topo: &Topology, cur: &NvmeSample, cur_topo: &Topology) -> NvmeIntervals {
    let dt = cur.taken.saturating_duration_since(prev.taken).as_secs_f64().max(1e-9);
    let gen_of = |t: &Topology, inst: u32| t.controller(&ctrl_name(inst)).and_then(|c| c.generation);
    let mut queues = Vec::new();
    let mut per_ctrl: BTreeMap<u32, CtrlAcc> = BTreeMap::new();
    for (&(inst, qid), cq) in &cur.queues {
        let Some(ctrl) = cur_topo.controller(&ctrl_name(inst)) else { continue };
        let same_gen = gen_of(prev_topo, inst) == ctrl.generation;
        let depth = if qid == 0 { Some(32) } else { ctrl.io_queue_depth() };
        let pq = prev.queues.get(&(inst, qid));
        let (Some(pq), true) = (pq, same_gen) else {
            let r = if same_gen { Reason::FirstInterval } else { Reason::CounterReset };
            queues.push(QueueStats {
                controller: ctrl.name.clone(),
                instance: inst,
                generation: ctrl.generation,
                qid,
                depth,
                inflight: Obs::measured(cq.inflight, SRC_CNT),
                inflight_max: Obs::unavailable(r),
                retries_per_s: Obs::unavailable(r),
                requeues_per_s: Obs::unavailable(r),
                failovers_per_s: Obs::unavailable(r),
                error_completions_per_s: Obs::unavailable(r),
                ops: Vec::new(),
            });
            continue;
        };
        let mut pa = Acc::default();
        pa.add(pq, hists_of(prev, inst, qid));
        let mut ca = Acc::default();
        ca.add(cq, hists_of(cur, inst, qid));
        // interval max: valid when BPF reset the watermark for this epoch;
        // with no dispatch in the interval the count only fell from its start.
        let imax = if cq.inflight_epoch == cur.epoch {
            Obs::measured(cq.inflight_max, SRC_CNT)
        } else {
            Obs::measured(pq.inflight.max(0) as u64, SRC_CNT)
        };
        let ops = op_stats(&pa, &ca, dt);
        let entry = per_ctrl.entry(inst).or_default();
        entry.prev.add(pq, hists_of(prev, inst, qid));
        entry.cur.add(cq, hists_of(cur, inst, qid));
        entry.maxes.push((qid, imax.clone()));
        if qid != 0 && !ops.is_empty() {
            entry.active += 1;
        }
        queues.push(QueueStats {
            controller: ctrl.name.clone(),
            instance: inst,
            generation: ctrl.generation,
            qid,
            depth,
            inflight: Obs::measured(cq.inflight, SRC_CNT),
            inflight_max: imax,
            retries_per_s: rate(pq.retries, cq.retries, dt),
            requeues_per_s: rate(pq.requeues, cq.requeues, dt),
            failovers_per_s: rate(pq.failovers, cq.failovers, dt),
            error_completions_per_s: rate(pq.error_completed, cq.error_completed, dt),
            ops,
        });
    }
    let controllers = per_ctrl
        .into_iter()
        .map(|(inst, CtrlAcc { prev: pa, cur: ca, maxes, active })| {
            let busiest = maxes.iter().filter(|(q, _)| *q != 0).max_by_key(|(_, m)| m.value.unwrap_or(0));
            ControllerNvmeStats {
                controller: ctrl_name(inst),
                instance: inst,
                generation: gen_of(cur_topo, inst),
                inflight: Obs::measured(ca.c.inflight, SRC_CNT),
                busiest_queue_inflight_max: busiest
                    .map(|(_, m)| m.clone())
                    .unwrap_or(Obs::unavailable(Reason::NoSamples)),
                busiest_queue: busiest.map(|(q, _)| *q),
                io_queues_active: active,
                ops: op_stats(&pa, &ca, dt),
            }
        })
        .collect();

    // namespace request latency = Σ over its path devices
    let mut dev_owner: BTreeMap<u32, &str> = BTreeMap::new();
    for ns in &cur_topo.namespaces {
        for p in &ns.paths {
            if let Some(dt) = p.dev.as_deref().and_then(kernel_dev_t) {
                dev_owner.insert(dt, ns.name.as_str());
            }
        }
        if let Some(dt) = ns.dev.as_deref().and_then(kernel_dev_t) {
            dev_owner.insert(dt, ns.name.as_str());
        }
    }
    let mut ns_acc: BTreeMap<(&str, Op), (Histogram, usize, bool)> = BTreeMap::new();
    for (&(dev, op), ch) in &cur.path_hists {
        let Some(ns) = dev_owner.get(&dev) else { continue };
        let ph = prev.path_hists.get(&(dev, op)).cloned().unwrap_or_default();
        let e = ns_acc.entry((ns, op)).or_insert_with(|| (Histogram::default(), 0, false));
        match ch.since(&ph) {
            Some(h) => {
                e.0.add(&h);
                e.1 += 1;
            }
            None => e.2 = true,
        }
    }
    let namespaces = ns_acc
        .into_iter()
        .filter(|(_, (h, _, reset))| h.count() > 0 || *reset)
        .map(|((ns, op), (h, n, reset))| NamespaceLatency {
            namespace: ns.to_string(),
            op,
            request: if reset {
                LatencySummary::unavailable(Reason::CounterReset)
            } else {
                LatencySummary::from_hist(&h, None, SRC_REQ)
            },
            paths: n,
        })
        .collect();
    let (pc, cc) = (&prev.counters, &cur.counters);
    let health = BpfHealth {
        untracked_completions: cc.untracked_completions.saturating_sub(pc.untracked_completions),
        cid_mismatches: cc.cid_mismatches.saturating_sub(pc.cid_mismatches),
        stale_replaced: cc.stale_replaced.saturating_sub(pc.stale_replaced),
        map_full: (cc.map_full_inflight + cc.map_full_qstats + cc.map_full_hist)
            .saturating_sub(pc.map_full_inflight + pc.map_full_qstats + pc.map_full_hist),
        events_lost: cc.events_lost.saturating_sub(pc.events_lost),
        slow_suppressed: cc.slow_suppressed.saturating_sub(pc.slow_suppressed),
        start_missing: cc.start_missing.saturating_sub(pc.start_missing),
        order_violations: cc.order_violations.saturating_sub(pc.order_violations),
    };
    NvmeIntervals { interval_s: dt, queues, controllers, namespaces, health }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Controller, CtrlState};
    use std::time::{Duration, Instant};

    fn topo(gen_: u64) -> Topology {
        let c = Controller {
            name: "nvme2".into(),
            instance: 2,
            subsystem: None,
            subsysnqn: None,
            transport: Some("tcp".into()),
            address: None,
            state: CtrlState::Live,
            cntlid: None,
            queue_count: Some(9),
            sqsize: Some(31),
            kato_s: None,
            ctrl_loss_tmo: None,
            reconnect_delay: None,
            fast_io_fail_tmo: None,
            numa_node: None,
            hostnqn: None,
            hostid: None,
            model: None,
            serial: None,
            firmware_rev: None,
            cntrltype: None,
            dctype: None,
            paths: vec![],
            namespaces: vec![],
            generation: Some(gen_),
            epoch: Some(1),
        };
        Topology { controllers: vec![c], ..Default::default() }
    }

    fn sample(t: Instant, epoch: u64, reads: u64, lat_ns: u64, inflight: i64, imax: u64, iepoch: u64) -> NvmeSample {
        let mut q = QueueCounters::default();
        let r = Op::Read.index();
        q.dispatched[r] = reads;
        q.completed[r] = reads;
        q.bytes[r] = reads * 4096;
        q.req_lat_cnt[r] = reads;
        q.req_lat_sum_ns[r] = reads * lat_ns;
        q.cmd_lat_cnt[r] = reads;
        q.cmd_lat_sum_ns[r] = reads * (lat_ns - 5000);
        q.inflight = inflight;
        q.inflight_max = imax;
        q.inflight_epoch = iepoch;
        let mut h = Histogram::default();
        let mut hc = Histogram::default();
        for _ in 0..reads {
            h.record(lat_ns);
            hc.record(lat_ns - 5000);
        }
        let mut hists = BTreeMap::new();
        hists.insert((2, 1, Op::Read, LatMetric::Request), h);
        hists.insert((2, 1, Op::Read, LatMetric::Command), hc);
        let mut queues = BTreeMap::new();
        queues.insert((2u32, 1u16), q);
        NvmeSample { taken: t, queues, hists, path_hists: BTreeMap::new(), counters: Default::default(), epoch }
    }

    #[test]
    fn interval_rates_means_percentiles() {
        let t0 = Instant::now();
        let a = sample(t0, 1, 100, 100_000, 3, 9, 1);
        let b = sample(t0 + Duration::from_secs(2), 2, 300, 100_000, 4, 12, 2);
        let v = nvme_intervals(&a, &topo(1), &b, &topo(1));
        let q = &v.queues[0];
        assert_eq!(q.depth, Some(32));
        assert_eq!(q.inflight_max.value, Some(12));
        let r = &q.ops[0];
        assert_eq!(r.op, Op::Read);
        assert_eq!(r.completed_per_s.value, Some(100.0));
        assert_eq!(r.request.samples, 200);
        assert_eq!(r.request.mean_us.value, Some(100.0)); // exact mean from sums
        let p50 = r.request.p50_us.value.expect("p50");
        assert!((100.0..=112.5).contains(&p50), "{p50}");
        assert_eq!(r.command.mean_us.value, Some(95.0));
        assert_eq!(v.controllers[0].ops[0].request.samples, 200);
        assert_eq!(v.controllers[0].busiest_queue, Some(1));
    }

    #[test]
    fn stale_watermark_epoch_uses_starting_inflight() {
        let t0 = Instant::now();
        let a = sample(t0, 1, 100, 100_000, 7, 9, 1);
        // no dispatch in the interval: entry still carries epoch 1
        let b = sample(t0 + Duration::from_secs(1), 2, 100, 100_000, 2, 9, 1);
        let v = nvme_intervals(&a, &topo(1), &b, &topo(1));
        assert_eq!(v.queues[0].inflight_max.value, Some(7));
        assert!(v.queues[0].ops.is_empty()); // idle op is omitted, not zero-filled
    }

    #[test]
    fn generation_change_resets() {
        let t0 = Instant::now();
        let a = sample(t0, 1, 100, 100_000, 3, 9, 1);
        let b = sample(t0 + Duration::from_secs(1), 2, 5, 100_000, 1, 1, 2);
        let v = nvme_intervals(&a, &topo(1), &b, &topo(2));
        assert_eq!(v.queues[0].retries_per_s.reason, Some(Reason::CounterReset));
        assert!(v.controllers.is_empty());
    }

    #[test]
    fn dev_t_encoding() {
        assert_eq!(kernel_dev_t("259:5"), Some((259 << 20) | 5));
        assert_eq!(kernel_dev_t("bogus"), None);
    }
}
