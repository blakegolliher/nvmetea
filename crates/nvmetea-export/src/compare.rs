//! `nvmetea compare BASELINE CURRENT` (`docs/architecture.md` §9.3,
//! `docs/latency-model.md` §12).
//!
//! - **Matching.** Controllers are matched by their key (subsystem NQN +
//!   fabric address), not by `nvmeN`. Every group of both captures is
//!   reported; a group present in only one is listed as such.
//! - **LAD.** For stage groups (controller | all, op, variant, size class):
//!   LAD(stage) = mean_current / mean_baseline. A stage is comparable only
//!   if both captures used the same boundary signature for stage timing and
//!   each group has at least `min_samples` complete records. Otherwise the
//!   output says `not comparable: <reason>`.
//! - **Highlight.** The largest LAD is highlighted among stages carrying at
//!   least 1 % of the request latency in either capture. Tiny stages make
//!   noisy ratios; their LAD is still reported.
//! - **Absent values** are `None`, never 0.

use crate::capture::{Capture, ControllerKey, Dist};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Options {
    pub min_samples: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options { min_samples: 100 }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureInfo {
    pub hostname: Option<String>,
    pub kernel_release: Option<String>,
    pub start_unix_s: f64,
    pub duration_s: f64,
    pub tool_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThroughputRow {
    pub controller: String,
    pub op: String,
    pub base_iops: Option<f64>,
    pub cur_iops: Option<f64>,
    pub iops_delta_pct: Option<f64>,
    pub base_mib_s: Option<f64>,
    pub cur_mib_s: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DistSummary {
    pub count: u64,
    pub mean_us: Option<f64>,
    pub p50_us: Option<f64>,
    pub p99_us: Option<f64>,
    pub p999_us: Option<f64>,
}

impl DistSummary {
    fn of(d: &Dist) -> DistSummary {
        let us = |v: Option<u64>| v.map(|x| x as f64 / 1e3);
        DistSummary {
            count: d.count,
            mean_us: d.mean_ns().map(|x| x / 1e3),
            p50_us: us(d.percentile_ns(0.5)),
            p99_us: us(d.percentile_ns(0.99)),
            p999_us: us(d.percentile_ns(0.999)),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyRow {
    pub controller: String,
    pub op: String,
    pub metric: String,
    pub base: Option<DistSummary>,
    pub cur: Option<DistSummary>,
    pub mean_delta_pct: Option<f64>,
    pub p99_delta_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StageRow {
    pub stage: String,
    pub label: String,
    pub base_mean_us: Option<f64>,
    pub cur_mean_us: Option<f64>,
    pub lad: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_comparable: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StageCompare {
    pub controller: String,
    pub op: String,
    pub variant: String,
    pub size_class: u32,
    pub base_complete: u64,
    pub cur_complete: u64,
    pub comparable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub request_base_mean_us: Option<f64>,
    pub request_cur_mean_us: Option<f64>,
    pub request_lad: Option<f64>,
    pub rows: Vec<StageRow>,
    /// Stage with the largest LAD among stages carrying ≥ 1 % of the request latency.
    pub max_lad_stage: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorRow {
    pub controller: String,
    pub base_nvme_errors: Option<u64>,
    pub cur_nvme_errors: Option<u64>,
    pub base_failovers: Option<u64>,
    pub cur_failovers: Option<u64>,
    pub base_retries: Option<u64>,
    pub cur_retries: Option<u64>,
    pub base_tcp_retrans_segments: Option<u64>,
    pub cur_tcp_retrans_segments: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub schema: &'static str,
    pub baseline: CaptureInfo,
    pub current: CaptureInfo,
    pub notes: Vec<String>,
    pub throughput: Vec<ThroughputRow>,
    pub latency: Vec<LatencyRow>,
    pub stages: Vec<StageCompare>,
    pub errors: Vec<ErrorRow>,
    pub states: Vec<String>,
}

fn info(c: &Capture) -> CaptureInfo {
    CaptureInfo {
        hostname: c.host.hostname.clone(),
        kernel_release: c.host.kernel_release.clone(),
        start_unix_s: c.start_unix_s,
        duration_s: c.duration_s,
        tool_version: c.tool.version.clone(),
    }
}

fn pct(base: Option<f64>, cur: Option<f64>) -> Option<f64> {
    match (base, cur) {
        (Some(b), Some(c)) if b > 0.0 => Some(100.0 * (c - b) / b),
        _ => None,
    }
}

/// key → display name ("nvme4 (192.0.2.3:4420)"), from both captures.
fn names(a: &Capture, b: &Capture) -> BTreeMap<ControllerKey, String> {
    let mut m = BTreeMap::new();
    for c in a.topology_end.controllers.iter().chain(&a.topology_start.controllers) {
        m.entry(c.key.clone()).or_insert_with(|| c.name.clone());
    }
    for c in b.topology_end.controllers.iter().chain(&b.topology_start.controllers) {
        let e = m.entry(c.key.clone()).or_insert_with(|| c.name.clone());
        if !e.split('/').any(|n| n == c.name) {
            *e = format!("{e}/{}", c.name);
        }
    }
    m.into_iter().map(|(k, n)| (k.clone(), format!("{n} ({})", k.label()))).collect()
}

fn key_of(c: &Capture, name: &str) -> Option<ControllerKey> {
    c.topology_end
        .controllers
        .iter()
        .chain(&c.topology_start.controllers)
        .find(|x| x.name == name)
        .map(|x| x.key.clone())
}

pub fn compare(base: &Capture, cur: &Capture, opt: &Options) -> Comparison {
    let mut notes = Vec::new();
    if base.host.hostname != cur.host.hostname {
        notes.push(format!(
            "different hosts: {} vs {}",
            base.host.hostname.as_deref().unwrap_or("?"),
            cur.host.hostname.as_deref().unwrap_or("?")
        ));
    }
    if base.host.kernel_release != cur.host.kernel_release {
        notes.push(format!(
            "different kernels: {} vs {}",
            base.host.kernel_release.as_deref().unwrap_or("?"),
            cur.host.kernel_release.as_deref().unwrap_or("?")
        ));
    }
    let sig_keys: BTreeSet<&String> = base.boundary_signature.keys().chain(cur.boundary_signature.keys()).collect();
    for k in sig_keys {
        let (a, b) = (base.boundary_signature.get(k), cur.boundary_signature.get(k));
        if a != b {
            notes.push(format!(
                "instrumentation of {k} differs: {} vs {}",
                a.map(String::as_str).unwrap_or("absent"),
                b.map(String::as_str).unwrap_or("absent")
            ));
        }
    }
    let nm = names(base, cur);
    let label = |k: &ControllerKey| nm.get(k).cloned().unwrap_or_else(|| k.label());

    // ---- throughput (Level 1 queue windows)
    let tput = |c: &Capture| -> BTreeMap<(ControllerKey, String), (u64, u64)> {
        let mut m: BTreeMap<(ControllerKey, String), (u64, u64)> = BTreeMap::new();
        for q in &c.queues {
            if q.qid == 0 {
                continue;
            }
            let Some(k) = key_of(c, &q.controller) else { continue };
            let e = m.entry((k, q.op.clone())).or_default();
            e.0 += q.completed;
            e.1 += q.bytes;
        }
        m
    };
    let (tb, tc) = (tput(base), tput(cur));
    let keys: BTreeSet<&(ControllerKey, String)> = tb.keys().chain(tc.keys()).collect();
    let mut throughput = Vec::new();
    for k in keys {
        let rate = |m: &BTreeMap<(ControllerKey, String), (u64, u64)>, d: f64| {
            m.get(k).filter(|_| d > 0.0).map(|(n, b)| (*n as f64 / d, *b as f64 / d / 1048576.0))
        };
        let (b, c) = (rate(&tb, base.duration_s), rate(&tc, cur.duration_s));
        throughput.push(ThroughputRow {
            controller: label(&k.0),
            op: k.1.clone(),
            base_iops: b.map(|x| x.0),
            cur_iops: c.map(|x| x.0),
            iops_delta_pct: pct(b.map(|x| x.0), c.map(|x| x.0)),
            base_mib_s: b.map(|x| x.1),
            cur_mib_s: c.map(|x| x.1),
        });
    }

    // ---- latency (Level 1 window histograms)
    let lat = |c: &Capture| -> BTreeMap<(ControllerKey, String, String), Dist> {
        c.latency.iter().map(|g| ((g.key.clone(), g.op.clone(), g.metric.clone()), g.dist.clone())).collect()
    };
    let (lb, lc) = (lat(base), lat(cur));
    let keys: BTreeSet<&(ControllerKey, String, String)> = lb.keys().chain(lc.keys()).collect();
    let mut latency = Vec::new();
    for k in keys {
        if !(k.2 == "request" || k.2 == "command") {
            continue;
        }
        let (b, c) = (lb.get(k).map(DistSummary::of), lc.get(k).map(DistSummary::of));
        latency.push(LatencyRow {
            controller: label(&k.0),
            op: k.1.clone(),
            metric: k.2.clone(),
            mean_delta_pct: pct(b.as_ref().and_then(|x| x.mean_us), c.as_ref().and_then(|x| x.mean_us)),
            p99_delta_pct: pct(b.as_ref().and_then(|x| x.p99_us), c.as_ref().and_then(|x| x.p99_us)),
            base: b,
            cur: c,
        });
    }

    // ---- stages and LAD
    let mut stages = Vec::new();
    let profile_sig = |c: &Capture| c.boundary_signature.get("stages").cloned();
    type SKey = (Option<ControllerKey>, String, String, u32);
    let sg = |c: &Capture| -> BTreeMap<SKey, crate::capture::StageGroup> {
        c.stages
            .as_ref()
            .map(|s| {
                s.groups
                    .iter()
                    .map(|g| ((g.key.clone(), g.op.clone(), g.variant.clone(), g.size_class), g.clone()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (sb, sc) = (sg(base), sg(cur));
    let keys: BTreeSet<&SKey> = sb.keys().chain(sc.keys()).collect();
    for k in keys {
        let (b, c) = (sb.get(k), sc.get(k));
        let ctrl = k.0.as_ref().map(&label).unwrap_or_else(|| "all".into());
        let reason = match (b, c) {
            (None, _) => Some("group absent from the baseline".to_string()),
            (_, None) => Some("group absent from the current capture".to_string()),
            _ if profile_sig(base) != profile_sig(cur) => Some("different stage instrumentation".to_string()),
            (Some(b), Some(c)) if b.complete < opt.min_samples || c.complete < opt.min_samples => {
                Some(format!("too few complete records ({} / {}, need {})", b.complete, c.complete, opt.min_samples))
            }
            _ => None,
        };
        let mean = |g: Option<&crate::capture::StageGroup>, st: &str| {
            g.and_then(|g| g.stages.iter().find(|s| s.stage == st)).and_then(|s| s.dist.mean_ns()).map(|x| x / 1e3)
        };
        let req_b = b.and_then(|g| g.request.mean_ns()).map(|x| x / 1e3);
        let req_c = c.and_then(|g| g.request.mean_ns()).map(|x| x / 1e3);
        let mut ids: Vec<(String, String)> = Vec::new();
        for g in [b, c].into_iter().flatten() {
            for s in &g.stages {
                if !ids.iter().any(|(i, _)| *i == s.stage) {
                    ids.push((s.stage.clone(), s.label.clone()));
                }
            }
        }
        let mut rows = Vec::new();
        let mut best: Option<(f64, String)> = None;
        for (id, lab) in ids {
            let (mb, mc) = (mean(b, &id), mean(c, &id));
            let (lad, nc) = if let Some(r) = &reason {
                (None, Some(r.clone()))
            } else {
                match (mb, mc) {
                    (Some(x), Some(y)) if x > 0.0 => (Some(y / x), None),
                    (Some(_), Some(_)) => (None, Some("baseline mean is 0".into())),
                    _ => (None, Some("stage unavailable in one capture".into())),
                }
            };
            let weighty =
                |m: Option<f64>, r: Option<f64>| matches!((m, r), (Some(m), Some(r)) if r > 0.0 && m / r >= 0.01);
            if let Some(l) = lad {
                if (weighty(mb, req_b) || weighty(mc, req_c)) && best.as_ref().is_none_or(|(bl, _)| l > *bl) {
                    best = Some((l, id.clone()));
                }
            }
            rows.push(StageRow { stage: id, label: lab, base_mean_us: mb, cur_mean_us: mc, lad, not_comparable: nc });
        }
        stages.push(StageCompare {
            controller: ctrl,
            op: k.1.clone(),
            variant: k.2.clone(),
            size_class: k.3,
            base_complete: b.map(|g| g.complete).unwrap_or(0),
            cur_complete: c.map(|g| g.complete).unwrap_or(0),
            comparable: reason.is_none(),
            request_lad: match (req_b, req_c, &reason) {
                (Some(x), Some(y), None) if x > 0.0 => Some(y / x),
                _ => None,
            },
            reason,
            request_base_mean_us: req_b,
            request_cur_mean_us: req_c,
            rows,
            max_lad_stage: best.map(|(_, s)| s),
        });
    }

    // ---- errors
    let cw = |c: &Capture| -> BTreeMap<ControllerKey, crate::capture::ControllerWindow> {
        c.controllers.iter().map(|w| (w.key.clone(), w.clone())).collect()
    };
    let (eb, ec) = (cw(base), cw(cur));
    let keys: BTreeSet<&ControllerKey> = eb.keys().chain(ec.keys()).collect();
    let errors = keys
        .into_iter()
        .map(|k| {
            let (b, c) = (eb.get(k), ec.get(k));
            ErrorRow {
                controller: label(k),
                base_nvme_errors: b.map(|w| w.nvme_errors),
                cur_nvme_errors: c.map(|w| w.nvme_errors),
                base_failovers: b.map(|w| w.failovers),
                cur_failovers: c.map(|w| w.failovers),
                base_retries: b.map(|w| w.retries),
                cur_retries: c.map(|w| w.retries),
                base_tcp_retrans_segments: b.and_then(|w| w.tcp_retrans_segments),
                cur_tcp_retrans_segments: c.and_then(|w| w.tcp_retrans_segments),
            }
        })
        .collect();

    // ---- controller / path states
    let mut states = Vec::new();
    let st = |c: &Capture| -> BTreeMap<ControllerKey, String> {
        c.topology_end.controllers.iter().map(|x| (x.key.clone(), x.state.clone())).collect()
    };
    let (zb, zc) = (st(base), st(cur));
    let keys: BTreeSet<&ControllerKey> = zb.keys().chain(zc.keys()).collect();
    for k in keys {
        match (zb.get(k), zc.get(k)) {
            (Some(a), Some(b)) if a != b => {
                states.push(format!("{}: {a} at the end of the baseline, {b} now", label(k)))
            }
            (Some(_), None) => states.push(format!("{}: only in the baseline", label(k))),
            (None, Some(_)) => states.push(format!("{}: only in the current capture", label(k))),
            _ => {}
        }
    }
    for (c, which) in [(base, "baseline"), (cur, "current")] {
        if !c.transitions.is_empty() {
            states.push(format!("{} transitions during the {which} capture", c.transitions.len()));
        }
    }

    Comparison {
        schema: "nvmetea.compare/1",
        baseline: info(base),
        current: info(cur),
        notes,
        throughput,
        latency,
        stages,
        errors,
        states,
    }
}

fn us(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(x) if x < 10.0 => format!("{x:.1}us"),
        Some(x) if x < 1000.0 => format!("{x:.0}us"),
        Some(x) if x < 1e6 => format!("{:.2}ms", x / 1e3),
        Some(x) => format!("{:.2}s", x / 1e6),
    }
}

fn d(v: Option<f64>) -> String {
    v.map(|x| format!("{x:+.1}%")).unwrap_or_else(|| "-".into())
}

/// Plain-text rendering. Higher latency/LAD is "worse", higher IOPS "better".
pub fn render_text(c: &Comparison) -> String {
    let mut o = String::new();
    let host = |i: &CaptureInfo| {
        format!(
            "{} ({}), {:.0} s, nvmetea {}",
            i.hostname.as_deref().unwrap_or("?"),
            i.kernel_release.as_deref().unwrap_or("?"),
            i.duration_s,
            i.tool_version
        )
    };
    o.push_str(&format!("baseline: {}\ncurrent:  {}\n", host(&c.baseline), host(&c.current)));
    for n in &c.notes {
        o.push_str(&format!("note: {n}\n"));
    }
    o.push_str("\nTHROUGHPUT\n");
    o.push_str(&format!(
        "{:<34} {:<6} {:>10} {:>10} {:>8} {:>9} {:>9}\n",
        "CONTROLLER", "OP", "IOPS base", "IOPS now", "Δ", "MiB/s b", "MiB/s n"
    ));
    for r in &c.throughput {
        let f = |v: Option<f64>, p: usize| {
            v.map(|x| if p == 0 && x < 10.0 { format!("{x:.1}") } else { format!("{x:.p$}") })
                .unwrap_or_else(|| "-".into())
        };
        let dir = match r.iops_delta_pct {
            Some(x) if x > 5.0 => " better",
            Some(x) if x < -5.0 => " worse",
            _ => "",
        };
        o.push_str(&format!(
            "{:<34} {:<6} {:>10} {:>10} {:>8} {:>9} {:>9}{dir}\n",
            r.controller,
            r.op,
            f(r.base_iops, 0),
            f(r.cur_iops, 0),
            d(r.iops_delta_pct),
            f(r.base_mib_s, 1),
            f(r.cur_mib_s, 1)
        ));
    }
    o.push_str("\nLATENCY (Level 1, all commands)\n");
    o.push_str(&format!(
        "{:<34} {:<6} {:<8} {:>9} {:>9} {:>8} {:>9} {:>9} {:>8}\n",
        "CONTROLLER", "OP", "METRIC", "mean b", "mean n", "Δ", "p99 b", "p99 n", "Δ"
    ));
    for r in &c.latency {
        let g = |s: &Option<DistSummary>, f: fn(&DistSummary) -> Option<f64>| us(s.as_ref().and_then(f));
        let dir = match r.mean_delta_pct {
            Some(x) if x > 10.0 => " worse",
            Some(x) if x < -10.0 => " better",
            _ => "",
        };
        o.push_str(&format!(
            "{:<34} {:<6} {:<8} {:>9} {:>9} {:>8} {:>9} {:>9} {:>8}{dir}\n",
            r.controller,
            r.op,
            r.metric,
            g(&r.base, |x| x.mean_us),
            g(&r.cur, |x| x.mean_us),
            d(r.mean_delta_pct),
            g(&r.base, |x| x.p99_us),
            g(&r.cur, |x| x.p99_us),
            d(r.p99_delta_pct)
        ));
    }
    if !c.stages.is_empty() {
        o.push_str("\nSTAGES (LAD = current mean / baseline mean; complete records)\n");
    }
    for s in &c.stages {
        o.push_str(&format!(
            "\n{} {} {} (size class 2^{}): {} / {} complete, request {} -> {}{}\n",
            s.controller,
            s.op,
            s.variant,
            s.size_class,
            s.base_complete,
            s.cur_complete,
            us(s.request_base_mean_us),
            us(s.request_cur_mean_us),
            s.request_lad.map(|l| format!(" (LAD {l:.2})")).unwrap_or_default()
        ));
        if let Some(r) = &s.reason {
            o.push_str(&format!("  not comparable: {r}\n"));
            continue;
        }
        for r in &s.rows {
            let mark = if s.max_lad_stage.as_deref() == Some(r.stage.as_str()) { "  <== largest LAD" } else { "" };
            o.push_str(&format!(
                "  {:<5} {:<58} {:>9} {:>9} {:>7}{mark}\n",
                r.stage,
                r.label,
                us(r.base_mean_us),
                us(r.cur_mean_us),
                r.lad.map(|l| format!("{l:.2}")).unwrap_or_else(|| r.not_comparable.clone().unwrap_or("-".into()))
            ));
        }
    }
    o.push_str("\nERRORS AND RETRANSMISSIONS (window totals, baseline -> current)\n");
    for e in &c.errors {
        let p = |a: Option<u64>, b: Option<u64>| {
            format!(
                "{} -> {}",
                a.map(|x| x.to_string()).unwrap_or("-".into()),
                b.map(|x| x.to_string()).unwrap_or("-".into())
            )
        };
        o.push_str(&format!(
            "  {:<34} NVMe errors {}  failovers {}  retries {}  TCP retrans segs {}\n",
            e.controller,
            p(e.base_nvme_errors, e.cur_nvme_errors),
            p(e.base_failovers, e.cur_failovers),
            p(e.base_retries, e.cur_retries),
            p(e.base_tcp_retrans_segments, e.cur_tcp_retrans_segments)
        ));
    }
    if !c.states.is_empty() {
        o.push_str("\nSTATES\n");
        for s in &c.states {
            o.push_str(&format!("  {s}\n"));
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::*;
    use nvmetea_core::model::Histogram;

    fn dist(v: u64, n: u64) -> Dist {
        let mut h = Histogram::default();
        for _ in 0..n {
            h.record(v);
        }
        Dist { count: n, sum_ns: Some(v * n), hist: SparseHist::from_hist(&h) }
    }

    fn cap(name: &str, c1_ns: u64, complete: u64, sig: &str) -> Capture {
        let key =
            ControllerKey { traddr: Some("192.0.2.1".into()), trsvcid: Some("4420".into()), ..Default::default() };
        let ctrl = CaptureController {
            name: name.into(),
            key: key.clone(),
            state: "live".into(),
            generation: Some(1),
            epoch: Some(1),
            io_queues: Some(8),
            queue_depth: Some(32),
        };
        let g = StageGroup {
            controller: Some(name.into()),
            key: Some(key.clone()),
            op: "read".into(),
            variant: "read".into(),
            size_class: 13,
            complete,
            partial: 0,
            excluded: 0,
            request: dist(c1_ns + 10_000, complete),
            stages: vec![
                StageDist {
                    stage: "A".into(),
                    family: "A".into(),
                    label: "block submission".into(),
                    bound: None,
                    dist: dist(2_000, complete),
                },
                StageDist {
                    stage: "C1".into(),
                    family: "C".into(),
                    label: "remote".into(),
                    bound: Some("upper bound".into()),
                    dist: dist(c1_ns, complete),
                },
                StageDist {
                    stage: "E2".into(),
                    family: "E".into(),
                    label: "completion".into(),
                    bound: None,
                    dist: dist(8_000, complete),
                },
            ],
        };
        Capture {
            schema: SCHEMA.into(),
            tool: Tool { name: "nvmetea".into(), version: "0.1.0".into() },
            host: Host { hostname: Some("h".into()), kernel_release: Some("6.12".into()), ..Default::default() },
            boundary_signature: BTreeMap::from([("stages".to_string(), sig.to_string())]),
            capabilities: vec![],
            filters: BTreeMap::new(),
            start_unix_s: 0.0,
            end_unix_s: 10.0,
            duration_s: 10.0,
            interval_s: 5.0,
            topology_start: CaptureTopology { controllers: vec![ctrl.clone()], namespaces: vec![] },
            topology_end: CaptureTopology { controllers: vec![ctrl], namespaces: vec![] },
            transitions: vec![],
            intervals: vec![],
            latency: vec![LatencyGroup {
                controller: name.into(),
                key: key.clone(),
                op: "read".into(),
                metric: "request".into(),
                dist: dist(c1_ns + 10_000, 1000),
            }],
            queues: vec![QueueWindow {
                controller: name.into(),
                qid: 1,
                op: "read".into(),
                dispatched: 1000,
                bytes: 8192 * 1000,
                completed: 1000,
                nvme_errors: 0,
            }],
            controllers: vec![ControllerWindow { controller: name.into(), key, ..Default::default() }],
            stages: Some(StageCapture {
                sample_every: 100,
                flavour: "fentry".into(),
                records: complete,
                sum_check_failures: 0,
                groups: vec![g],
            }),
            events: vec![],
            quality: Quality::default(),
            self_overhead: Overhead::default(),
        }
    }

    #[test]
    fn lad_matches_by_controller_key_and_highlights_the_weighty_stage() {
        // same controller under a different nvmeN name: matched by address
        let b = cap("nvme2", 1_000_000, 500, "fentry D1-D10");
        let c = cap("nvme5", 3_000_000, 500, "fentry D1-D10");
        let r = compare(&b, &c, &Options::default());
        assert_eq!(r.stages.len(), 1);
        let s = &r.stages[0];
        assert!(s.comparable);
        let c1 = s.rows.iter().find(|r| r.stage == "C1").expect("C1");
        assert!((c1.lad.expect("lad") - 3.0).abs() < 1e-9);
        assert_eq!(s.max_lad_stage.as_deref(), Some("C1"));
        assert!(s.controller.contains("nvme2/nvme5"), "{}", s.controller);
        assert_eq!(r.throughput.len(), 1);
        assert_eq!(r.throughput[0].iops_delta_pct, Some(0.0));
        let text = render_text(&r);
        assert!(text.contains("largest LAD"), "{text}");
    }

    #[test]
    fn not_comparable_reasons() {
        let b = cap("nvme2", 1_000_000, 50, "fentry D1-D10");
        let c = cap("nvme2", 1_000_000, 500, "fentry D1-D10");
        let r = compare(&b, &c, &Options::default());
        assert!(r.stages[0].reason.as_deref().unwrap_or("").contains("too few complete records"));
        let b = cap("nvme2", 1_000_000, 500, "kprobe D1-D10");
        let r = compare(&b, &c, &Options::default());
        assert_eq!(r.stages[0].reason.as_deref(), Some("different stage instrumentation"));
        assert!(r.notes.iter().any(|n| n.contains("instrumentation of stages differs")));
        assert!(r.stages[0].rows.iter().all(|x| x.lad.is_none()));
    }
}
