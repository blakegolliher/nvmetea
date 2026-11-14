//! Stage partition of one command (`docs/latency-model.md` §5.3, rules R1/R2).
//!
//! Each protocol variant has an ordered boundary sequence; the stage between
//! two consecutive boundaries has a fixed name. A missing boundary, or one out
//! of order, merges the stages around it into one *unclassified* span between
//! the nearest valid boundaries, so the spans of a record always add up exactly
//! to E_BLK_DONE − E_START.

use nvmetea_core::model::stage::flag;
use nvmetea_core::model::{Op, StageRecord};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Variant {
    /// READ with its data phase staged (C2H data copies seen).
    Read,
    /// READ whose data copies were not observed: the data phase is inside C1.
    ReadUnstaged,
    WriteInline,
    WriteR2t,
    /// More than one R2T: B4 contains further round trips (not separable).
    WriteMultiR2t,
    /// WRITE whose data send was not classified (data hooks missing).
    WriteUnstaged,
    /// Flush and other commands answered by one response.
    Other,
}

impl Variant {
    pub fn as_str(self) -> &'static str {
        match self {
            Variant::Read => "read",
            Variant::ReadUnstaged => "read (data phase not staged)",
            Variant::WriteInline => "write in-capsule",
            Variant::WriteR2t => "write R2T",
            Variant::WriteMultiR2t => "write multi-R2T",
            Variant::WriteUnstaged => "write (data send not staged)",
            Variant::Other => "other",
        }
    }
}

/// Stage names (latency model §5.2–5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Stage {
    A,
    B1,
    B2,
    C1,
    D1r,
    D3r,
    B3,
    B4,
    C3,
    D1,
    D2a,
    D2,
    C2,
    C4,
    D1b,
    D2b,
    D3,
    E1,
    E2,
    Unclassified,
}

impl Stage {
    pub fn id(self) -> &'static str {
        match self {
            Stage::A => "A",
            Stage::B1 => "B1",
            Stage::B2 => "B2",
            Stage::C1 => "C1",
            Stage::D1r => "D1r",
            Stage::D3r => "D3r",
            Stage::B3 => "B3",
            Stage::B4 => "B4",
            Stage::C3 => "C3",
            Stage::D1 => "D1",
            Stage::D2a => "D2a",
            Stage::D2 => "D2",
            Stage::C2 => "C2",
            Stage::C4 => "C4",
            Stage::D1b => "D1b",
            Stage::D2b => "D2b",
            Stage::D3 => "D3",
            Stage::E1 => "E1",
            Stage::E2 => "E2",
            Stage::Unclassified => "?",
        }
    }

    /// What the stage is, in the context of `v`.
    pub fn label(self, v: Variant) -> &'static str {
        match self {
            Stage::A => "block submission",
            Stage::B1 => "send queueing (worker wakeup or behind other commands)",
            Stage::B2 => {
                if v == Variant::WriteInline {
                    "command + in-capsule data transmit"
                } else {
                    "command transmit (send calls)"
                }
            }
            Stage::C1 => match v {
                Variant::WriteR2t | Variant::WriteMultiR2t => "remote/transport: command → R2T",
                Variant::Read => "remote/transport: command → first data",
                Variant::ReadUnstaged => "remote/transport: command → response (incl. data)",
                _ => "remote/transport: command → response",
            },
            Stage::D1r => "R2T receive wakeup",
            Stage::D3r => "R2T processing",
            Stage::B3 => "data transmit queueing",
            Stage::B4 => {
                if v == Variant::WriteMultiR2t {
                    "data transmit incl. further R2T round trips"
                } else {
                    "data transmit"
                }
            }
            Stage::C3 => "remote/transport: data → response",
            Stage::D1 => "receive wakeup",
            Stage::D2a => "receive: headers before first data",
            Stage::D2 => "receive: data processing (host busy)",
            Stage::C2 => "remote/transport: data streaming wait",
            Stage::C4 => "remote/transport: response after data",
            Stage::D1b => "response receive wakeup",
            Stage::D2b => "receive: response after data",
            Stage::D3 => "response processing",
            Stage::E1 => "completion handoff",
            Stage::E2 => "completion processing",
            Stage::Unclassified => "unclassified (boundary missing)",
        }
    }

    /// Family of the specification's stage breakdown: A local submission,
    /// B transmit, C remote/transport, D receive, E completion.
    pub fn family(self) -> char {
        match self {
            Stage::A => 'A',
            Stage::B1 | Stage::B2 | Stage::B3 | Stage::B4 => 'B',
            Stage::C1 | Stage::C2 | Stage::C3 | Stage::C4 => 'C',
            Stage::D1r | Stage::D3r | Stage::D1 | Stage::D2a | Stage::D2 | Stage::D1b | Stage::D2b | Stage::D3 => 'D',
            Stage::E1 | Stage::E2 => 'E',
            Stage::Unclassified => '?',
        }
    }

    /// Bound semantics of the sequence-mapped receive boundary (§5.4): C ends at
    /// the first notification covering the PDU's skb, so C is an upper bound and
    /// the wakeup after it a lower bound.
    pub fn bound(self) -> Option<&'static str> {
        match self {
            Stage::C1 | Stage::C3 | Stage::C4 => Some("upper bound"),
            Stage::D1r | Stage::D1 | Stage::D1b => Some("lower bound"),
            _ => None,
        }
    }
}

/// One span of a command's timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub stage: Stage,
    /// Boundary names delimiting the span.
    pub from: &'static str,
    pub to: &'static str,
    pub ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Partition {
    pub variant: Variant,
    pub spans: Vec<Span>,
    /// Every stage of the variant classified (no merged span).
    pub classified: bool,
    /// A boundary was present but earlier than the one before it (R1).
    pub order_violation: bool,
}

impl Partition {
    pub fn total_ns(&self) -> u64 {
        self.spans.iter().map(|s| s.ns).sum()
    }
}

pub fn variant_of(r: &StageRecord) -> Variant {
    match r.op() {
        Op::Read => {
            if r.has(flag::C2H_SEEN) && r.t.c2h_first.is_some() {
                Variant::Read
            } else {
                Variant::ReadUnstaged
            }
        }
        Op::Write => {
            if r.has(flag::MULTI_R2T) {
                Variant::WriteMultiR2t
            } else if r.has(flag::R2T) || r.t.r2t_proc.is_some() {
                Variant::WriteR2t
            } else if r.has(flag::INLINE) {
                Variant::WriteInline
            } else {
                Variant::WriteUnstaged
            }
        }
        _ => Variant::Other,
    }
}

/// Marks the data-phase span of a READ, which is split by busy time.
const DATA: Option<Stage> = None;

type Step = (&'static str, Option<u64>, Option<Stage>);

fn steps(r: &StageRecord, v: Variant) -> Vec<Step> {
    let t = &r.t;
    let mut s: Vec<Step> = vec![
        ("start", t.start, Some(Stage::A)),
        ("setup", t.setup, Some(Stage::A)),
        ("tx_start", t.tx_start, Some(Stage::B1)),
        ("cmd_sent", t.cmd_sent, Some(Stage::B2)),
    ];
    match v {
        Variant::WriteR2t | Variant::WriteMultiR2t => s.extend([
            ("r2t_notify", t.r2t_notify, Some(Stage::C1)),
            ("r2t_start", t.r2t_start, Some(Stage::D1r)),
            ("r2t_proc", t.r2t_proc, Some(Stage::D3r)),
            ("h2c_start", t.h2c_start, Some(Stage::B3)),
            ("h2c_sent", t.h2c_sent, Some(Stage::B4)),
            ("rsp_notify", t.rsp_notify, Some(Stage::C3)),
            ("rsp_start", t.rsp_start, Some(Stage::D1)),
            ("rsp_parsed", t.rsp_parsed, Some(Stage::D3)),
        ]),
        Variant::Read => {
            s.extend([
                ("rx_notify", t.rx_notify, Some(Stage::C1)),
                ("rx_start", t.rx_start, Some(Stage::D1)),
                ("c2h_first", t.c2h_first, Some(Stage::D2a)),
                ("c2h_last", t.c2h_last, DATA),
            ]);
            let after_data = matches!((t.rsp_notify, t.c2h_last), (Some(n), Some(l)) if n > l);
            if !r.has(flag::DATA_SUCCESS) && after_data {
                s.extend([
                    ("rsp_notify", t.rsp_notify, Some(Stage::C4)),
                    ("rsp_start", t.rsp_start, Some(Stage::D1b)),
                    ("rsp_parsed", t.rsp_parsed, Some(Stage::D3)),
                ]);
            } else {
                s.push(("rsp_parsed", t.rsp_parsed, Some(Stage::D2b)));
            }
        }
        _ => s.extend([
            ("rsp_notify", t.rsp_notify, Some(Stage::C1)),
            ("rsp_start", t.rsp_start, Some(Stage::D1)),
            ("rsp_parsed", t.rsp_parsed, Some(Stage::D3)),
        ]),
    }
    s.extend([("nvme", t.nvme, Some(Stage::E1)), ("blk", t.blk, Some(Stage::E2))]);
    s
}

/// Partition a record into spans. `None` when E_START or E_BLK_DONE is
/// missing (the end-to-end interval itself is unknown).
pub fn partition(r: &StageRecord) -> Option<Partition> {
    let v = variant_of(r);
    let s = steps(r, v);
    let (first, t0) = (s[0].0, s[0].1?);
    r.t.blk?;
    let mut spans = Vec::with_capacity(s.len());
    let mut last = (first, t0);
    let mut gap = false;
    let mut order_violation = false;
    for &(name, t, stage) in &s[1..] {
        let Some(t) = t else {
            gap = true;
            continue;
        };
        if t < last.1 {
            order_violation = true;
            gap = true;
            continue;
        }
        let ns = t - last.1;
        if gap {
            spans.push(Span { stage: Stage::Unclassified, from: last.0, to: name, ns });
            gap = false;
        } else if let Some(st) = stage {
            spans.push(Span { stage: st, from: last.0, to: name, ns });
        } else {
            // READ data phase: host busy (D2) and waiting for data (C2)
            let busy = r.busy_c2h_ns.min(ns);
            spans.push(Span { stage: Stage::D2, from: last.0, to: name, ns: busy });
            spans.push(Span { stage: Stage::C2, from: last.0, to: name, ns: ns - busy });
        }
        last = (name, t);
    }
    // the final boundary is E_BLK_DONE; a trailing gap cannot remain because
    // blk is present, but an out-of-order blk can
    if last.0 != "blk" {
        return None;
    }
    let classified = !spans.iter().any(|x| x.stage == Stage::Unclassified);
    Some(Partition { variant: v, spans, classified, order_violation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvmetea_core::model::Boundaries;

    fn rec(opcode: u8, flags: u32, t: Boundaries) -> StageRecord {
        StageRecord { opcode, flags, t, ..Default::default() }
    }

    fn r2t_write() -> StageRecord {
        rec(
            1,
            flag::R2T,
            Boundaries {
                start: Some(100),
                setup: Some(103),
                tx_start: Some(110),
                cmd_sent: Some(120),
                r2t_notify: Some(400),
                r2t_start: Some(405),
                r2t_proc: Some(410),
                h2c_start: Some(420),
                h2c_sent: Some(450),
                rsp_notify: Some(6000),
                rsp_start: Some(6008),
                rsp_parsed: Some(6010),
                nvme: Some(6012),
                blk: Some(6013),
                ..Default::default()
            },
        )
    }

    #[test]
    fn r2t_write_every_stage() {
        let r = r2t_write();
        let p = partition(&r).expect("partition");
        assert_eq!(p.variant, Variant::WriteR2t);
        assert!(p.classified);
        let ids: Vec<&str> = p.spans.iter().map(|s| s.stage.id()).collect();
        assert_eq!(ids, ["A", "B1", "B2", "C1", "D1r", "D3r", "B3", "B4", "C3", "D1", "D3", "E1", "E2"]);
        let c3 = p.spans.iter().find(|s| s.stage == Stage::C3).expect("C3");
        assert_eq!(c3.ns, 6000 - 450);
        assert_eq!(p.total_ns(), r.e2e_ns().expect("e2e"));
    }

    #[test]
    fn missing_boundary_merges_neighbours() {
        let mut r = r2t_write();
        r.t.r2t_notify = None; // sequence mapping unresolved
        let p = partition(&r).expect("partition");
        assert!(!p.classified);
        let u = p.spans.iter().find(|s| s.stage == Stage::Unclassified).expect("merged");
        assert_eq!((u.from, u.to, u.ns), ("cmd_sent", "r2t_start", 405 - 120));
        assert!(!p.spans.iter().any(|s| s.stage == Stage::C1 || s.stage == Stage::D1r));
        assert_eq!(p.total_ns(), 6013 - 100);
    }

    #[test]
    fn order_violation_merges_and_is_flagged() {
        let mut r = r2t_write();
        r.t.r2t_start = Some(300); // before r2t_notify
        let p = partition(&r).expect("partition");
        assert!(p.order_violation);
        assert!(!p.classified);
        assert_eq!(p.total_ns(), 6013 - 100);
    }

    #[test]
    fn read_data_phase_split_by_busy_time() {
        let mut r = rec(
            2,
            flag::C2H_SEEN | flag::DATA_SUCCESS,
            Boundaries {
                start: Some(0),
                setup: Some(2),
                tx_start: Some(2),
                cmd_sent: Some(10),
                rx_notify: Some(500),
                rx_start: Some(510),
                c2h_first: Some(515),
                c2h_last: Some(615),
                rsp_parsed: Some(615),
                nvme: Some(616),
                blk: Some(617),
                ..Default::default()
            },
        );
        r.busy_c2h_ns = 30;
        let p = partition(&r).expect("partition");
        assert_eq!(p.variant, Variant::Read);
        let get = |s: Stage| p.spans.iter().find(|x| x.stage == s).map(|x| x.ns);
        assert_eq!(get(Stage::D2), Some(30));
        assert_eq!(get(Stage::C2), Some(70));
        assert_eq!(get(Stage::D2b), Some(0));
        assert_eq!(p.total_ns(), 617);
        // busy beyond the span is clamped, the sum still holds
        r.busy_c2h_ns = 10_000;
        let p = partition(&r).expect("partition");
        assert_eq!(p.spans.iter().find(|x| x.stage == Stage::C2).map(|x| x.ns), Some(0));
        assert_eq!(p.total_ns(), 617);
    }

    #[test]
    fn read_with_separate_response_capsule() {
        let r = rec(
            2,
            flag::C2H_SEEN,
            Boundaries {
                start: Some(0),
                setup: Some(1),
                tx_start: Some(1),
                cmd_sent: Some(5),
                rx_notify: Some(100),
                rx_start: Some(101),
                c2h_first: Some(102),
                c2h_last: Some(150),
                rsp_notify: Some(300),
                rsp_start: Some(305),
                rsp_parsed: Some(306),
                nvme: Some(307),
                blk: Some(308),
                ..Default::default()
            },
        );
        let p = partition(&r).expect("partition");
        let ids: Vec<&str> = p.spans.iter().map(|s| s.stage.id()).collect();
        assert_eq!(ids, ["A", "B1", "B2", "C1", "D1", "D2a", "D2", "C2", "C4", "D1b", "D3", "E1", "E2"]);
        assert_eq!(p.total_ns(), 308);
    }

    #[test]
    fn inline_write_and_unstaged_read() {
        let w = rec(
            1,
            flag::INLINE | flag::DIRECT,
            Boundaries {
                start: Some(0),
                setup: Some(1),
                tx_start: Some(1),
                cmd_sent: Some(4),
                rsp_notify: Some(80),
                rsp_start: Some(81),
                rsp_parsed: Some(82),
                nvme: Some(83),
                blk: Some(84),
                ..Default::default()
            },
        );
        let p = partition(&w).expect("partition");
        assert_eq!(p.variant, Variant::WriteInline);
        assert!(p.classified);
        let mut r = w.clone();
        r.opcode = 2;
        r.flags = 0;
        let p = partition(&r).expect("partition");
        assert_eq!(p.variant, Variant::ReadUnstaged);
        assert!(p.classified);
    }

    #[test]
    fn no_end_to_end_without_start_or_end() {
        let mut r = r2t_write();
        r.t.start = None;
        assert!(partition(&r).is_none());
        let mut r = r2t_write();
        r.t.blk = None;
        assert!(partition(&r).is_none());
        let mut r = r2t_write();
        r.t.blk = Some(50); // before start
        assert!(partition(&r).is_none());
    }

    /// Property: for any subset of missing boundaries and any ordering, the
    /// spans of a partition add up exactly to E_BLK_DONE − E_START.
    #[test]
    fn sum_check_holds_for_every_missing_pattern() {
        let base = r2t_write();
        let fields: [fn(&mut Boundaries) -> &mut Option<u64>; 12] = [
            |b| &mut b.setup,
            |b| &mut b.tx_start,
            |b| &mut b.cmd_sent,
            |b| &mut b.r2t_notify,
            |b| &mut b.r2t_start,
            |b| &mut b.r2t_proc,
            |b| &mut b.h2c_start,
            |b| &mut b.h2c_sent,
            |b| &mut b.rsp_notify,
            |b| &mut b.rsp_start,
            |b| &mut b.rsp_parsed,
            |b| &mut b.nvme,
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for mask in 0u32..(1 << fields.len()) {
            let mut r = base.clone();
            for (i, f) in fields.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    *f(&mut r.t) = None;
                }
            }
            // also scramble one present boundary pseudo-randomly
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let j = (seed % fields.len() as u64) as usize;
            if let Some(v) = f_get(fields[j], &mut r.t) {
                *fields[j](&mut r.t) = Some(v.wrapping_add(seed % 8000).min(6013));
            }
            let p = partition(&r).expect("partition");
            assert_eq!(p.total_ns(), 6013 - 100, "mask {mask:#x}");
        }
    }

    fn f_get(f: fn(&mut Boundaries) -> &mut Option<u64>, b: &mut Boundaries) -> Option<u64> {
        *f(b)
    }
}
