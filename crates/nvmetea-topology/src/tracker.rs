//! Controller lifecycle tracking across scans.
//!
//! * **generation**: a new number whenever a controller object appears (first
//!   seen, re-created under the same or a different `nvmeN`, or its logical
//!   connection identity changed). Counters never carry across generations.
//! * **epoch**: increments each time a generation enters `live` (reconnect /
//!   reset replaces every queue socket).
//!
//! With polling alone, a delete + re-create that completes between two scans
//! under the same name and identity is indistinguishable from no change; uevents
//! (and in Phase 2 BPF lifecycle hooks) close that gap. Each transition records
//! its source so the operator can tell.

use nvmetea_core::model::{ControllerKey, CtrlState, Topology};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionSource {
    /// Found by comparing consecutive sysfs scans.
    Poll,
    /// Scan triggered by a kernel uevent.
    Uevent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    Added { state: CtrlState },
    State { from: CtrlState, to: CtrlState },
    Removed { last_state: CtrlState },
}

#[derive(Debug, Clone, Serialize)]
pub struct Transition {
    #[serde(with = "unix_time")]
    pub at: SystemTime,
    pub controller: String,
    pub generation: u64,
    pub change: Change,
    pub source: TransitionSource,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tracked {
    pub key: ControllerKey,
    pub generation: u64,
    pub epoch: u64,
    pub state: CtrlState,
    #[serde(with = "unix_time")]
    pub since: SystemTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct Removed {
    pub name: String,
    pub tracked: Tracked,
    #[serde(with = "unix_time")]
    pub removed_at: SystemTime,
}

pub struct Tracker {
    next_generation: u64,
    current: BTreeMap<String, Tracked>,
    transitions: VecDeque<Transition>,
    history: VecDeque<Removed>,
    max_transitions: usize,
    max_history: usize,
}

impl Default for Tracker {
    fn default() -> Self {
        Tracker::new(4096, 64)
    }
}

impl Tracker {
    pub fn new(max_transitions: usize, max_history: usize) -> Self {
        Tracker {
            next_generation: 1,
            current: BTreeMap::new(),
            transitions: VecDeque::new(),
            history: VecDeque::new(),
            max_transitions,
            max_history,
        }
    }

    /// Compare a fresh scan with the previous one, annotate `topo` with
    /// generations/epochs, and return the transitions found.
    pub fn observe(&mut self, topo: &mut Topology, now: SystemTime, source: TransitionSource) -> Vec<Transition> {
        let mut out = Vec::new();
        let mut seen = BTreeMap::new();
        for c in &mut topo.controllers {
            let key = c.key();
            let entry = self.current.remove(&c.name);
            let tracked = match entry {
                Some(mut t) if t.key == key => {
                    if t.state != c.state {
                        if c.state.is_live() {
                            t.epoch += 1;
                        }
                        out.push(Transition {
                            at: now,
                            controller: c.name.clone(),
                            generation: t.generation,
                            change: Change::State { from: t.state.clone(), to: c.state.clone() },
                            source,
                        });
                        t.state = c.state.clone();
                        t.since = now;
                    }
                    t
                }
                other => {
                    if let Some(old) = other {
                        // same name, different connection: the old one is gone
                        out.push(Transition {
                            at: now,
                            controller: c.name.clone(),
                            generation: old.generation,
                            change: Change::Removed { last_state: old.state.clone() },
                            source,
                        });
                        self.push_history(c.name.clone(), old, now);
                    }
                    let g = self.next_generation;
                    self.next_generation += 1;
                    out.push(Transition {
                        at: now,
                        controller: c.name.clone(),
                        generation: g,
                        change: Change::Added { state: c.state.clone() },
                        source,
                    });
                    Tracked {
                        key,
                        generation: g,
                        epoch: u64::from(c.state.is_live()),
                        state: c.state.clone(),
                        since: now,
                    }
                }
            };
            c.generation = Some(tracked.generation);
            c.epoch = Some(tracked.epoch);
            seen.insert(c.name.clone(), tracked);
        }
        let gone: Vec<(String, Tracked)> = std::mem::take(&mut self.current).into_iter().collect();
        for (name, t) in gone {
            out.push(Transition {
                at: now,
                controller: name.clone(),
                generation: t.generation,
                change: Change::Removed { last_state: t.state.clone() },
                source,
            });
            self.push_history(name, t, now);
        }
        self.current = seen;
        for t in &out {
            if self.transitions.len() == self.max_transitions {
                self.transitions.pop_front();
            }
            self.transitions.push_back(t.clone());
        }
        out
    }

    fn push_history(&mut self, name: String, tracked: Tracked, now: SystemTime) {
        if self.history.len() == self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(Removed { name, tracked, removed_at: now });
    }

    pub fn transitions(&self) -> impl Iterator<Item = &Transition> {
        self.transitions.iter()
    }
    pub fn history(&self) -> impl Iterator<Item = &Removed> {
        self.history.iter()
    }
    pub fn tracked(&self, name: &str) -> Option<&Tracked> {
        self.current.get(name)
    }
}

mod unix_time {
    use serde::Serializer;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        s.serialize_f64(secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::tcp_multipath_host;
    use crate::scan::scan;
    use crate::sysfs::SysRoot;
    use std::time::Duration;

    fn t(n: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(n)
    }

    #[test]
    fn first_scan_adds_everything() {
        let f = tcp_multipath_host("trk1", 2, 1);
        let mut tr = Tracker::default();
        let mut topo = scan(&SysRoot::new(f.as_path()));
        let ch = tr.observe(&mut topo, t(1), TransitionSource::Poll);
        assert_eq!(ch.len(), 3);
        assert!(ch.iter().all(|c| matches!(c.change, Change::Added { .. })));
        let c = topo.controller("nvme2").expect("nvme2");
        assert_eq!(c.epoch, Some(1));
        let g2 = c.generation;
        // unchanged rescan: nothing new, same generation
        let mut topo = scan(&SysRoot::new(f.as_path()));
        assert!(tr.observe(&mut topo, t(2), TransitionSource::Poll).is_empty());
        assert_eq!(topo.controller("nvme2").and_then(|c| c.generation), g2);
    }

    #[test]
    fn reset_reconnect_bumps_epoch_not_generation() {
        let f = tcp_multipath_host("trk2", 1, 1);
        let root = SysRoot::new(f.as_path());
        let mut tr = Tracker::default();
        let mut topo = scan(&root);
        tr.observe(&mut topo, t(1), TransitionSource::Poll);
        let g = topo.controller("nvme2").and_then(|c| c.generation);
        for (i, st) in ["resetting", "connecting", "live"].iter().enumerate() {
            f.write("class/nvme/nvme2/state", st);
            let mut topo = scan(&root);
            let ch = tr.observe(&mut topo, t(2 + i as u64), TransitionSource::Uevent);
            assert_eq!(ch.len(), 1);
            assert_eq!(ch[0].source, TransitionSource::Uevent);
        }
        let mut topo = scan(&root);
        tr.observe(&mut topo, t(9), TransitionSource::Poll);
        let c = topo.controller("nvme2").expect("nvme2");
        assert_eq!(c.generation, g);
        assert_eq!(c.epoch, Some(2));
    }

    #[test]
    fn removal_then_recreation_same_name_is_new_generation() {
        let f = tcp_multipath_host("trk3", 2, 1);
        let root = SysRoot::new(f.as_path());
        let mut tr = Tracker::default();
        let mut topo = scan(&root);
        tr.observe(&mut topo, t(1), TransitionSource::Poll);
        let g_old = topo.controller("nvme3").and_then(|c| c.generation).expect("gen");
        let saved_addr = "traddr=192.0.2.2,trsvcid=4420,src_addr=198.51.100.5";
        f.remove("class/nvme/nvme3");
        let mut topo = scan(&root);
        let ch = tr.observe(&mut topo, t(2), TransitionSource::Poll);
        assert!(matches!(ch.as_slice(), [Transition { change: Change::Removed { .. }, .. }]));
        assert_eq!(tr.history().count(), 1);
        f.controller(
            "nvme3",
            Some("nvme-subsys2"),
            &[
                ("transport", "tcp"),
                ("address", saved_addr),
                ("state", "connecting"),
                ("subsysnqn", "nqn.2024-08.com.example:subsys-a"),
            ],
        );
        let mut topo = scan(&root);
        tr.observe(&mut topo, t(3), TransitionSource::Poll);
        let g_new = topo.controller("nvme3").and_then(|c| c.generation).expect("gen");
        assert!(g_new > g_old);
        assert_eq!(topo.controller("nvme3").and_then(|c| c.epoch), Some(0));
    }

    #[test]
    fn same_name_different_endpoint_is_replacement() {
        let f = tcp_multipath_host("trk4", 1, 1);
        let root = SysRoot::new(f.as_path());
        let mut tr = Tracker::default();
        let mut topo = scan(&root);
        tr.observe(&mut topo, t(1), TransitionSource::Poll);
        f.write("class/nvme/nvme2/address", "traddr=192.0.2.99,trsvcid=4420");
        let mut topo = scan(&root);
        let ch = tr.observe(&mut topo, t(2), TransitionSource::Poll);
        assert_eq!(ch.len(), 2);
        assert!(matches!(ch[0].change, Change::Removed { .. }));
        assert!(matches!(ch[1].change, Change::Added { .. }));
    }

    #[test]
    fn bounded_logs() {
        let f = tcp_multipath_host("trk5", 1, 1);
        let root = SysRoot::new(f.as_path());
        let mut tr = Tracker::new(3, 1);
        for i in 0..10 {
            f.write("class/nvme/nvme2/state", if i % 2 == 0 { "resetting" } else { "live" });
            let mut topo = scan(&root);
            tr.observe(&mut topo, t(i), TransitionSource::Poll);
        }
        assert_eq!(tr.transitions().count(), 3);
    }
}
