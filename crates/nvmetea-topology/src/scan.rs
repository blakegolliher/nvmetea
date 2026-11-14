//! One-shot scan of the NVMe sysfs hierarchy into a [`Topology`].
//!
//! Relationships come from directory structure (subsystem → controller links,
//! controller → path entries), not from parsing names alone. Names are only used
//! to pair a path with its multipath head, and that pairing is cross-checked
//! against NSID and WWID.

use crate::address::parse_address;
use crate::names;
use crate::sysfs::{AttrSet, SysRoot, list_dir, read_attr, read_num};
use nvmetea_core::model::{Controller, CtrlState, Namespace, NsKind, NsPath, ScanIssue, Subsystem, Topology};
use std::collections::BTreeMap;
use std::path::Path;

pub fn scan(root: &SysRoot) -> Topology {
    let mut issues = Vec::new();
    let mut subsystems = Vec::new();
    let mut ctrl_subsys: BTreeMap<String, String> = BTreeMap::new();

    // Subsystems and their member links.
    let sdir = root.class_subsystem();
    let mut snames: Vec<String> =
        list_dir(&sdir, &mut issues).into_iter().filter(|n| names::subsys(n).is_some()).collect();
    snames.sort_by_key(|n| names::natural_key(n));
    for name in snames {
        let dir = sdir.join(&name);
        let mut controllers = Vec::new();
        let mut heads = Vec::new();
        for e in list_dir(&dir, &mut issues) {
            if names::ctrl(&e).is_some() {
                controllers.push(e);
            } else if names::namespace(&e).is_some() {
                heads.push(e);
            }
        }
        controllers.sort_by_key(|n| names::natural_key(n));
        heads.sort_by_key(|n| names::natural_key(n));
        for c in &controllers {
            ctrl_subsys.insert(c.clone(), name.clone());
        }
        subsystems.push(Subsystem {
            instance: names::subsys(&name).unwrap_or(0),
            nqn: read_attr(&dir, AttrSet::Subsystem, "subsysnqn", &mut issues),
            subsystype: read_attr(&dir, AttrSet::Subsystem, "subsystype", &mut issues),
            iopolicy: read_attr(&dir, AttrSet::Subsystem, "iopolicy", &mut issues),
            model: read_attr(&dir, AttrSet::Subsystem, "model", &mut issues),
            serial: read_attr(&dir, AttrSet::Subsystem, "serial", &mut issues),
            firmware_rev: read_attr(&dir, AttrSet::Subsystem, "firmware_rev", &mut issues),
            controllers,
            namespaces: heads,
            name,
        });
    }

    // Controllers.
    let cdir = root.class_nvme();
    let mut cnames: Vec<String> =
        list_dir(&cdir, &mut issues).into_iter().filter(|n| names::ctrl(n).is_some()).collect();
    cnames.sort_by_key(|n| names::natural_key(n));
    let mut controllers = Vec::new();
    for name in cnames {
        controllers.push(scan_controller(&cdir.join(&name), &name, ctrl_subsys.get(&name).cloned(), &mut issues));
    }

    // Namespaces: multipath heads from subsystems, direct namespaces from controllers.
    let mut namespaces = Vec::new();
    let mut head_index: BTreeMap<String, usize> = BTreeMap::new();
    for s in &subsystems {
        for h in &s.namespaces {
            let ns = scan_namespace(root, h, NsKind::MultipathHead, Some(s.name.clone()), None, &mut issues);
            head_index.insert(h.clone(), namespaces.len());
            namespaces.push(ns);
        }
    }
    for c in &controllers {
        for d in &c.namespaces {
            let ns = scan_namespace(root, d, NsKind::Direct, c.subsystem.clone(), Some(c.name.clone()), &mut issues);
            namespaces.push(ns);
        }
    }

    // Paths → heads.
    for c in &controllers {
        for p in &c.paths {
            let Some((s_inst, c_inst, n_idx)) = names::path(p) else { continue };
            if Some(c_inst) != names::ctrl(&c.name) {
                issues.push(ScanIssue {
                    path: root.block(p).display().to_string(),
                    problem: format!("path {p} listed under {} but names controller instance {c_inst}", c.name),
                });
            }
            let dir = root.block(p);
            let path = NsPath {
                name: p.clone(),
                controller: c.name.clone(),
                dev: read_attr(&dir, AttrSet::Namespace, "dev", &mut issues),
                nsid: read_num(&dir, AttrSet::Namespace, "nsid", &mut issues),
                wwid: read_attr(&dir, AttrSet::Namespace, "wwid", &mut issues),
                ana_state: read_attr(&dir, AttrSet::Namespace, "ana_state", &mut issues),
                ana_grpid: read_num(&dir, AttrSet::Namespace, "ana_grpid", &mut issues),
            };
            let head = format!("nvme{s_inst}n{n_idx}");
            match head_index.get(&head) {
                Some(&i) => {
                    let ns = &mut namespaces[i];
                    if (ns.nsid.is_some() && path.nsid.is_some() && ns.nsid != path.nsid)
                        || (ns.wwid.is_some() && path.wwid.is_some() && ns.wwid != path.wwid)
                    {
                        issues.push(ScanIssue {
                            path: dir.display().to_string(),
                            problem: format!("path {p} does not match head {head} (nsid/wwid differ); not linked"),
                        });
                    } else {
                        ns.paths.push(path);
                    }
                }
                None => issues.push(ScanIssue {
                    path: dir.display().to_string(),
                    problem: format!("path {p} has no multipath head {head}"),
                }),
            }
        }
    }
    for ns in &mut namespaces {
        ns.paths.sort_by_key(|p| names::natural_key(&p.name));
    }

    Topology { subsystems, controllers, namespaces, issues }
}

fn scan_controller(dir: &Path, name: &str, subsystem: Option<String>, issues: &mut Vec<ScanIssue>) -> Controller {
    let a = |n: &str, issues: &mut Vec<ScanIssue>| read_attr(dir, AttrSet::Controller, n, issues);
    let mut paths = Vec::new();
    let mut direct = Vec::new();
    for e in list_dir(dir, issues) {
        if names::path(&e).is_some() {
            paths.push(e);
        } else if names::namespace(&e).is_some() {
            direct.push(e);
        }
    }
    paths.sort_by_key(|n| names::natural_key(n));
    direct.sort_by_key(|n| names::natural_key(n));
    let state = match a("state", issues) {
        Some(s) => CtrlState::parse(&s),
        None => CtrlState::Unreadable,
    };
    Controller {
        name: name.to_string(),
        instance: names::ctrl(name).unwrap_or(0),
        subsystem,
        subsysnqn: a("subsysnqn", issues),
        transport: a("transport", issues),
        address: a("address", issues).map(|s| parse_address(&s)),
        state,
        cntlid: read_num(dir, AttrSet::Controller, "cntlid", issues),
        queue_count: read_num(dir, AttrSet::Controller, "queue_count", issues),
        sqsize: read_num(dir, AttrSet::Controller, "sqsize", issues),
        kato_s: read_num(dir, AttrSet::Controller, "kato", issues),
        ctrl_loss_tmo: a("ctrl_loss_tmo", issues),
        reconnect_delay: a("reconnect_delay", issues),
        fast_io_fail_tmo: a("fast_io_fail_tmo", issues),
        numa_node: read_num(dir, AttrSet::Controller, "numa_node", issues),
        hostnqn: a("hostnqn", issues),
        hostid: a("hostid", issues),
        model: a("model", issues),
        serial: a("serial", issues),
        firmware_rev: a("firmware_rev", issues),
        cntrltype: a("cntrltype", issues),
        dctype: a("dctype", issues),
        paths,
        namespaces: direct,
        generation: None,
        epoch: None,
    }
}

fn scan_namespace(
    root: &SysRoot,
    name: &str,
    kind: NsKind,
    subsystem: Option<String>,
    controller: Option<String>,
    issues: &mut Vec<ScanIssue>,
) -> Namespace {
    let dir = root.block(name);
    let a = |n: &str, issues: &mut Vec<ScanIssue>| read_attr(&dir, AttrSet::Namespace, n, issues);
    let size_sectors: Option<u64> = read_num(&dir, AttrSet::Namespace, "size", issues);
    Namespace {
        name: name.to_string(),
        kind,
        subsystem,
        controller,
        dev: a("dev", issues),
        nsid: read_num(&dir, AttrSet::Namespace, "nsid", issues),
        wwid: a("wwid", issues),
        uuid: a("uuid", issues),
        nguid: a("nguid", issues),
        eui: a("eui", issues),
        size_bytes: size_sectors.and_then(|s| s.checked_mul(512)),
        logical_block_size: read_num(&dir, AttrSet::Namespace, "queue/logical_block_size", issues),
        iostats: a("queue/iostats", issues).map(|v| v == "1"),
        paths: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{FakeSys, tcp_multipath_host};

    #[test]
    fn empty_system_is_fine() {
        let f = FakeSys::new("empty");
        let t = scan(&SysRoot::new(f.as_path()));
        assert!(t.controllers.is_empty() && t.subsystems.is_empty() && t.namespaces.is_empty());
        assert!(t.issues.is_empty());
    }

    #[test]
    fn multipath_tcp_layout() {
        let f = tcp_multipath_host("mp", 6, 10);
        let t = scan(&SysRoot::new(f.as_path()));
        assert!(t.issues.is_empty(), "{:?}", t.issues);
        assert_eq!(t.subsystems.len(), 2);
        assert_eq!(t.controllers.len(), 7);
        assert_eq!(t.tcp_controllers().count(), 6);
        let s2 = t.subsystem("nvme-subsys2").expect("subsys2");
        assert_eq!(s2.controllers, ["nvme2", "nvme3", "nvme4", "nvme5", "nvme6", "nvme7"]);
        assert_eq!(s2.namespaces.len(), 10);
        let c = t.controller("nvme3").expect("nvme3");
        assert_eq!(c.subsystem.as_deref(), Some("nvme-subsys2"));
        assert_eq!(c.io_queues(), Some(8));
        assert_eq!(c.io_queue_depth(), Some(32));
        assert_eq!(c.address.as_ref().and_then(|a| a.traddr.as_deref()), Some("192.0.2.2"));
        assert_eq!(c.paths.len(), 10);
        assert_eq!(c.paths[1], "nvme2c3n2");
        let ns = t.namespace("nvme2n10").expect("head");
        assert_eq!(ns.kind, NsKind::MultipathHead);
        assert_eq!(ns.paths.len(), 6);
        assert!(ns.paths.iter().all(|p| p.nsid == Some(10)));
        assert_eq!(ns.size_bytes, Some(1953125000 * 512));
        assert!(ns.paths.iter().all(|p| p.ana_state.is_none()));
        let pcie = t.namespace("nvme0n1").expect("direct");
        assert_eq!(pcie.kind, NsKind::Direct);
        assert_eq!(pcie.controller.as_deref(), Some("nvme0"));
        assert_eq!(t.controller_block_devices("nvme0"), ["nvme0n1"]);
    }

    #[test]
    fn ana_states_and_mismatch_detection() {
        let f = tcp_multipath_host("ana", 2, 1);
        f.write("block/nvme2c2n1/ana_state", "optimized\n");
        f.write("block/nvme2c2n1/ana_grpid", "1\n");
        f.write("block/nvme2c3n1/ana_state", "inaccessible\n");
        f.write("block/nvme2c3n1/wwid", "eui.ffff\n"); // inconsistent with head
        let t = scan(&SysRoot::new(f.as_path()));
        let ns = t.namespace("nvme2n1").expect("head");
        assert_eq!(ns.paths.len(), 1);
        assert_eq!(ns.paths[0].ana_state.as_deref(), Some("optimized"));
        assert_eq!(ns.paths[0].ana_grpid, Some(1));
        assert_eq!(t.issues.len(), 1);
        assert!(t.issues[0].problem.contains("does not match head"));
    }

    #[test]
    fn states_missing_attrs_and_junk_entries() {
        let f = tcp_multipath_host("states", 3, 1);
        f.write("class/nvme/nvme2/state", "resetting\n");
        f.write("class/nvme/nvme3/state", "deleting (no IO)\n");
        f.remove("class/nvme/nvme4/state");
        f.remove("class/nvme/nvme4/queue_count");
        f.write("class/nvme/nvme4/sqsize", "lots\n");
        f.mkdir("class/nvme/nvme4/power");
        f.mkdir("class/nvme/nvme4/hwmon7");
        f.mkdir("class/nvme/nvme-fabrics"); // not a controller
        f.write("class/nvme/nvme2/address", "traddr=2001:db8::5,trsvcid=4421,host_traddr=2001:db8::9\n");
        let t = scan(&SysRoot::new(f.as_path()));
        assert_eq!(t.controller("nvme2").map(|c| c.state.clone()), Some(CtrlState::Resetting));
        assert_eq!(t.controller("nvme3").map(|c| c.state.clone()), Some(CtrlState::DeletingNoIo));
        let c4 = t.controller("nvme4").expect("nvme4");
        assert_eq!(c4.state, CtrlState::Unreadable);
        assert_eq!(c4.queue_count, None);
        assert_eq!(c4.sqsize, None);
        assert_eq!(t.controllers.len(), 4);
        assert_eq!(t.issues.len(), 1, "{:?}", t.issues); // the malformed sqsize
        let a2 = t.controller("nvme2").and_then(|c| c.address.clone()).expect("addr");
        assert_eq!(a2.trsvcid.as_deref(), Some("4421"));
        assert_eq!(a2.host_traddr.as_deref(), Some("2001:db8::9"));
    }

    #[test]
    fn orphan_path_and_removed_controller() {
        let f = tcp_multipath_host("orphan", 2, 2);
        f.remove("block/nvme2n2");
        f.remove("class/nvme-subsystem/nvme-subsys2/nvme2n2");
        f.remove("class/nvme/nvme3");
        let t = scan(&SysRoot::new(f.as_path()));
        assert_eq!(t.tcp_controllers().count(), 1);
        // the subsystem still links nvme3 (dangling symlink) - listed, not scanned
        assert_eq!(t.issues.iter().filter(|i| i.problem.contains("no multipath head")).count(), 1);
    }

    #[test]
    fn never_touches_secret_fifo() {
        // A FIFO blocks open(O_RDONLY) until a writer appears: if the scanner ever
        // opened it, this test would hang.
        let f = tcp_multipath_host("fifo", 1, 1);
        for n in ["dhchap_secret", "dhchap_ctrl_secret", "tls_key"] {
            let p = f.path_of(&format!("class/nvme/nvme2/{n}"));
            let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).expect("cstring");
            // SAFETY: valid NUL-terminated path.
            let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
            assert_eq!(rc, 0);
        }
        let t = scan(&SysRoot::new(f.as_path()));
        assert_eq!(t.tcp_controllers().count(), 1);
    }
}
