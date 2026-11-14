//! Allow-listed sysfs access (`docs/architecture.md` §6.2).
//!
//! Every attribute read goes through [`read_attr`], which refuses names that are
//! not on the allow-list for the object kind. Secrets (`dhchap_*`, `tls_*`) and
//! write-only control nodes are never opened.

use nvmetea_core::model::ScanIssue;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

/// Root of a sysfs tree (`/sys` normally; a fixture directory in tests).
#[derive(Debug, Clone)]
pub struct SysRoot {
    root: PathBuf,
}

impl SysRoot {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        SysRoot { root: root.into() }
    }
    pub fn system() -> Self {
        SysRoot::new("/sys")
    }
    pub fn path(&self) -> &Path {
        &self.root
    }
    pub fn class_nvme(&self) -> PathBuf {
        self.root.join("class/nvme")
    }
    pub fn class_subsystem(&self) -> PathBuf {
        self.root.join("class/nvme-subsystem")
    }
    pub fn block(&self, dev: &str) -> PathBuf {
        self.root.join("block").join(dev)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrSet {
    Controller,
    Subsystem,
    Namespace,
}

pub const CONTROLLER_ATTRS: &[&str] = &[
    "transport",
    "address",
    "state",
    "cntlid",
    "subsysnqn",
    "queue_count",
    "sqsize",
    "kato",
    "ctrl_loss_tmo",
    "reconnect_delay",
    "fast_io_fail_tmo",
    "numa_node",
    "hostnqn",
    "hostid",
    "model",
    "serial",
    "firmware_rev",
    "cntrltype",
    "dctype",
    "dev",
];

pub const SUBSYSTEM_ATTRS: &[&str] = &["subsysnqn", "subsystype", "iopolicy", "model", "serial", "firmware_rev"];

pub const NAMESPACE_ATTRS: &[&str] = &[
    "nsid",
    "wwid",
    "uuid",
    "nguid",
    "eui",
    "csi",
    "size",
    "ana_state",
    "ana_grpid",
    "ro",
    "hidden",
    "queue/logical_block_size",
    "queue/iostats",
    "inflight",
    "dev",
];

/// Never opened, even if a caller asks (defence in depth).
pub const NEVER_READ: &[&str] = &[
    "dhchap_secret",
    "dhchap_ctrl_secret",
    "tls_key",
    "tls_configured_key",
    "tls_keyring",
    "delete_controller",
    "reset_controller",
    "rescan_controller",
];

const MAX_ATTR_BYTES: u64 = 4096;

fn allowed(set: AttrSet, name: &str) -> bool {
    if NEVER_READ.contains(&name) {
        return false;
    }
    match set {
        AttrSet::Controller => CONTROLLER_ATTRS.contains(&name),
        AttrSet::Subsystem => SUBSYSTEM_ATTRS.contains(&name),
        AttrSet::Namespace => NAMESPACE_ATTRS.contains(&name),
    }
}

/// Read one attribute. Returns `None` when the attribute does not exist (normal:
/// attributes vary by kernel and target), is empty, or could not be read; the
/// last case is recorded in `issues`.
pub fn read_attr(dir: &Path, set: AttrSet, name: &str, issues: &mut Vec<ScanIssue>) -> Option<String> {
    if !allowed(set, name) {
        issues.push(ScanIssue {
            path: dir.join(name).display().to_string(),
            problem: "refused: attribute is not on the read allow-list".into(),
        });
        return None;
    }
    let p = dir.join(name);
    let f = match File::open(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => {
            issues.push(ScanIssue { path: p.display().to_string(), problem: format!("open: {e}") });
            return None;
        }
    };
    let mut buf = Vec::with_capacity(128);
    if let Err(e) = f.take(MAX_ATTR_BYTES).read_to_end(&mut buf) {
        // e.g. ENODEV while a controller is being torn down
        issues.push(ScanIssue { path: p.display().to_string(), problem: format!("read: {e}") });
        return None;
    }
    let s = match String::from_utf8(buf) {
        Ok(s) => s,
        Err(e) => {
            issues
                .push(ScanIssue { path: p.display().to_string(), problem: "non-UTF-8 content (lossy decode)".into() });
            String::from_utf8_lossy(e.as_bytes()).into_owned()
        }
    };
    let t = s.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

/// Parse an attribute as a number; a malformed value is an issue, not a panic.
pub fn read_num<T: std::str::FromStr>(dir: &Path, set: AttrSet, name: &str, issues: &mut Vec<ScanIssue>) -> Option<T> {
    let s = read_attr(dir, set, name, issues)?;
    match s.parse::<T>() {
        Ok(v) => Some(v),
        Err(_) => {
            issues.push(ScanIssue {
                path: dir.join(name).display().to_string(),
                problem: format!("unexpected value {s:?}"),
            });
            None
        }
    }
}

/// Directory entry names, sorted; a missing directory is empty (no NVMe at all).
pub fn list_dir(dir: &Path, issues: &mut Vec<ScanIssue>) -> Vec<String> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            issues.push(ScanIssue { path: dir.display().to_string(), problem: format!("read_dir: {e}") });
            return Vec::new();
        }
    };
    let mut names: Vec<String> = rd.filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::FakeSys;

    #[test]
    fn refuses_secrets_and_unknown() {
        let f = FakeSys::new("refuse");
        f.write("class/nvme/nvme0/dhchap_secret", "DHHC-1:00:secret:");
        let dir = f.root.join("class/nvme/nvme0");
        let mut issues = vec![];
        assert_eq!(read_attr(&dir, AttrSet::Controller, "dhchap_secret", &mut issues), None);
        assert_eq!(read_attr(&dir, AttrSet::Controller, "whatever", &mut issues), None);
        assert_eq!(issues.len(), 2);
        assert!(issues[0].problem.starts_with("refused"));
    }

    #[test]
    fn trims_and_handles_missing_and_malformed() {
        let f = FakeSys::new("attrs");
        f.write("class/nvme/nvme0/state", "live\n");
        f.write("class/nvme/nvme0/cntlid", "abc\n");
        f.write("class/nvme/nvme0/hostnqn", "\n");
        let dir = f.root.join("class/nvme/nvme0");
        let mut issues = vec![];
        assert_eq!(read_attr(&dir, AttrSet::Controller, "state", &mut issues).as_deref(), Some("live"));
        assert_eq!(read_attr(&dir, AttrSet::Controller, "model", &mut issues), None);
        assert_eq!(read_attr(&dir, AttrSet::Controller, "hostnqn", &mut issues), None);
        assert!(issues.is_empty());
        assert_eq!(read_num::<u16>(&dir, AttrSet::Controller, "cntlid", &mut issues), None);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn caps_oversized_and_non_utf8() {
        let f = FakeSys::new("big");
        f.write("class/nvme/nvme0/model", &"x".repeat(10000));
        f.write_bytes("class/nvme/nvme0/serial", &[0x41, 0xff, 0x42]);
        let dir = f.root.join("class/nvme/nvme0");
        let mut issues = vec![];
        assert_eq!(read_attr(&dir, AttrSet::Controller, "model", &mut issues).map(|s| s.len()), Some(4096));
        assert_eq!(read_attr(&dir, AttrSet::Controller, "serial", &mut issues).as_deref(), Some("A\u{fffd}B"));
        assert_eq!(issues.len(), 1);
    }
}
