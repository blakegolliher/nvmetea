//! NVMe subsystem / controller / namespace / path inventory.
//!
//! `nvmeN` names are display names only. Identity is [`ControllerKey`] plus the
//! generation and connection epoch assigned by the topology tracker
//! (`docs/architecture.md` §4.2).

use serde::{Serialize, Serializer};
use std::collections::BTreeMap;

/// Controller state as reported by `/sys/class/nvme/nvmeN/state`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CtrlState {
    New,
    Live,
    Resetting,
    Connecting,
    Deleting,
    DeletingNoIo,
    Dead,
    /// A value this build does not know (kernels may add states).
    Unknown(String),
    /// The attribute could not be read.
    Unreadable,
}

impl CtrlState {
    pub fn parse(s: &str) -> CtrlState {
        match s.trim() {
            "new" => CtrlState::New,
            "live" => CtrlState::Live,
            "resetting" => CtrlState::Resetting,
            "connecting" => CtrlState::Connecting,
            "deleting" => CtrlState::Deleting,
            "deleting (no IO)" => CtrlState::DeletingNoIo,
            "dead" => CtrlState::Dead,
            other => CtrlState::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            CtrlState::New => "new",
            CtrlState::Live => "live",
            CtrlState::Resetting => "resetting",
            CtrlState::Connecting => "connecting",
            CtrlState::Deleting => "deleting",
            CtrlState::DeletingNoIo => "deleting (no IO)",
            CtrlState::Dead => "dead",
            CtrlState::Unknown(s) => s.as_str(),
            CtrlState::Unreadable => "unreadable",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, CtrlState::Live)
    }
}

impl Serialize for CtrlState {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// Parsed `address` attribute (`traddr=…,trsvcid=…,src_addr=…`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FabricAddress {
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traddr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trsvcid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_traddr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_iface: Option<String>,
    /// Local address of the admin queue socket, reported by newer kernels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_addr: Option<String>,
    /// Keys this build does not interpret, kept verbatim.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

/// Logical identity of a fabrics connection, independent of the `nvmeN` name.
/// `src_addr` is deliberately excluded: it is the kernel's report of the current
/// socket and can change across reconnects when no host address was configured.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ControllerKey {
    pub subsysnqn: Option<String>,
    pub transport: Option<String>,
    pub traddr: Option<String>,
    pub trsvcid: Option<String>,
    pub host_traddr: Option<String>,
    pub host_iface: Option<String>,
    /// For non-fabrics controllers (PCIe) the address is the PCI BDF.
    pub raw_address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Controller {
    pub name: String,
    pub instance: u32,
    pub subsystem: Option<String>,
    pub subsysnqn: Option<String>,
    pub transport: Option<String>,
    pub address: Option<FabricAddress>,
    pub state: CtrlState,
    pub cntlid: Option<u16>,
    /// Total queues including the admin queue.
    pub queue_count: Option<u32>,
    /// 0's based submission queue size as exported by sysfs.
    pub sqsize: Option<u32>,
    pub kato_s: Option<u32>,
    pub ctrl_loss_tmo: Option<String>,
    pub reconnect_delay: Option<String>,
    pub fast_io_fail_tmo: Option<String>,
    pub numa_node: Option<i32>,
    pub hostnqn: Option<String>,
    pub hostid: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware_rev: Option<String>,
    pub cntrltype: Option<String>,
    pub dctype: Option<String>,
    /// Hidden per-path block devices (`nvmeXcYnZ`) when native multipath is on.
    pub paths: Vec<String>,
    /// Namespaces attached directly (native multipath off, or PCIe).
    pub namespaces: Vec<String>,
    /// Assigned by the tracker; `None` for a one-shot scan.
    pub generation: Option<u64>,
    pub epoch: Option<u64>,
}

impl Controller {
    pub fn is_tcp(&self) -> bool {
        self.transport.as_deref() == Some("tcp")
    }
    pub fn is_fabrics(&self) -> bool {
        matches!(self.transport.as_deref(), Some("tcp" | "rdma" | "fc" | "loop"))
    }
    /// I/O queues = `queue_count` − 1 (the admin queue).
    pub fn io_queues(&self) -> Option<u32> {
        self.queue_count.map(|q| q.saturating_sub(1))
    }
    /// Configured I/O queue depth = `sqsize` + 1.
    pub fn io_queue_depth(&self) -> Option<u32> {
        self.sqsize.map(|s| s.saturating_add(1))
    }
    pub fn key(&self) -> ControllerKey {
        let a = self.address.as_ref();
        let fabrics = self.is_fabrics();
        ControllerKey {
            subsysnqn: self.subsysnqn.clone(),
            transport: self.transport.clone(),
            traddr: a.and_then(|a| a.traddr.clone()),
            trsvcid: a.and_then(|a| a.trsvcid.clone()),
            host_traddr: a.and_then(|a| a.host_traddr.clone()),
            host_iface: a.and_then(|a| a.host_iface.clone()),
            raw_address: if fabrics { None } else { a.map(|a| a.raw.clone()) },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NsKind {
    /// Native-multipath head device `nvmeXnY` (bio-based).
    MultipathHead,
    /// Namespace block device bound to a single controller.
    Direct,
}

#[derive(Debug, Clone, Serialize)]
pub struct NsPath {
    pub name: String,
    pub controller: String,
    /// `major:minor` of the path block device.
    pub dev: Option<String>,
    pub nsid: Option<u32>,
    pub wwid: Option<String>,
    pub ana_state: Option<String>,
    pub ana_grpid: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Namespace {
    pub name: String,
    pub kind: NsKind,
    pub subsystem: Option<String>,
    /// Owning controller for [`NsKind::Direct`].
    pub controller: Option<String>,
    /// `major:minor` of the namespace block device.
    pub dev: Option<String>,
    pub nsid: Option<u32>,
    pub wwid: Option<String>,
    pub uuid: Option<String>,
    pub nguid: Option<String>,
    pub eui: Option<String>,
    pub size_bytes: Option<u64>,
    pub logical_block_size: Option<u32>,
    /// `queue/iostats` of the namespace block device.
    pub iostats: Option<bool>,
    pub paths: Vec<NsPath>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Subsystem {
    pub name: String,
    pub instance: u32,
    pub nqn: Option<String>,
    pub subsystype: Option<String>,
    pub iopolicy: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware_rev: Option<String>,
    pub controllers: Vec<String>,
    pub namespaces: Vec<String>,
}

/// Something unexpected found while scanning; never fatal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanIssue {
    pub path: String,
    pub problem: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Topology {
    pub subsystems: Vec<Subsystem>,
    pub controllers: Vec<Controller>,
    pub namespaces: Vec<Namespace>,
    pub issues: Vec<ScanIssue>,
}

impl Topology {
    pub fn controller(&self, name: &str) -> Option<&Controller> {
        self.controllers.iter().find(|c| c.name == name)
    }
    pub fn subsystem(&self, name: &str) -> Option<&Subsystem> {
        self.subsystems.iter().find(|s| s.name == name)
    }
    pub fn namespace(&self, name: &str) -> Option<&Namespace> {
        self.namespaces.iter().find(|n| n.name == name)
    }
    pub fn tcp_controllers(&self) -> impl Iterator<Item = &Controller> {
        self.controllers.iter().filter(|c| c.is_tcp())
    }
    /// Block devices that carry a controller's I/O: its paths, or its direct namespaces.
    pub fn controller_block_devices(&self, ctrl: &str) -> Vec<&str> {
        match self.controller(ctrl) {
            Some(c) => c.paths.iter().chain(c.namespaces.iter()).map(String::as_str).collect(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip() {
        for s in ["new", "live", "resetting", "connecting", "deleting", "deleting (no IO)", "dead"] {
            assert_eq!(CtrlState::parse(s).as_str(), s);
        }
        assert_eq!(CtrlState::parse("frozen"), CtrlState::Unknown("frozen".into()));
        assert!(CtrlState::parse("live\n").is_live());
    }
}
