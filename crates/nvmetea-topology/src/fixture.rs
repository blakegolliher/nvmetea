//! Builder for synthetic sysfs/procfs trees used by tests (this crate's and the
//! CLI's). It mirrors the kernel layout nvmetea reads:
//!
//! ```text
//! class/nvme-subsystem/nvme-subsysS/{attrs, nvmeC -> ctrl, nvmeSnN -> head}
//! class/nvme/nvmeC/{attrs, nvmeScCnN -> path | nvmeCnN -> direct ns}
//! block/<dev>/{attrs, queue/…}
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A temporary directory removed on drop.
pub struct FakeSys {
    pub root: PathBuf,
}

impl FakeSys {
    pub fn new(tag: &str) -> FakeSys {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("nvmetea-fixture-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture root");
        FakeSys { root }
    }

    pub fn write(&self, rel: &str, content: &str) {
        self.write_bytes(rel, content.as_bytes());
    }

    pub fn write_bytes(&self, rel: &str, content: &[u8]) {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&p, content).expect("write fixture file");
    }

    pub fn mkdir(&self, rel: &str) {
        std::fs::create_dir_all(self.root.join(rel)).expect("mkdir");
    }

    pub fn remove(&self, rel: &str) {
        let p = self.root.join(rel);
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::remove_file(&p);
    }

    fn link(&self, target_rel: &str, link_rel: &str) {
        let link = self.root.join(link_rel);
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(self.root.join(target_rel), &link).expect("symlink");
    }

    fn attrs(&self, dir: &str, attrs: &[(&str, &str)]) {
        self.mkdir(dir);
        for (k, v) in attrs {
            self.write(&format!("{dir}/{k}"), &format!("{v}\n"));
        }
    }

    pub fn subsystem(&self, name: &str, attrs: &[(&str, &str)]) {
        self.attrs(&format!("class/nvme-subsystem/{name}"), attrs);
    }

    /// A controller, linked from its subsystem when `subsys` is given.
    pub fn controller(&self, name: &str, subsys: Option<&str>, attrs: &[(&str, &str)]) {
        self.attrs(&format!("class/nvme/{name}"), attrs);
        if let Some(s) = subsys {
            self.link(&format!("class/nvme/{name}"), &format!("class/nvme-subsystem/{s}/{name}"));
        }
    }

    /// A multipath head device listed under its subsystem.
    pub fn head(&self, subsys: &str, name: &str, attrs: &[(&str, &str)]) {
        self.attrs(&format!("block/{name}"), attrs);
        self.link(&format!("block/{name}"), &format!("class/nvme-subsystem/{subsys}/{name}"));
    }

    /// A per-path device under its controller.
    pub fn path(&self, ctrl: &str, name: &str, attrs: &[(&str, &str)]) {
        self.attrs(&format!("block/{name}"), attrs);
        self.link(&format!("block/{name}"), &format!("class/nvme/{ctrl}/{name}"));
    }

    /// A namespace attached directly to a controller (no multipath head).
    pub fn direct_namespace(&self, ctrl: &str, name: &str, attrs: &[(&str, &str)]) {
        self.path(ctrl, name, attrs);
    }

    pub fn path_of(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn as_path(&self) -> &Path {
        &self.root
    }
}

impl Drop for FakeSys {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A complete NVMe/TCP multipath layout like the development host's (sanitised):
/// one subsystem, `n_ctrl` TCP controllers with 8 I/O queues each, `n_ns`
/// namespaces, no ANA; plus one PCIe controller with a direct namespace.
pub fn tcp_multipath_host(tag: &str, n_ctrl: u32, n_ns: u32) -> FakeSys {
    let f = FakeSys::new(tag);
    let nqn = "nqn.2024-08.com.example:subsys-a";
    f.subsystem("nvme-subsys0", &[("subsysnqn", "nqn.2014.08.org.nvmexpress:pcie-ssd"), ("iopolicy", "numa")]);
    f.controller(
        "nvme0",
        Some("nvme-subsys0"),
        &[
            ("transport", "pcie"),
            ("address", "0000:03:00.0"),
            ("state", "live"),
            ("queue_count", "129"),
            ("sqsize", "1023"),
            ("cntlid", "0"),
        ],
    );
    f.direct_namespace(
        "nvme0",
        "nvme0n1",
        &[
            ("nsid", "1"),
            ("wwid", "eui.0001"),
            ("size", "1875385008"),
            ("queue/logical_block_size", "512"),
            ("queue/iostats", "1"),
        ],
    );
    f.subsystem(
        "nvme-subsys2",
        &[("subsysnqn", nqn), ("iopolicy", "round-robin"), ("subsystype", "nvm"), ("model", "Example")],
    );
    for c in 0..n_ctrl {
        let inst = c + 2;
        let name = format!("nvme{inst}");
        let addr = format!("traddr=192.0.2.{},trsvcid=4420,src_addr=198.51.100.5", c + 1);
        let cntlid = format!("{}", 70 + c);
        f.controller(
            &name,
            Some("nvme-subsys2"),
            &[
                ("transport", "tcp"),
                ("address", &addr),
                ("state", "live"),
                ("subsysnqn", nqn),
                ("queue_count", "9"),
                ("sqsize", "31"),
                ("cntlid", &cntlid),
                ("kato", "5"),
                ("ctrl_loss_tmo", "off"),
                ("reconnect_delay", "10"),
                ("numa_node", "-1"),
                ("hostnqn", "nqn.2014-08.org.nvmexpress:uuid:00000000-0000-0000-0000-000000000001"),
            ],
        );
        for n in 1..=n_ns {
            let p = format!("nvme2c{inst}n{n}");
            let nsid = format!("{n}");
            let wwid = format!("eui.{:032x}", n);
            f.path(
                &name,
                &p,
                &[("nsid", &nsid), ("wwid", &wwid), ("hidden", "1"), ("queue/logical_block_size", "4096")],
            );
        }
    }
    for n in 1..=n_ns {
        let h = format!("nvme2n{n}");
        let nsid = format!("{n}");
        let wwid = format!("eui.{:032x}", n);
        f.head(
            "nvme-subsys2",
            &h,
            &[
                ("nsid", &nsid),
                ("wwid", &wwid),
                ("size", "1953125000"),
                ("queue/logical_block_size", "4096"),
                ("queue/iostats", "1"),
            ],
        );
    }
    f
}
