//! Parsers of kernel-provided text and netlink data never panic on hostile or
//! corrupted input (seeded random and mutated inputs).

use nvmetea_core::testrng::Rng;
use nvmetea_topology::{address, diskstats, uevent};

const DISKSTATS: &str = " 259       0 nvme2c2n1 32965630 0 263725040 10948 8884761 0 71078088 5530 0 1234 16478 0 0 0 0 5 10\n\
 259       5 nvme2n1 100 0 800 10 200 0 1600 20 3 40 30\n   8 0 sda 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17\n";

#[test]
fn diskstats_survives_garbage() {
    let mut r = Rng::new(1);
    for _ in 0..20_000 {
        let b = if r.below(4) == 0 { r.bytes(512) } else { r.mutate(DISKSTATS.as_bytes()) };
        let text = String::from_utf8_lossy(&b);
        let (m, _issues) = diskstats::parse(&text);
        assert!(m.len() <= text.lines().count());
    }
}

#[test]
fn uevent_survives_garbage() {
    let seed = b"change@/devices/virtual/nvme-fabrics/ctl/nvme3\0ACTION=change\0DEVPATH=/devices/virtual/nvme-fabrics/ctl/nvme3\0SUBSYSTEM=nvme\0NVME_EVENT=connected\0DEVNAME=nvme3\0";
    let mut r = Rng::new(2);
    for _ in 0..20_000 {
        let b = if r.below(4) == 0 { r.bytes(512) } else { r.mutate(seed) };
        if let Some(e) = uevent::parse(&b) {
            let _ = e.is_nvme_relevant();
            let _ = e.devname();
        }
    }
}

#[test]
fn address_survives_garbage() {
    let seed = b"traddr=192.0.2.3,trsvcid=4420,src_addr=198.51.100.95,host_traddr=fe80::1%eth0,host_iface=eth0";
    let mut r = Rng::new(3);
    for _ in 0..20_000 {
        let b = r.mutate(seed);
        let s = String::from_utf8_lossy(&b);
        let a = address::parse_address(&s);
        assert_eq!(a.raw, s);
        let _ = address::parse_ip(&s);
    }
}
