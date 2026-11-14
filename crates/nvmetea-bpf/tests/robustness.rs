//! The BTF and kallsyms parsers never panic on corrupted input. The live
//! module BTF of this host, when readable, is the mutation seed.

use nvmetea_bpf::{btf, symbols};
use nvmetea_core::testrng::Rng;
use std::collections::BTreeSet;

fn seed() -> Vec<u8> {
    // a small valid header + empty sections when no module BTF is readable
    std::fs::read("/sys/kernel/btf/nvme_tcp").unwrap_or_else(|_| {
        let mut v = vec![0x9f, 0xeb, 1, 0, 24, 0, 0, 0];
        v.extend_from_slice(&[0u8; 16]);
        v
    })
}

#[test]
fn btf_survives_garbage() {
    let s = seed();
    let base =
        std::fs::read("/sys/kernel/btf/vmlinux").ok().and_then(|v| btf::parse(&v, None, &[]).ok()).map(|(_, st)| st);
    let mut r = Rng::new(20);
    let n = if s.len() > 100_000 { 300 } else { 3000 };
    for i in 0..n {
        let b = match i % 3 {
            0 => r.mutate(&s),
            1 => r.mutate(&s[..s.len().min(4096)]),
            _ => {
                let mut b = vec![0x9f, 0xeb, 1, 0];
                b.extend(r.bytes(256));
                b
            }
        };
        let _ = btf::parse(&b, base.as_ref(), &["nvme_tcp_queue", "nvme_tcp_request"]);
    }
}

#[test]
fn kallsyms_survives_garbage() {
    let seed = b"ffffffffc041c840 t nvme_tcp_try_send_cmd_pdu\t[nvme_tcp]\nffffffff81000000 T _stext\n0000000000000000 t x [nvme_core]\n";
    let wanted: BTreeSet<String> = ["_stext".to_string()].into_iter().collect();
    let mut r = Rng::new(21);
    for _ in 0..20_000 {
        let b = r.mutate(seed);
        let _ = symbols::parse_kallsyms(&b[..], &["nvme_tcp", "nvme_core"], &wanted);
        let _ = symbols::parse_filter_functions(&b[..], &["nvme_tcp"], &wanted);
    }
}
