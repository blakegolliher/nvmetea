//! tcp_info and /proc/net/tcp decoding never panic on corrupted input.

use nvmetea_core::testrng::Rng;
use nvmetea_tcp::{procnet, tcpinfo};

#[test]
fn tcp_info_any_length() {
    let mut r = Rng::new(10);
    for _ in 0..50_000 {
        let b = r.bytes(400);
        if let Some(i) = tcpinfo::decode(&b) {
            // fields beyond the supplied length must be absent, not invented
            if b.len() < 120 {
                assert!(i.bytes_acked.is_none());
            }
        }
    }
}

#[test]
fn procnet_survives_garbage() {
    let seed = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 5F05C8AC:9650 03D4C8AC:1144 01 00000000:00000000 00:00000000 00000000     0        0 230649 1 0000000000000000 20 4 30 10 -1\n";
    let mut r = Rng::new(11);
    for _ in 0..20_000 {
        let b = r.mutate(seed.as_bytes());
        let text = String::from_utf8_lossy(&b);
        let (v, _skipped) = procnet::parse(&text, &|_, _| true);
        assert!(v.len() <= text.lines().count());
    }
}
