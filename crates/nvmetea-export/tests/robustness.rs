//! The capture reader never panics on corrupted files: it returns an error.

use nvmetea_core::testrng::Rng;
use nvmetea_export::capture;

#[test]
fn capture_reader_survives_garbage() {
    let seed = br#"{"schema":"nvmetea.capture/1","tool":{"name":"nvmetea","version":"0.1.0"},"host":{},"boundary_signature":{},"capabilities":[],"start_unix_s":0,"end_unix_s":1,"duration_s":1,"interval_s":1,"topology_start":{"controllers":[],"namespaces":[]},"topology_end":{"controllers":[],"namespaces":[]},"transitions":[],"intervals":[],"latency":[{"controller":"nvme2","key":{},"op":"read","metric":"request","dist":{"count":2,"sum_ns":10,"hist":[[17,2],[999,5]]}}],"queues":[],"controllers":[],"events":[],"quality":{"events_dropped":0},"self_overhead":{}}"#;
    assert!(capture::from_json(std::str::from_utf8(seed).expect("utf8")).is_ok());
    let mut r = Rng::new(30);
    for _ in 0..20_000 {
        let b = r.mutate(seed);
        if let Ok(c) = capture::from_json(&String::from_utf8_lossy(&b)) {
            for g in &c.latency {
                // out-of-range bucket indexes are ignored, not a panic
                let _ = g.dist.hist.to_hist();
                let _ = g.dist.percentile_ns(0.99);
            }
        }
    }
}
