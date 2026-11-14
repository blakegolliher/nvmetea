//! Load the Level 3 object, print the queue <-> socket table, observe events.
use nvmetea_bpf::tcpsock::{TcpSockCollector, TcpSockConfig};
use std::time::Duration;

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let topo = nvmetea_topology::scan(&nvmetea_topology::SysRoot::system());
    let mut c = match TcpSockCollector::start(&TcpSockConfig::from_topology(&topo)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("start failed: {e}");
            if let nvmetea_bpf::core::LoadError::Load { log, .. } = &e {
                eprintln!("{}", &log[log.len().saturating_sub(4000)..]);
            }
            std::process::exit(1);
        }
    };
    println!("load {:.1} ms attach {:.1} ms", c.report.load_ms, c.report.attach_ms);
    for p in &c.report.programs {
        println!("  {:<20} {:<28} attached={} {}", p.program, p.attach, p.attached, p.error.as_deref().unwrap_or(""));
    }
    if let Some(e) = &c.iterator_error {
        println!("iterator unavailable: {e}");
    }
    let t = std::time::Instant::now();
    let qs = c.queue_sockets().expect("iterator");
    println!("iterator: {} queue sockets in {:.2} ms", qs.len(), t.elapsed().as_secs_f64() * 1e3);
    for q in &qs {
        println!(
            "QS nvme{} q{} cookie={:#x} {} -> {} {} io_cpu={:?} hdr={} data={} tls={:?}",
            q.instance,
            q.qid,
            q.cookie,
            q.local,
            q.remote,
            q.state.as_str(),
            q.io_cpu,
            q.hdr_digest,
            q.data_digest,
            q.tls
        );
    }
    std::thread::sleep(Duration::from_secs(secs));
    let ev = c.drain_events();
    println!("events in {secs}s: {}  health: {:?}", ev.len(), c.health());
    for e in ev.iter().take(5) {
        println!("  {:?}", e);
    }
    let cnt = c.counters();
    println!("sockets with event counters: {}", cnt.len());
}
