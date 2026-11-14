//! Load the Level 2 object, observe sampled commands, print records and health.
//! Usage: driver_smoke [kprobe|fentry|auto] [seconds] [sample_every]
use nvmetea_bpf::driver::{DriverCollector, DriverConfig, DriverEvent, Flavour};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("__preflight") {
        std::process::exit(nvmetea_bpf::preflight::run_helper());
    }
    let fl = args.get(1).map(String::as_str).unwrap_or("kprobe");
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let every: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(10);
    let flavour = match fl {
        "fentry" => Flavour::Fentry,
        "auto" => {
            let pf = nvmetea_bpf::preflight::check(Duration::from_secs(2));
            println!("preflight: {pf:?}");
            if pf.fentry_ok() { Flavour::Fentry } else { Flavour::Kprobe }
        }
        _ => Flavour::Kprobe,
    };
    let topo = nvmetea_topology::scan(&nvmetea_topology::SysRoot::system());
    let cfg = DriverConfig::from_topology(&topo, flavour, every);
    let mut c = match DriverCollector::start(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("start failed: {e}");
            if let nvmetea_bpf::core::LoadError::Load { log, .. } = &e {
                eprintln!("{}", &log[log.len().saturating_sub(6000)..]);
            }
            std::process::exit(1);
        }
    };
    println!("flavour {:?} load {:.1} ms attach {:.1} ms", flavour, c.report.load_ms, c.report.attach_ms);
    for p in &c.report.programs {
        println!("  {:<20} {:<44} attached={} {}", p.program, p.attach, p.attached, p.error.as_deref().unwrap_or(""));
    }
    for (id, why) in &c.dropped {
        println!("  dropped {id}: {why}");
    }
    let t = Instant::now();
    let mut recs = Vec::new();
    let mut timeouts = 0;
    while t.elapsed() < Duration::from_secs(secs) {
        std::thread::sleep(Duration::from_millis(100));
        for e in c.drain_events() {
            match e {
                DriverEvent::Command(r) => recs.push(r),
                DriverEvent::Timeout(_) => timeouts += 1,
            }
        }
    }
    println!(
        "records {} timeouts {} in {:.1}s; health {:?}",
        recs.len(),
        timeouts,
        t.elapsed().as_secs_f64(),
        c.health()
    );
    println!("sampled in flight now: {}", c.sampled_inflight());
    for r in recs.iter().take(4) {
        println!("{r:#?}");
    }
    let mut flags = std::collections::BTreeMap::new();
    for r in &recs {
        for n in nvmetea_core::model::stage::flag::names(r.flags) {
            *flags.entry(n).or_insert(0usize) += 1;
        }
    }
    println!("flag counts: {flags:?}");
    let w = c.workers();
    println!("workers: {} queues; e.g. {:?}", w.len(), w.iter().next());
}
