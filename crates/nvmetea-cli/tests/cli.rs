//! End-to-end tests of the `nvmetea` binary against fixture sysfs/procfs trees.
//! `--no-sock-diag` makes TCP collection read the fixture's /proc/net/tcp.

use nvmetea_topology::fixture::{FakeSys, tcp_multipath_host};
use serde_json::Value;
use std::net::Ipv4Addr;
use std::process::{Command, Output, Stdio};

fn hex_ip(ip: Ipv4Addr) -> String {
    format!("{:08X}", u32::from_ne_bytes(ip.octets()))
}

/// /proc/net/tcp rows: `n2` sockets to nvme2's target, `n3` to nvme3's.
fn proc_tree(f: &FakeSys, n2: usize, n3: usize, reads: u64) {
    let local: Ipv4Addr = "198.51.100.5".parse().expect("ip");
    let mut tcp = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    let mut row = 0;
    for (target, n) in [("192.0.2.1", n2), ("192.0.2.2", n3)] {
        let t: Ipv4Addr = target.parse().expect("ip");
        for q in 0..n {
            tcp.push_str(&format!(
                "{row:4}: {}:{:04X} {}:1144 01 00000000:00000000 00:00000000 00000000     0        0 {} 1 0000000000000000 20 4 30 10 -1\n",
                hex_ip(local),
                40000 + row,
                hex_ip(t),
                1000 + row
            ));
            row += 1;
            let _ = q;
        }
    }
    f.write("proc/net/tcp", &tcp);
    let mut ds = String::new();
    for (i, dev) in ["nvme2c2n1", "nvme2c3n1", "nvme2n1", "nvme0n1"].iter().enumerate() {
        ds.push_str(&format!(" 259 {i} {dev} {reads} 0 {} 10 0 0 0 0 0 5 10 0 0 0 0 0 0\n", reads * 8));
    }
    f.write("proc/diskstats", &ds);
}

fn run(f: &FakeSys, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nvmetea"))
        .args(args)
        .arg("--sysfs-root")
        .arg(f.as_path())
        .arg("--proc-root")
        .arg(f.path_of("proc"))
        .arg("--no-sock-diag")
        .arg("--no-bpf") // never load BPF onto the host kernel from tests
        .output()
        .expect("run nvmetea")
}

fn json(o: &Output) -> Value {
    assert!(o.status.success(), "stderr: {}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).expect("valid JSON")
}

#[test]
fn status_health_and_fallback_backend() {
    let f = tcp_multipath_host("cli-status", 2, 1);
    proc_tree(&f, 9, 7, 100);
    let v = json(&run(&f, &["status", "--json"]));
    assert_eq!(v["schema"], "nvmetea.status/1");
    assert_eq!(v["tcp"]["backend"], "proc_net");
    assert_eq!(v["tcp"]["degraded"], "inet_diag_unavailable");
    let subs = v["subsystems"].as_array().expect("subsystems");
    assert_eq!(subs.len(), 1, "PCIe subsystem must be hidden without --all-transports");
    let ctrls = subs[0]["controllers"].as_array().expect("controllers");
    assert_eq!(ctrls[0]["name"], "nvme2");
    assert_eq!(ctrls[0]["health"], "ok");
    assert_eq!(ctrls[0]["connections"]["established"], 9);
    assert_eq!(ctrls[0]["connections"]["association"], "derived");
    assert_eq!(ctrls[1]["health"], "degraded: 7/9 connections");
    assert_eq!(subs[0]["namespaces"][0]["usable_paths"], 2);

    let all = json(&run(&f, &["status", "--json", "--all-transports"]));
    assert_eq!(all["subsystems"].as_array().map(|a| a.len()), Some(2));
}

#[test]
fn rates_are_unavailable_not_zero_without_interval() {
    let f = tcp_multipath_host("cli-ctrl", 2, 1);
    proc_tree(&f, 9, 9, 100);
    let v = json(&run(&f, &["controllers", "--interval", "0", "--json"]));
    let c = &v["controllers"][0];
    assert_eq!(c["name"], "nvme2");
    assert!(c["io"]["read_iops"]["value"].is_null());
    assert_eq!(c["io"]["read_iops"]["reason"], "first_interval");
    assert_eq!(c["io"]["in_flight"]["value"], 0);
    assert_eq!(c["io"]["in_flight"]["quality"], "measured");
    // /proc/net/tcp has no tcp_info: RTT is unavailable, never 0
    assert!(c["tcp"]["rtt_min_us"]["value"].is_null());
    assert_eq!(c["tcp"]["rtt_min_us"]["reason"], "inet_diag_unavailable");

    let o = run(&f, &["controllers", "--interval", "0"]);
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("nvme2"));
    assert!(text.contains("rerun with --interval"));
}

#[test]
fn controllers_interval_measures_counters() {
    let f = tcp_multipath_host("cli-rate", 2, 1);
    proc_tree(&f, 9, 9, 100);
    let v = json(&run(&f, &["controllers", "--interval", "0.2", "--json"]));
    // counters did not change between the samples: a real zero, measured as derived
    assert_eq!(v["controllers"][0]["io"]["read_iops"]["value"], 0.0);
    assert_eq!(v["controllers"][0]["io"]["read_iops"]["quality"], "derived");
}

#[test]
fn tcp_command_queue_column_is_unavailable() {
    let f = tcp_multipath_host("cli-tcp", 2, 1);
    proc_tree(&f, 3, 0, 1);
    let v = json(&run(&f, &["tcp", "--interval", "0", "--json"]));
    let s = v["sockets"].as_array().expect("sockets");
    assert_eq!(s.len(), 3);
    assert_eq!(s[0]["controller"], "nvme2");
    assert!(s[0]["qid"]["value"].is_null());
    assert_eq!(s[0]["qid"]["reason"], "disabled_by_user");
    assert_eq!(s[0]["source"], "proc_net");
}

#[test]
fn topology_and_filters() {
    let f = tcp_multipath_host("cli-topo", 3, 2);
    proc_tree(&f, 0, 0, 0);
    let v = json(&run(&f, &["topology", "--json", "--namespace", "nvme2n2"]));
    let ns = v["namespaces"].as_array().expect("ns");
    assert_eq!(ns.len(), 1);
    assert_eq!(ns[0]["paths"].as_array().map(|p| p.len()), Some(3));
    let by_addr = json(&run(&f, &["status", "--json", "--controller", "192.0.2.2:4420"]));
    assert_eq!(by_addr["subsystems"][0]["controllers"].as_array().map(|c| c.len()), Some(1));
    assert_eq!(by_addr["subsystems"][0]["controllers"][0]["name"], "nvme3");
    let by_nqn = json(&run(&f, &["status", "--json", "--subsystem", "subsys-a"]));
    assert_eq!(by_nqn["subsystems"][0]["name"], "nvme-subsys2");

    let bad = run(&f, &["status", "--controller", "nvme9"]);
    assert!(!bad.status.success());
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(err.contains("no controller matches --controller nvme9"), "{err}");
    assert!(err.contains("nvme2, nvme3, nvme4"), "{err}");
}

#[test]
fn empty_system() {
    let f = FakeSys::new("cli-empty");
    f.write("proc/diskstats", "");
    let o = run(&f, &["status"]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("No NVMe/TCP controllers found"));
    let v = json(&run(&f, &["controllers", "--interval", "0", "--json"]));
    assert_eq!(v["controllers"].as_array().map(|a| a.len()), Some(0));
}

#[test]
fn missing_procfs_files_degrade_gracefully() {
    let f = tcp_multipath_host("cli-noproc", 1, 1);
    // no proc/diskstats, no proc/net/tcp
    let v = json(&run(&f, &["status", "--json"]));
    assert_eq!(v["tcp"]["backend"], "none");
    assert!(v["tcp"]["error"].as_str().is_some_and(|e| e.contains("/proc/net/tcp")));
    let c = json(&run(&f, &["controllers", "--interval", "0", "--json"]));
    assert_eq!(c["controllers"][0]["io"]["read_iops"]["reason"], "missing_interface");
}

#[test]
fn closed_stdout_is_not_a_crash() {
    let f = tcp_multipath_host("cli-pipe", 6, 10);
    proc_tree(&f, 9, 9, 1);
    let mut child = Command::new(env!("CARGO_BIN_EXE_nvmetea"))
        .args(["topology", "--sysfs-root"])
        .arg(f.as_path())
        .arg("--proc-root")
        .arg(f.path_of("proc"))
        .arg("--no-sock-diag")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(child.stdout.take()); // reader goes away immediately
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.code().is_some(), "killed by a signal");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn queues_without_bpf_reports_why_and_shows_inventory() {
    let f = tcp_multipath_host("cli-queues", 2, 1);
    proc_tree(&f, 9, 9, 1);
    let v = json(&run(&f, &["queues", "--interval", "0.1", "--json"]));
    assert_eq!(v["schema"], "nvmetea.queues/1");
    assert_eq!(v["bpf"]["state"], "disabled");
    assert_eq!(v["bpf"]["reason"], "disabled_by_user");
    assert_eq!(v["queues"].as_array().map(|a| a.len()), Some(0));
    let o = run(&f, &["queues", "--interval", "0.1"]);
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("No per-queue data"), "{text}");
    assert!(text.contains("nvme3"));
    let bad = run(&f, &["queues", "--interval", "0.1", "--op", "bogus"]);
    assert!(!bad.status.success());
}

#[test]
fn controllers_json_carries_bpf_status() {
    let f = tcp_multipath_host("cli-ctrl-bpf", 1, 1);
    proc_tree(&f, 9, 0, 1);
    let v = json(&run(&f, &["controllers", "--interval", "0.1", "--json"]));
    assert_eq!(v["bpf"]["state"], "disabled");
    assert!(v["latency"].is_null(), "no latency without BPF, not zeros");
}

#[test]
fn probe_load_respects_no_bpf() {
    let f = tcp_multipath_host("cli-probe", 1, 1);
    proc_tree(&f, 0, 0, 0);
    let v = json(&run(&f, &["probe", "--load", "--json"]));
    assert_eq!(v["schema"], "nvmetea.probe/1");
    assert!(v.get("bpf_load").is_none());
}

#[test]
fn tcp_without_bpf_uses_endpoint_association_and_says_why() {
    let f = tcp_multipath_host("cli-tcp-nobpf", 2, 1);
    proc_tree(&f, 9, 9, 1);
    let v = json(&run(&f, &["tcp", "--interval", "0.1", "--json"]));
    assert_eq!(v["queue_association"]["state"], "disabled");
    let s = v["sockets"].as_array().expect("sockets");
    assert_eq!(s.len(), 18);
    assert_eq!(s[0]["association"], "derived");
    assert_eq!(s[0]["qid"]["reason"], "disabled_by_user");
    assert_eq!(s[0]["io_cpu"]["reason"], "disabled_by_user");
    assert_eq!(s[0]["retransmit_events"]["reason"], "dependency_unavailable");
    let text = String::from_utf8_lossy(&run(&f, &["tcp", "--interval", "0.1"]).stdout).to_string();
    assert!(text.contains("QID/IO_CPU need the BPF queue table (disabled_by_user"), "{text}");
}

#[test]
fn queues_json_has_no_connections_without_bpf() {
    let f = tcp_multipath_host("cli-qconn", 1, 1);
    proc_tree(&f, 9, 0, 1);
    let v = json(&run(&f, &["queues", "--interval", "0.1", "--json"]));
    assert_eq!(v["tcp_bpf"]["state"], "disabled");
    assert_eq!(v["connections"].as_array().map(|a| a.len()), Some(0));
}

#[test]
fn profile_refuses_without_bpf_and_validates_arguments() {
    let f = tcp_multipath_host("cli-profile", 2, 1);
    proc_tree(&f, 3, 2, 100);
    let o = run(&f, &["profile", "-i", "0.2"]);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("profile needs the BPF driver hooks"), "stderr: {err}");
    // the internal preflight helper stays out of the help text
    let h = run(&f, &["--help"]);
    let help = String::from_utf8_lossy(&h.stdout);
    assert!(help.contains("profile"), "{help}");
    assert!(!help.contains("__preflight"), "{help}");
}

#[test]
fn serve_requires_listen_and_reports_bad_addresses() {
    let f = tcp_multipath_host("cli-serve", 2, 1);
    proc_tree(&f, 3, 2, 100);
    let o = run(&f, &["serve"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("--listen"), "{}", String::from_utf8_lossy(&o.stderr));
    let o = run(&f, &["serve", "--listen", "not-an-address"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("expected ADDR:PORT"));
}

#[test]
fn serve_exposes_metrics_without_bpf() {
    use std::io::{Read, Write};
    let f = tcp_multipath_host("cli-serve-run", 2, 1);
    proc_tree(&f, 3, 2, 100);
    // an ephemeral port that is free right now
    let port = std::net::TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nvmetea"))
        .args(["serve", "--listen", &listen, "-i", "0.25"])
        .arg("--sysfs-root")
        .arg(f.as_path())
        .arg("--proc-root")
        .arg(f.path_of("proc"))
        .arg("--no-sock-diag")
        .arg("--no-bpf")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mut body = String::new();
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let Ok(mut s) = std::net::TcpStream::connect(&listen) else { continue };
        let _ = s.write_all(b"GET /metrics HTTP/1.0\r\n\r\n");
        body.clear();
        let _ = s.read_to_string(&mut body);
        if body.contains("200 OK") {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(body.contains("200 OK"), "{body}");
    assert!(body.contains("nvmetea_controller_state{controller=\"nvme2\",state=\"live\"} 1"), "{body}");
    assert!(body.contains("nvmetea_collector_up{collector=\"bpf_core\"} 0"));
    assert!(body.contains("reason=\"disabled_by_user\""));
    // BPF disabled: its families are absent, not zero
    assert!(!body.contains("nvmetea_nvme_commands_total"));
    assert!(!body.contains("nvmetea_tcp_rtt_seconds"));
    assert!(body.contains("nvmetea_snapshot_age_seconds"));
}
