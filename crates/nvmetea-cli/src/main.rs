//! `nvmetea`: Linux NVMe/TCP initiator observability (read-only).

mod cmd;
mod filter;
mod fmt;
mod sample;
mod signal;

use clap::{Parser, Subcommand};
use filter::Filter;
use nvmetea_topology::SysRoot;
use sample::Collector;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "nvmetea",
    version,
    about = "Linux NVMe/TCP initiator observability (read-only)",
    long_about = "Shows NVMe/TCP subsystems, controllers, namespaces, paths and TCP connections.\n\
                  Without a subcommand on a terminal: the interactive TUI (otherwise `status`).\n\
                  Passive data (sysfs, /proc/diskstats, uevents, socket diagnostics) works unprivileged.\n\
                  Per-command latency, per-queue depth and errors come from the Level 1 BPF collector\n\
                  (root, or CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN); `nvmetea probe` shows what this kernel offers."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,
    /// Include PCIe, RDMA, FC and loop controllers (default: NVMe/TCP only).
    #[arg(long, global = true)]
    all_transports: bool,
    /// Controller: name (nvme3), target address, or address:port.
    #[arg(long, global = true, value_name = "CTRL")]
    controller: Option<String>,
    /// Subsystem: name (nvme-subsys2), NQN, or NQN suffix.
    #[arg(long, global = true, value_name = "NQN")]
    subsystem: Option<String>,
    /// Namespace: device (nvme2n1), WWID, UUID or NGUID.
    #[arg(long, global = true, value_name = "NS")]
    namespace: Option<String>,
    /// Alternative sysfs root (testing).
    #[arg(long, global = true, hide = true, default_value = "/sys")]
    sysfs_root: PathBuf,
    /// Alternative procfs root (testing).
    #[arg(long, global = true, hide = true, default_value = "/proc")]
    proc_root: PathBuf,
    /// Do not use NETLINK_SOCK_DIAG; read /proc/net/tcp instead (no RTT data).
    #[arg(long, global = true, hide = true)]
    no_sock_diag: bool,
    /// Do not load BPF programs (passive Level 0 data only).
    #[arg(long, global = true)]
    no_bpf: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Controller and subsystem health.
    Status,
    /// Subsystem / namespace / path inventory.
    Topology,
    /// Per-controller I/O rates and TCP summary over an interval.
    Controllers {
        /// Seconds between the two samples (0 = no rates).
        #[arg(long, short, default_value_t = 1.0)]
        interval: f64,
    },
    /// Per-queue activity, in-flight depth and command latency (BPF; root).
    Queues {
        #[arg(long, short, default_value_t = 2.0)]
        interval: f64,
        /// Only this operation: read, write, flush, other, admin, all.
        #[arg(long)]
        op: Option<String>,
        /// Only this queue id (0 = admin).
        #[arg(long, value_name = "QID")]
        queue: Option<u16>,
    },
    /// Per-connection TCP diagnostics over an interval.
    Tcp {
        #[arg(long, short, default_value_t = 1.0)]
        interval: f64,
    },
    /// Live refreshing summary (Ctrl-C to stop).
    Top {
        #[arg(long, short, default_value_t = 2.0)]
        interval: f64,
        /// Stop after N refreshes.
        #[arg(long, short = 'n')]
        count: Option<u64>,
    },
    /// Where command time goes, stage by stage, for sampled commands (driver hooks; root).
    Profile {
        /// Seconds to observe.
        #[arg(long, short, default_value_t = 10.0)]
        interval: f64,
        /// Record 1 in N commands (1 = every command).
        #[arg(long, default_value_t = 100, value_name = "N")]
        sample: u32,
        /// Hook flavour: auto (fentry if the attach preflight passes, else kprobe), fentry, kprobe.
        #[arg(long, default_value = "auto")]
        flavour: String,
        /// Show the N slowest sampled commands stage by stage.
        #[arg(long, default_value_t = 5, value_name = "N")]
        slowest: usize,
        /// Report nvmetea's BPF program run time. Enables BPF run-time statistics host-wide
        /// (BPF_ENABLE_STATS) for the duration of the run.
        #[arg(long)]
        bpf_stats: bool,
    },
    /// Record a capture (nvmetea.capture/1 JSON) for later `compare`.
    Record {
        /// Seconds to record.
        #[arg(long, short = 'd', default_value_t = 60.0)]
        duration: f64,
        /// Seconds per interval summary.
        #[arg(long, short, default_value_t = 5.0)]
        interval: f64,
        /// Output file (default nvmetea-capture-<unix time>.json).
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
        /// Stage profile: record 1 in N commands (0 = no stage profile).
        #[arg(long, default_value_t = 100, value_name = "N")]
        sample: u32,
        /// Stage hook flavour: auto, fentry, kprobe.
        #[arg(long, default_value = "auto")]
        flavour: String,
    },
    /// Compare two captures: throughput, latency, errors, and stage LAD.
    Compare {
        baseline: PathBuf,
        current: PathBuf,
        /// Complete records a stage group needs in both captures to be compared.
        #[arg(long, default_value_t = 100, value_name = "N")]
        min_samples: u64,
    },
    /// Prometheus exposition on /metrics (and /healthz). --listen is required; there is no default port.
    Serve {
        /// ADDR:PORT to listen on, e.g. 127.0.0.1:9469.
        #[arg(long, value_name = "ADDR:PORT")]
        listen: String,
        /// Seconds between snapshots (0.25-60). A scrape never triggers collection.
        #[arg(long, short, default_value_t = 5.0)]
        interval: f64,
        /// At most this many controllers (the rest are dropped and counted).
        #[arg(long, default_value_t = 64)]
        prom_max_controllers: usize,
        /// At most this many queues per controller (the rest go to qid="other").
        #[arg(long, default_value_t = 128)]
        prom_max_queues: usize,
    },
    /// Capability discovery: what this kernel and these privileges allow.
    Probe {
        /// Also load and attach the BPF collector for a short sample, then detach (root).
        #[arg(long)]
        load: bool,
    },
    /// Print a shell completion script (bash, zsh, fish, elvish, powershell).
    Completions { shell: clap_complete::Shell },
    /// Internal: write man pages (nvmetea.1 and one per subcommand) into DIR.
    #[command(name = "__man", hide = true)]
    Man { dir: PathBuf },
    /// Internal: render every TUI tab as text after sampling (testing without a terminal).
    #[command(name = "__tui-snapshot", hide = true)]
    TuiSnapshot {
        #[arg(long, short, default_value_t = 2.0)]
        interval: f64,
        /// Also start stage profiling (Breakdown tab).
        #[arg(long)]
        profile: bool,
        #[arg(long, default_value_t = 160)]
        width: u16,
        #[arg(long, default_value_t = 45)]
        height: u16,
    },
    /// Internal: fentry attach preflight helper (run by nvmetea itself).
    #[command(name = "__preflight", hide = true)]
    Preflight,
}

pub struct Ctx {
    pub collector: Collector,
    pub filter: Filter,
    pub json: bool,
    pub no_bpf: bool,
}

/// Man pages: nvmetea.1 plus nvmetea-<subcommand>.1 for the visible subcommands.
fn write_man(dir: &std::path::Path) -> anyhow::Result<()> {
    use clap::CommandFactory;
    std::fs::create_dir_all(dir)?;
    let cmd = Cli::command().name("nvmetea");
    let mut buf = Vec::new();
    clap_mangen::Man::new(cmd.clone()).render(&mut buf)?;
    std::fs::write(dir.join("nvmetea.1"), buf)?;
    for sub in cmd.get_subcommands().filter(|c| !c.is_hide_set()) {
        // clap names are &'static str (this runs once, at packaging time)
        let name: &'static str = Box::leak(format!("nvmetea-{}", sub.get_name()).into_boxed_str());
        let mut buf = Vec::new();
        clap_mangen::Man::new(sub.clone().name(name)).render(&mut buf)?;
        std::fs::write(dir.join(format!("{name}.1")), buf)?;
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let mut ctx = Ctx {
        collector: Collector::new(SysRoot::new(&cli.sysfs_root), cli.proc_root.clone()),
        filter: Filter {
            controller: cli.controller.clone(),
            subsystem: cli.subsystem.clone(),
            namespace: cli.namespace.clone(),
            all_transports: cli.all_transports,
        },
        json: cli.json,
        no_bpf: cli.no_bpf,
    };
    ctx.collector.use_sock_diag = !cli.no_sock_diag;
    if cli.no_bpf {
        ctx.collector.bpf = sample::Bpf::Disabled;
        ctx.collector.tcp_bpf = sample::TcpBpf::Disabled;
    }
    let r = match cli.cmd {
        None if !cli.json && fmt::is_tty() && std::io::IsTerminal::is_terminal(&std::io::stdin()) => {
            cmd::tui::run(cmd::tui::Config {
                sys: SysRoot::new(&cli.sysfs_root),
                proc_root: cli.proc_root.clone(),
                use_sock_diag: !cli.no_sock_diag,
                no_bpf: cli.no_bpf,
                filter: ctx.filter.clone(),
                interval: 2.0,
            })
        }
        None => cmd::status::run(&mut ctx),
        Some(Cmd::Status) => cmd::status::run(&mut ctx),
        Some(Cmd::Topology) => cmd::topology::run(&mut ctx),
        Some(Cmd::Controllers { interval }) => cmd::controllers::run(&mut ctx, interval),
        Some(Cmd::Queues { interval, op, queue }) => cmd::queues::run(&mut ctx, interval, op, queue),
        Some(Cmd::Tcp { interval }) => cmd::tcp::run(&mut ctx, interval),
        Some(Cmd::Top { interval, count }) => cmd::top::run(&mut ctx, interval, count),
        Some(Cmd::Profile { interval, sample, flavour, slowest, bpf_stats }) => {
            cmd::profile::run(&mut ctx, cmd::profile::Args { interval, sample, flavour, slowest, bpf_stats })
        }
        Some(Cmd::Serve { listen, interval, prom_max_controllers, prom_max_queues }) => cmd::serve::run(
            &mut ctx,
            cmd::serve::Args { listen, interval, max_controllers: prom_max_controllers, max_queues: prom_max_queues },
        ),
        Some(Cmd::Record { duration, interval, output, sample, flavour }) => {
            cmd::record::run(&mut ctx, cmd::record::Args { duration, interval, output, sample, flavour })
        }
        Some(Cmd::Compare { baseline, current, min_samples }) => {
            cmd::compare::run(&ctx, &baseline, &current, min_samples)
        }
        Some(Cmd::Probe { load }) => cmd::probe::run(&mut ctx, load),
        Some(Cmd::TuiSnapshot { interval, profile, width, height }) => cmd::tui::snapshot(
            cmd::tui::Config {
                sys: SysRoot::new(&cli.sysfs_root),
                proc_root: cli.proc_root.clone(),
                use_sock_diag: !cli.no_sock_diag,
                no_bpf: cli.no_bpf,
                filter: ctx.filter.clone(),
                interval,
            },
            profile,
            width,
            height,
        ),
        Some(Cmd::Completions { shell }) => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut Cli::command(), "nvmetea", &mut std::io::stdout());
            Ok(())
        }
        Some(Cmd::Man { dir }) => write_man(&dir),
        Some(Cmd::Preflight) => std::process::exit(nvmetea_bpf::preflight::run_helper()),
    };
    if let Err(e) = r {
        eprintln!("nvmetea: {e:#}");
        std::process::exit(1);
    }
}
