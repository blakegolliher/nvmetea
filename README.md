# nvmetea

[![ci](https://github.com/blakegolliher/nvmetea/actions/workflows/ci.yml/badge.svg)](https://github.com/blakegolliher/nvmetea/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/blakegolliher/nvmetea)](https://github.com/blakegolliher/nvmetea/releases/latest)

**See where every NVMe/TCP I/O spends its time, from the Linux host.**

Your NVMe-over-TCP writes take 10 ms. Is it the network? The storage target?
This server's CPUs? The kernel's queues? `nvmetea` answers that from the
initiator side, live, without touching the target and without changing
anything on the host.

```
$ sudo nvmetea profile

ALL CONTROLLERS  WRITE R2T  64KiB-128KiB: 4469 complete, 0 partial, 0 excluded; request mean 10.31ms, p50 8.39ms, p99 46.14ms
  STAGE  WHAT                                                      MEAN  SHARE     p50      p99
  A      block submission                                         1.9us   0.0%   2.0us    3.8us
  B1     send queueing (worker wakeup or behind other commands)   4.7us   0.0%   3.3us     20us
  B2     command transmit (send calls)                            2.9us   0.0%   3.1us    5.6us
  C1     remote/transport: command → R2T ^                        870us   8.4%   655us   4.72ms
  ...
  B4     data transmit                                            9.3us   0.1%    10us     18us
  C3     remote/transport: data → response ^                     9.40ms  91.2%  7.34ms  46.14ms
  D1     receive wakeup v                                         4.9us   0.0%   3.6us     23us
  ...
  local: A 0.0%  B 0.2%  D 0.1%  E 0.0%   remote/transport: C 99.6%
```

That is a real 10-second capture of 64 KiB writes. **99.6 % of each 10 ms
write is spent waiting on the network and the target. This host adds about
40 µs.** You know where to look next.

## Try it in one minute

On a Linux x86_64 host with NVMe/TCP controllers connected:

```sh
curl -LO https://github.com/blakegolliher/nvmetea/releases/latest/download/nvmetea-linux-x86_64
chmod +x nvmetea-linux-x86_64
sudo ./nvmetea-linux-x86_64            # live dashboard; press ? for keys, q to quit
```

Then try:

```sh
sudo ./nvmetea-linux-x86_64 profile    # where the time goes, stage by stage (10 s)
sudo ./nvmetea-linux-x86_64 queues     # every queue: IOPS, depth in use, latency p50/p99
./nvmetea-linux-x86_64 status          # no root needed: controllers, paths, connections
```

On Rocky Linux / RHEL 9, install the RPM from the
[release page](https://github.com/blakegolliher/nvmetea/releases/latest).
It adds a man page, shell completions and a Prometheus exporter service:

```sh
sudo dnf install ./nvmetea-0.1.0-1.el9.x86_64.rpm
sudo nvmetea
```

## What it shows

| Question | Command |
|---|---|
| Are my controllers, paths and connections healthy? | `nvmetea status` |
| Which subsystems, namespaces and paths do I have? | `nvmetea topology` |
| Latency per controller and per queue: p50, p99, p99.9 | `sudo nvmetea controllers`, `sudo nvmetea queues` |
| Where does a slow command's time go? | `sudo nvmetea profile` |
| Is TCP the problem: RTT, retransmits, congestion, per queue? | `sudo nvmetea tcp` |
| Everything at once, live | `sudo nvmetea` (TUI) or `sudo nvmetea top` |
| What changed between yesterday and today? | `sudo nvmetea record -o before.json`, later `record -o after.json`, then `nvmetea compare before.json after.json` |
| Graphs and alerts | `sudo nvmetea serve --listen 127.0.0.1:9469` (Prometheus) |

Every command takes `--json`, and `--controller nvme3` to focus on one
controller.

**The stages.**
- **A:** the block layer hands the I/O to the NVMe driver.
- **B:** this host sends the command (and data).
- **C:** the network and the target. Measured from this side as "sent →
  answer arrived".
- **D:** this host receives and parses the answer.
- **E:** completion back to the application.

If C dominates, look at the network or the target. If B or D dominate, look at
this host: a busy CPU, the queue's worker or the NIC. `nvmetea profile` also
names the queues and CPUs with the most local time.

**When something changes,** `compare` points at the stage that moved. In a
test with 2 ms of added network delay on one controller, it flagged that
controller's "command → R2T" stage: 217 µs → 2.23 ms, the largest change.

## Requirements

- **Linux x86_64** with glibc ≥ 2.34: Rocky/RHEL/Alma 9, Ubuntu 22.04+,
  Debian 12+. It uses the system libelf, zlib and zstd, which are installed
  by default.
- **Root** for latency, queue and stage data. nvmetea uses eBPF, and the
  kernel needs BTF, the default on these distributions.
- **Without root**, `status`, `topology`, `controllers` and `tcp` still show
  health, throughput and TCP data, and say what is missing and why.
- `nvmetea probe` tells you what this kernel and these privileges allow.

**Tested on:** Rocky Linux 9.6 userspace with a 6.12 el9 kernel, 6 NVMe/TCP
controllers. Stock Rocky 9 (5.14) and Ubuntu kernels are designed for but not
yet validated. Reports are welcome.

## Is it safe to run in production?

- **Read-only.** It never writes to devices, sysfs or configuration, and it
  never reads authentication or TLS key files.
- **Low overhead.**
  - Continuous monitoring adds about 0.4 µs of CPU per I/O.
  - `profile` samples 1 in 100 commands by default, adding about 0.85 µs per
    I/O while it runs.
- **Clean exit.** Its kernel hooks detach when it exits, even if it is killed.
  Ctrl-C during `record` still writes the capture.
- **No guessing.** If a value cannot be measured, it shows `-` and the reason,
  never a made-up 0.

## Prometheus exporter

```sh
sudo nvmetea serve --listen 127.0.0.1:9469      # /metrics and /healthz
```

The RPM ships `nvmetea-exporter.service`. It runs as an unprivileged dynamic
user with only the kernel capabilities it needs. Set the address in
`/etc/sysconfig/nvmetea-exporter`, then:

```sh
sudo systemctl enable --now nvmetea-exporter
```

See [docs/metrics.md](docs/metrics.md) for every metric, with example queries.

## Build from source

You need Rust ≥ 1.85 with `rustfmt`, clang, and the libelf and zlib headers.
- Rocky 9: `dnf install clang elfutils-libelf-devel zlib-devel`
- Ubuntu/Debian: `apt install clang libelf-dev zlib1g-dev pkg-config`

```sh
cargo build --release          # target/release/nvmetea
cargo test --workspace
packaging/rpm/build.sh         # optional: target/rpm/*.rpm
```

## Documentation

| | |
|---|---|
| [Troubleshooting](docs/troubleshooting.md) | reason codes, privileges, symptoms |
| [Metrics](docs/metrics.md) | every Prometheus metric |
| [Latency model](docs/latency-model.md) | what each stage measures, exactly |
| [Architecture](docs/architecture.md) | how it works |
| [Kernel compatibility](docs/kernel-compatibility.md) | kernels, fallbacks, what was validated |
| [Validation records](docs/validation/) | measured results, fault-injection tests, overhead |
| [Capture format](docs/schema/capture-v1.md) | `record` file format, with a JSON Schema |

## License

MIT. The eBPF programs in `bpf/` are Dual MIT/GPL, as the kernel requires.
See [NOTICE](NOTICE) for acknowledgements.
