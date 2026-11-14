# Phase 1 — Passive monitoring: validation record

Date: 2026-11-13. Host: the development initiator.
- Rocky Linux 9.6 userspace, kernel 6.12.117-1.el9 (non-distribution LTS build), x86_64, 128 CPUs.
- 6 NVMe/TCP controllers to one subsystem, 8 I/O queues × depth 32 each, 10 namespaces, native multipath, no ANA reported by the target.
- One PCIe controller.

All checks were read-only. No I/O was generated. Workloads present during
validation were provided by the operator.

## What was built

| Crate | Contents |
|---|---|
| `nvmetea-core` | model (topology, block, TCP), `Obs`/`Quality`/`Reason`, interval engine (controller / namespace / socket rates, generation-aware, never negative or zero-filled) |
| `nvmetea-topology` | allow-listed sysfs reader, scanner, lifecycle tracker (generation, epoch, transition log, history), diskstats parser, uevent listener, fixture builder |
| `nvmetea-tcp` | raw `NETLINK_SOCK_DIAG` client, length-gated `tcp_info` decoder (offsets checked against kernel BTF), `/proc/net/tcp{,6}` fallback, endpoint association with ambiguity detection |
| `nvmetea-bpf` | passive discovery: BTF parser (vmlinux + split module BTF, anonymous members), kallsyms/ftrace scan, probe catalog with attach rule F4, CO-RE field checks |
| `nvmetea-cli` | `status`, `topology`, `controllers`, `tcp`, `top`, `probe`; `--json` everywhere; filters `--controller/--subsystem/--namespace/--all-transports` |

Not in this build, and reported as such by the tool rather than shown as empty:
- BPF collectors (per-command latency, queues, driver stages, TCP events);
- the TUI, `record`, `compare` and `serve`.

## Automated tests

`cargo test --workspace`: **65 passed, 0 failed**.
`cargo clippy --workspace --all-targets -D warnings`: clean. `cargo fmt --check`: clean.

The tests cover:
- **Sysfs parsing**: missing, malformed, oversized and non-UTF-8 attributes; refusal of non-allow-listed names. Secret attributes are FIFOs in the fixture: opening one would hang the test, so a pass proves they are never opened.
- **Topology**: multipath, PCIe, ANA, nsid/wwid mismatches, orphan paths, removed controllers, IPv6 addresses.
- **Lifecycle**: added/state/removed changes; reset raises the epoch only; recreation under the same name gets a new generation; an endpoint change counts as a replacement; logs are bounded.
- **diskstats**: 11/15/17-field formats, partitions skipped, head accounting vs sum of paths.
- **TCP**: `tcp_info` full and short lengths; sock_diag message and attribute parsing, kernel errors, truncation; a live unprivileged dump; `/proc/net/tcp` IPv4/IPv6 and v4-mapped addresses; association that is unique, ambiguous, or limited to the local address.
- **Engine**: rates, generation change → `counter_reset`, new socket → `first_interval`.
- **Discovery**: BTF parsing (synthetic and running kernel, anonymous unions), kallsyms clones, and attach rule F4 (exact symbol, `.constprop` clone, inlined, missing, module not loaded, no root).
- **CLI end to end** against fixtures:
  - health (`ok`, `degraded: 7/9 connections`);
  - unavailable-not-zero in JSON;
  - the `/proc/net/tcp` fallback;
  - filter errors with suggestions;
  - empty systems and missing procfs files;
  - a closed stdout pipe.

## Live cross-checks on the development host

| Check | Result |
|---|---|
| `nvmetea topology --json --all-transports` vs `nvme list-subsys -o json` (nvme-cli 2.16): controller set and NQN, transport, address, state, subsystem | **match** (7 controllers, 2 subsystems) |
| `nvmetea tcp --json` vs `ss -tnie`: every socket's remote endpoint, inode, cookie | **match** (54/54) |
| controller ↔ connection association | each controller owns exactly the 9 sockets to its own endpoint; 0 ambiguous, 0 unassociated |
| block read throughput (diskstats, per controller) vs TCP bytes received (`tcp_info`, same controller) | 522.0 vs 523.6 MiB/s (the difference is PDU headers) |
| Σ namespace heads (head accounting) vs Σ controllers (path devices) | ≈ 400k vs ≈ 400k read IOPS |
| `nvmetea probe` unprivileged | tracepoints eligible via BTF. Function hooks: kprobe eligible, fentry `unknown (permission_denied)` because `available_filter_functions` needs root. sock_diag and uevents OK. 29/29 CO-RE fields present |
| `nvmetea probe` as root | every catalog probe eligible (consistent with the Phase 0 runtime spikes) |
| `nvmetea top -n 3 -i 1` | 3 refreshes in 3.0 s, ≈ 14 ms CPU in total; NDJSON mode valid |
| release binary | 2.1 MB. Needs `libc.so.6`, `libgcc_s.so.1`, `ld-linux`; highest glibc symbol 2.34 (Rocky 9 = 2.34, Ubuntu 22.04 = 2.35) |

Phase 0 addendum recorded during this phase: READ data-phase hooks validated for
single-PDU reads (`latency-model.md` §10.3).

## Limitations and open items

- **Stock Rocky 9 kernel (5.14.0-5xx/6xx)**: not run yet. It needs a VM or a reboot
  of a non-production host; only binary inspection exists (`kernel-compatibility.md`).
  Ubuntu is deferred by decision.
- **Live controller transitions** (reset/reconnect/remove) were not exercised on this
  host because it carries production storage. The tracker logic is unit-tested and
  the uevent listener opens and receives. End-to-end validation needs the loopback
  harness in a VM.
- `INET_DIAG` autoload (Ubuntu builds it as a module) and the `/proc/net/tcp`
  fallback were exercised through fixtures and `--no-sock-diag`, not on a kernel
  without `inet_diag`.
- Property-based and fuzz tests are not written yet (planned in Phase 5).
- diskstats-derived `r_ms`/`w_ms` are millisecond-resolution means that include
  queueing. The tool labels them as such and never presents them as percentiles.
