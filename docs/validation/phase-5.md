# Phase 5 — Hardening and release: validation record (in progress)

Date: 2026-11-13. Host: the development initiator (Rocky Linux 9.6 userspace,
kernel 6.12.117-1.el9, 6 NVMe/TCP controllers × 8 I/O queues). Workload: the
operator's `elbencho` random writes, later mixed with reads, about 30–41k
commands/s.

## Done

| Item | Where | Result |
|---|---|---|
| Level 1 in-flight redesign (slot array, array-indexed per-queue maps) | `bpf/core.bpf.c`, `crates/nvmetea-bpf/src/core.rs` | **362 ns per command** of program run time (was 1,324 in the same window). Correctness against diskstats unchanged. Details: `phase-3-driver.md`, "Level 1 redesign" |
| Queue registration keyed by NVMe queue; qid from the tag set | `bpf/core.bpf.c` `region_of`, `queue_facts` | fixes I/O-queue statistics registered under qid 0 after a fresh connect. Regions are reused across reconnects. Validated with a forced reconnect (below) |
| Bounded map memory | `CoreConfig::from_topology` | development host ≈ 5 MiB, 64 × 32 queues ≈ 58 MiB, capped beyond. Unit test `map_sizes_are_bounded` |
| Graceful stop | `crates/nvmetea-cli/src/signal.rs` | the first SIGINT/SIGTERM makes `record` write the capture, `profile` report, `serve` exit after the snapshot, and the TUI restore the terminal. A second signal > 0.5 s later exits immediately. An inherited ignored SIGINT stays ignored |
| `probe` text | `cmd/probe.rs`, `main.rs` | CAP_SYS_ADMIN listed as required. Level 2 shown as on demand (it was "not in this build"). After `--load`, the load outcome replaces static checks that cannot verify kprobe symbols without CAP_SYSLOG |
| Packaging | `packaging/stage.sh`, `packaging/rpm/`, `packaging/deb/` | el9 RPM `nvmetea-0.1.0-1.el9.x86_64.rpm`, 1.9 MB: binary, 14 man pages, bash/zsh/fish completions, unit, environment file, licences, docs. Highest glibc symbol 2.34. **The DEB recipe is untested** (no Debian tooling on this host) |
| systemd unit hardening | `packaging/systemd/nvmetea-exporter.service` | `DynamicUser=yes`; capability bounding and ambient sets = CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN, CAP_SYS_RESOURCE; `ProtectSystem=strict`, `ProtectKernelTunables`, `ProtectKernelLogs`, `ProtectKernelModules`, `PrivateDevices`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, … |
| Robustness (fuzz-style) tests | `crates/{nvmetea-topology,nvmetea-tcp,nvmetea-bpf,nvmetea-export}/tests/robustness.rs`; `nvmetea-tcp` sock_diag in-crate | 20,000–50,000 mutated inputs each: diskstats, uevents, addresses, `tcp_info` of any length, `/proc/net/tcp`, BTF blobs, kallsyms, captures, netlink messages. **Found and fixed one panic:** non-ASCII input in `/proc/net` address parsing |
| CI workflow | `.github/workflows/ci.yml`, `deny.toml` | x86_64 and aarch64 fmt/clippy/test/smoke, `promtool check metrics`, el9 RPM built and installed in a Rocky 9 container, cargo-deny. **Not run**: no repository yet (decision D-7). The YAML parses |
| Metrics reference | `docs/metrics.md` | all 61 families: type, labels, meaning, source, conventions, queries |
| Troubleshooting guide | `docs/troubleshooting.md` | reason codes, privileges, symptoms, stage-profiling notes, stopping, reporting |

## Live checks

**Hardened unit, as a dynamic user.**
- Method: the unit's `[Service]` hardening lines were passed to `systemd-run`
  as properties, with the binary staged in `/run/nvmetea-test` and removed
  afterwards.
- Tested as root and then as a dynamic user with `ProtectKernelTunables` and
  `ProtectKernelLogs` added. Those lines are now in the unit.

| Check | Result |
|---|---|
| `probe --load --json` under the sandbox | euid 65405 (dynamic), capabilities CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN. Level 1 active (45,146 commands observed in 1 s); Level 3 active, 54 queue sockets identified in 0.74 ms; L3 lifecycle programs attached |
| `serve` under the sandbox for 12 s (`RuntimeMaxSec`) | `/healthz` 200. `collector_up` 1 for topology, diskstats, sock_diag, bpf_core and bpf_tcp. All four capabilities `active`. 3,281 series. Stopped by systemd's SIGTERM, which logged `stopping` |
| Without CAP_SYS_ADMIN (earlier run) | every BPF collector unavailable, reported as `permission_denied` with the module-BTF explanation. Passive collectors active |

**Forced reconnect with `serve` running.**
- Method: `tools/faultinject` phase `rst` on nvme4. This is the authorized
  fault injection: one controller, with 5 other live paths; cleanup verified.

| Check | Result |
|---|---|
| Slot cursor / queue cursor (`.bss`) | 1,668 → 1,668 and 54 → 54: no region or index allocated again |
| Fabrics Connect commands | 8, counted on nvme4 qids 1–8, one each, `op="other"`, 1,024 bytes each. The previous build counted them under the admin op |
| Quality | `stale_replaced` 0, `map_full` 0. `nvme_error_status_total{status_type="3"}` (path errors) rose during recovery, as expected |
| Controller | `live` after the reconnect. NIC qdiscs unchanged |

**Graceful stop.**

| Command | Signal | Result |
|---|---|---|
| `record -d 60` | SIGINT at 9 s | capture written, `duration_s` 8.41, 5 intervals, 35 stage groups; validates against `capture-v1.schema.json` |
| `profile -i 60` | SIGINT at 4 s | report of 895 sampled commands over 3.4 s |
| `serve` | SIGINT, SIGTERM | `stopping`, exit; 0 nvmetea programs left attached. 3 of 3 runs, after fixing the duplicate-signal race (below) |
| TUI (pty via `script`) | SIGTERM | left the alternate screen and showed the cursor |

**Fixed during this phase.**
- **Duplicate stop signal.** `timeout` signals both the child and its process
  group, so one stop request arrived twice. The second copy was treated as
  "force exit", which skipped the graceful path.
  - Fix: a second signal within 0.5 s of the first counts as the same request.
  - Unit test: `first_signal_requests_stop_and_a_duplicate_is_ignored`.
- **Test artifact.** Under `script`, a `timeout` without `--foreground`
  backgrounds the TUI's process group, and the TUI stopped on SIGTTOU. This
  is not an nvmetea bug. The test now uses `timeout --foreground`.

## Automated tests

`cargo test --workspace`: **126 passed, 0 failed**. `clippy -D warnings` and
`fmt --check` are clean. New since Phase 4:
- the robustness suites;
- `map_sizes_are_bounded`;
- the signal test.

## Not done

| Item | Why | What it needs |
|---|---|---|
| Overhead benchmarks per `implementation-plan.md` §6 (added latency at QD1, IOPS regression, ≥ 5 alternating runs) | needs a dedicated target and controllable I/O. The development host's storage carries the operator's workload, and nvmetea does not generate I/O on it | a benchmark VM with an NVMe/TCP loopback target (qemu/KVM) |
| Runtime matrix: stock Rocky 9 5.14, Ubuntu 22.04/24.04, mainline | qemu is not installed (`/dev/kvm` exists); images must be downloaded | approval to install qemu-kvm and download cloud images |
| aarch64 | no cross toolchain or ARM host here. CI has an arm64 runner job | a run of the CI workflow, or an ARM VM |
| DEB package | recipe written, untested | an Ubuntu container or VM |
| CI, cargo-deny, `promtool`, MSRV 1.85 | not run: no repository (D-7). cargo-deny and promtool are not installed here. The exposition is checked by nvmetea's own validator in tests | the repository |
| `--btf-dir` (modules without BTF) | deferred | — |
| Text-tracepoint fallback (P1b/P2b), BPF generations (P9) | deferred since Phase 2 | — |
| Per-queue histograms beyond 903 queues | counted (`map_full{hist}`), not stored | a sparse overflow map if such hosts appear |
