# nvmetea — Implementation plan

Status: Phase 0 deliverable. Last updated 2026-11-13.

## 1. Phase 0 outcome

| Phase 0 item (spec §19) | Where |
|---|---|
| 1. Reference implementations studied | ntprof design, reference, host BPF and model; nfs-gaze and nfsview patterns and pitfalls. Findings are applied throughout `architecture.md`. |
| 2. Metric-to-source map | `architecture.md` §13 |
| 3. Exact probe candidates | `kernel-compatibility.md` §5 (P1–P9, D1–D13, T1–T6, L1–L4) |
| 4. Kernel capabilities validated | `kernel-compatibility.md` §2–4. Runtime-validated on el9 6.12. Binary-inspected on Rocky 9.6/9.8 and Ubuntu 5.15/6.8/6.17. Source-inspected upstream 5.14→7.3 and CS9. |
| 5. Command lifecycle and timing model | `latency-model.md` §2–6 |
| 6. Fallback for every metric | `architecture.md` §13 and `kernel-compatibility.md` §5 |
| 7. Acceptance tests and budgets | this document §4–§6 |
| 8. Unobservable components | `latency-model.md` §9 |

Phase 0 changed nothing on the development host. It read sysfs, procfs, tracefs and
BTF. It ran short read-only bpftrace observations (`tools/feasibility/`) of
workloads already running on the host: an application read workload, and an
operator-provided `elbencho` write workload. It created no test resources and
generated no I/O.

### Key design decisions taken in Phase 0

1. **Correlation keys on the request's driver PDU address** from `raw_tp` arguments.
   Tracepoint text fields are not used. The `nvme_complete_rq` cid changed meaning
   across 5.15 builds (F1). Text fields remain a fallback only.
2. **Probe selection is per running kernel.** Every examined build inlines a
   different set of nvme-tcp functions (F3). A BTF name can exist without an
   attachable symbol (F4). A common hook set that works across all six builds
   exists and is the default plan.
3. **Continuous mode splits A, B1, B2, C+D, E1 and E2.** Only profile mode separates
   C (remote/transport) from D (local receive), using per-skb receive hooks on
   sampled commands. The combined C+D row is labelled as such.
4. **Receive arrival timestamps (`--rx-timestamps`) are opt-in**, because they turn
   on RX timestamping for every socket. By default the C/D boundary is the
   `sk_data_ready` notification, mapped to the response bytes by TCP sequence
   number. That gives C as an upper bound and D as a lower bound. The simpler
   "first notify since drain" heuristic was tested against live traffic and
   rejected (`latency-model.md` §5.4, §10.2).
5. **Queue↔socket association** uses a BPF `iter/tcp` program joined to
   unprivileged sock_diag through the socket cookie. This was runtime-validated on
   54 queues.
6. **Controller identity** is the connection identity plus a BPF-maintained
   generation, never `nvmeN`.

## 2. Phases

Every phase follows the same discipline:
1. Design note (a short section added to the relevant doc).
2. Implementation.
3. Tests.
4. `cargo fmt --check`, `clippy -D warnings` and tests pass.
5. Results and limitations recorded in `docs/validation/phase-N.md`.
6. CLI, TUI, metrics and docs consistent.

Nothing is reported as working on compilation alone.

### Phase 1 — Passive monitoring (Level 0)

**Status (2026-11-13):** implemented and validated on the el9 6.12 development host
(`docs/validation/phase-1.md`). Open: the stock Rocky 9 kernel run (needs a VM).
Live controller transitions (reset → connecting → live, epoch +1, same generation)
were validated by fault injection on the development host
(`docs/validation/fault-injection.md`); removal and re-add remain for the harness.

**Scope**:
- `nvmetea-core` model: identities, observation/quality, units, histogram type, telemetry engine.
- `nvmetea-topology`: sysfs allow-list reader, reconciliation, uevents, generations, transition log.
- `BlockStats`: diskstats with head-vs-path handling (F7).
- `nvmetea-tcp` passive: sock_diag client with kernel-side bytecode filter on NVMe/TCP endpoints, `tcp_info` decoding gated by length, `/proc/net/tcp{,6}` fallback, endpoint-level controller association.
- CLI: `status`, `topology`, `controllers`, `tcp`, `top`, with `--json`.
- `probe`: steps 1–7 of `kernel-compatibility.md` §6.1, no load/attach.

**Tests**:
- Fixture sysfs trees under `tests/fixtures/sysfs/`:
  - sanitized capture of the development host (6 TCP controllers, 10 namespaces, multipath, no ANA, plus one PCIe controller);
  - synthetic trees: ANA optimized/non-optimized/inaccessible, multipath disabled, controller `resetting`/`connecting`/`deleting`, controller removed and re-added with the same name, missing attributes, hostile values (non-UTF-8, oversized, unexpected keys), IPv6 addresses, non-4420 ports.
- diskstats corpus: 17- and 20-field formats, zero head counters (5.15), counter wrap.
- netlink fixtures: recorded sock_diag replies (IPv4/IPv6, short `tcp_info` from older kernels).
- Property tests for delta/reset handling.

**Exit criteria**:
- On the development host, `nvmetea topology --json` matches an independent sysfs walk and `nvme list-subsys -o json` (test only).
- Every TCP socket is associated to its controller.
- Rates match diskstats deltas.
- Runs unprivileged with documented reduced fields.
- Same results in Rocky 9 and Ubuntu 22.04 VMs (loopback target, harness §5).

### Phase 2 — Core eBPF latency (Level 1)

**Status (2026-11-13):** implemented and validated on the el9 6.12 host
(`docs/validation/phase-2.md`). These items are deferred:
- text-tracepoint fallback (no target kernel lacks BTF);
- BPF-side generations (P9);
- removed-controller map cleanup;
- per-I/O overhead measurement (benchmark VM);
- the stock Rocky 5.14 runtime run.

fentry preflight and parallel attach moved to Phase 3, because Level 1 uses no
fentry.

**Scope**:
- `bpf/core.bpf.c`: P1–P9 and L3, `raw_tp` + CO-RE, text-tracepoint fallback P1b/P2b.
- Planner and loader: flavours, rule F4, fentry preflight in a re-exec'd helper, parallel attach with timeout and kprobe restart, arming, per-object independence.
- Map sizing from topology; histograms; ring buffer events; slow-command records (adaptive threshold, rate limit).
- NvmeCore collector.
- `probe --load/--attach`; `queues` and `controllers` with latency and errors.

**Tests**:
- Unit: bucket function test vectors shared by C and Rust (generated table); request-correlation state machine tested in a userspace simulator with event scripts:
  - cid reuse at QD1 (16-dispatch wrap);
  - retry with `retries` increment; requeue; failover; cancel during reset;
  - missed completion (stale replace); untracked completion; delete + recreate with the same `nvmeN`;
  - map-full behaviour.
- Integration (harness §5): cases 1–8, 16–18 of §4.
- Cross-checks:
  - BPF command counts equal diskstats deltas per path device, exactly, at steady state;
  - request-latency mean within the bucket resolution of diskstats-derived mean service time at QD1;
  - fio `clat` compared with documented boundary differences;
  - ntprof host-only on the same workload, per matching component.

**Exit criteria**: real measured latency distributions per controller, queue and op on
the development host (read-only observation) and in Rocky 9 / Ubuntu 22.04 / Ubuntu
24.04 VMs. All fallbacks exercised. Overhead measured against §6 budgets (preliminary).

### Phase 3 — Driver and TCP instrumentation (Levels 2–3, profile mode)

**Status (2026-11-13):** part 1 (Level 3) is implemented and validated on the el9
6.12 host: the queue ↔ TCP connection table (T1), transport events (T3–T7), and
per-queue connection telemetry in `tcp`, `queues` and `top`
(`docs/validation/phase-3-tcp.md`). The event path was validated by scoped fault
injection on the development host: loss, delay and a connection reset on one
controller (`docs/validation/fault-injection.md`).

Part 2 (Level 2: driver-stage timing and profile mode) is implemented and
validated on the same host (`docs/validation/phase-3-driver.md`). It covers:
- `bpf/tcp_driver.bpf.c` with D1–D4, D6–D10 and D12, in kprobe and fentry flavours;
- the fentry attach preflight;
- `nvmetea-profile` (partition with rules R1–R3/R5–R7, sum-checked);
- `nvmetea profile` with `--bpf-stats`.

Attribution tests:
- **netem delay:** only C1 moves, by the injected amount.
- **CPU contention on a queue's io_cpu:** only that queue's B and D move.
- **netem loss:** only C moves.

Open items:
- D11 (on-CPU worker time), D13 (polled queues), `--rx-timestamps`;
- the Level 1 per-command cost: one pass brought it from 1.42 to 1.32 µs, still above the 0.5 µs budget. The remainder is cross-CPU memory traffic in the shared in-flight hash; the next step is an open-addressed in-flight array (see the validation record).

**Scope**:
- `bpf/tcp_driver.bpf.c` D1–D13 and `bpf/tcp_sock.bpf.c` T1, T3–T6.
- `nvmetea-profile`: stage reconstruction for every protocol variant (`latency-model.md` §5.3), accounting rules R1–R7, grouping, LAD.
- `profile` command; `--rx-timestamps`.
- Worker accounting with sched_switch-based on-CPU estimate.
- Queue↔socket mapping; TCP event correlation for slow commands.

**Tests**:
- Sum-check property tests on reconstructed records (Σ stages == request latency, for every variant and every missing-boundary pattern).
- Attribution tests (`latency-model.md` §11), run in VMs:
  - netem delay;
  - null_blk `completion_nsec`;
  - CPU hog on `io_cpu`;
  - netem loss;
  - rq_affinity.
- READ 4 KiB–4 MiB, inline and R2T WRITEs, QD 1–128, mixed R/W.
- Fallback tests: programs force-disabled (simulated inlining), kprobe-only mode, module BTF treated as missing.

**Exit criteria**:
- Every attribution test moves only the expected stage, within tolerance (§4).
- Profile records validated against ntprof host-side components on the same commands' distributions.
- READ data-phase split validated on the development host with read-only observation when READ traffic is present.

**Stretch**: bio-level tracking above the path request (multipath head → request) in
profile mode.

### Phase 4 — TUI, capture, export

**Status (2026-11-13):** implemented and validated on the development host
(`docs/validation/phase-4.md`):
- the TUI (all nine tabs, the keymap, the Breakdown tab with an on-demand stage
  profile);
- `serve --listen` (exposition with cardinality limits);
- `record` with `docs/schema/capture-v1.*`;
- `compare` with LAD.

Not yet built: TUI rolling trends; the opt-in per-path and per-queue
histograms and the Level 2 families in the exposition; queue-imbalance changes in
`compare`; BPF object hashes in captures. See the record.

**Scope**:
- All nine TUI tabs and the keymap. Breakdown view with a slow-command timeline.
- `record` and the `capture-v1` schema with a JSON Schema file.
- `compare` with LAD and non-comparability reasons.
- `serve` Prometheus exposition (§10 of the architecture) with cardinality limits.

**Tests**:
- TUI rendering snapshots (ratatui `TestBackend`) including unavailable/estimated/low-sample rendering.
- Exposition golden files and `promtool check metrics`.
- Capture schema validation, round-trip, forward-compatibility (unknown fields ignored, unknown major refused).
- Compare on fixture captures with different boundary signatures.

**Exit criteria**: one model drives all outputs. The same capture renders identically in
TUI replay, CLI and JSON.

### Phase 5 — Hardening and release

**Status (2026-11-13): in progress** (`docs/validation/phase-5.md`).
- Done:
  - the Level 1 slot redesign (362 ns per command of program run time);
  - queue-keyed registration with qid from the tag set;
  - bounded map memory;
  - graceful stop;
  - the el9 RPM, with the systemd unit hardened to a dynamic user and
    validated live;
  - man pages and completions;
  - robustness tests (one panic found and fixed);
  - the CI workflow (written, not run: D-7);
  - `docs/metrics.md` and `docs/troubleshooting.md`.
- Open:
  - §6 benchmarks and the runtime matrix (benchmark VM: needs qemu and cloud
    images);
  - aarch64;
  - DEB;
  - `--btf-dir`.

**Scope**:
- Overhead benchmarks (§6) in continuous and profile modes.
- Runtime compatibility matrix (§5.3).
- aarch64 builds and VM validation.
- RPM/DEB packages, systemd unit, man page and completions.
- CI and release automation.
- Fuzzing.
- `--btf-dir` for modules without BTF.
- Documentation: metrics reference, troubleshooting guide, compatibility report with exact kernel builds.

**Exit criteria**: the spec's definition of done (§20), with the measured numbers
published.

## 3. Repository bootstrap (start of Phase 1)

- Cargo workspace per `architecture.md` §3; edition 2024; MSRV pinned in
  `rust-toolchain.toml`.
- Crates: `libbpf-rs`/`libbpf-cargo`, `libbpf-sys` (vendored, static), `ratatui`,
  `crossterm`, `clap` (derive, completions, mangen), `serde`/`serde_json`,
  `crossbeam-channel`, `arc-swap`, `tiny_http`, `thiserror`/`anyhow`,
  `rustix`/`libc` (netlink). Versions are pinned at bootstrap. No async runtime.
- CI (GitHub Actions):
  - fmt, clippy, unit tests;
  - BPF compile for x86_64 + aarch64;
  - `cargo deny` (licences, advisories, internal dependency rules);
  - VM integration jobs (KVM runners);
  - release builds in a Rocky 9 container (glibc 2.34) and an ARM runner.

## 4. Acceptance tests (spec §17)

The loopback harness (§5) runs every case on every runtime matrix kernel unless noted.
"Pass" always includes:
- no crash;
- correct capability report;
- metrics marked with the correct quality;
- no fabricated values: unavailable values must be absent/N/A, never zero.

| # | Case | Pass criteria |
|---|---|---|
| 1 | Initial controller connection | controller appears with the correct identity, queues, sockets and generation. Transition `new→connecting→live` logged (L3) or `→live` (poll) |
| 2 | Controller disappearance | moves to history with final counters. No further series under its generation. Its sockets close (T4) |
| 3 | Reset and reconnect | same generation, epoch +1, new socket cookies. Queue↔socket map refreshed. Cancelled commands counted, not in latency |
| 4 | Multiple controllers (multipath) | per-path and per-controller stats. Namespace totals equal Σ paths (exact) |
| 5 | Multiple I/O queues | per-queue counts sum to controller counts. qid attribution equals the CPU→hctx mapping |
| 6 | Concurrent READ/WRITE | per-op separation; variant classification (inline/R2T) correct |
| 7 | Small and large I/O | READ data-phase split present for multi-PDU reads (profile). Σ stages = request latency |
| 8 | Increasing queue depth | outstanding ≤ configured depth; Little's-law occupancy consistent with tracked outstanding within 10 %; receive-backlog share reported |
| 9 | Transport faults / retransmissions | retransmissions attributed to the faulted queue's socket only. Slow-command records show nearby retransmissions |
| 10 | Artificial local processing delay | B1/D1 grow by the injected amount ± tolerance; C does not |
| 11 | Artificial network delay (netem X µs) | C1 (+C3 for R2T) grows by X ± max(5 µs, 10 %); A, B, D, E change < 5 µs |
| 12 | Artificial target-side delay (null_blk Y µs) | C1 grows by Y ± max(5 µs, 10 %); other stages < 5 µs |
| 13 | Missing kernel BTF (custom kernel) | Level 0 + text-tracepoint P1b/P2b; request latency unavailable with `btf_vmlinux_missing` |
| 14 | Missing module BTF (custom kernel / out-of-tree module) | L1 via text fallback; L2/T1 unavailable with `btf_module_missing` |
| 15 | Unavailable driver symbols | the planner picks the documented fallback (e.g. D5 for D1–D3); a forced-disable simulation covers every D-probe |
| 16 | Permission failures | unprivileged: Level 0 works; BPF reported `permission_denied`. With only `CAP_BPF`: actual outcome reported. Lockdown confidentiality: Level 0 only, reported |
| 17 | Map pressure and lost events | with tiny maps/ring buffer: `map_full`/`events_lost` counted, affected commands excluded, totals still exact |
| 18 | High IOPS stress | null_blk, many queues, ≥ 1 M IOPS where hardware allows: no lost totals, overhead per §6 |

Unit-test list (spec §17): sysfs parsers; subsystem/controller/namespace relationships;
lifecycle identities; counter deltas and resets; histogram aggregation and percentile
estimator; request correlation including cid reuse; missing stage events; stage
arithmetic; capture schema validation; compare calculations.

## 5. Test environment

### 5.1 Safety interlock

The harness creates nvmet targets, null_blk devices and netem qdiscs, and it
connects/disconnects/resets controllers. It **refuses to run** unless both hold:
- it is inside a VM (systemd-detect-virt) or `NVMETEA_HARNESS_ALLOW=1` is set;
- no pre-existing NVMe-oF controllers exist (any controller with transport
  `tcp`/`rdma`/`fc`/`loop` not created by the harness).

The harness creates targets and controllers, so it stays in VMs. The development host
is **not** production: the operator confirmed this on 2026-11-13 and authorized fault
injection there. Faults on the development host use only `tools/faultinject/`. That
script impairs one controller, scoped to its target address through an ifb redirect,
keeps other multipath paths up, and removes everything on exit.

### 5.2 Harness (`tests/loopback/`)

- Target: `null_blk` (memory-backed, configurable `completion_nsec`, `irqmode`, queue
  counts) exported through `nvmet` + `nvmet-tcp` on 127.0.0.1. Additional ports or
  addresses to the same subsystem give multipath and multiple controllers. IPv6 and
  non-4420 ports are covered.
- Host: `nvme connect -t tcp` with chosen `--nr-io-queues`, `--queue-size`, digests.
- Faults: `tc netem` (delay/loss) on the loopback device (VM only), CPU hogs pinned
  with `taskset`, `nvme reset`, `nvme disconnect`/re-connect.
- Workload: `fio` with JSON output, used for cross-checks (harness only, never by
  nvmetea).

### 5.3 Runtime matrix

| Target | How |
|---|---|
| Rocky 9.6 and 9.8 stock kernels | QEMU/KVM with Rocky cloud images (validates userspace, glibc, packaging too) |
| Ubuntu 22.04 GA: the **original GA build** (pre-cid-fix, F1) and the latest 5.15.0-x | cloud image + pinned kernel packages |
| Ubuntu 22.04 HWE 6.8, 24.04 GA 6.8, 24.04 HWE (6.17 today) | cloud images |
| Upstream latest stable and mainline (7.x) | virtme-ng booting built kernels |
| Custom kernels without BTF / without module BTF | virtme-ng, cases 13–14 |
| aarch64 (Rocky 9, Ubuntu 24.04) | ARM runners / VMs |
| Real NVMe/TCP target | development host: observation plus scoped fault injection (`tools/faultinject/`); other lab hosts if provided (decision D-4) |

Each run records the exact kernel build, module list, BTF state and capability report
in `docs/validation/`.

## 6. Performance budgets

Targets are validated in Phase 2 (preliminary) and Phase 5 (release). If a budget is
missed, the measured number is published and the design is revisited (for example,
by switching the continuous default to Level 1 only). Budgets are never met by
claiming "zero overhead".

| Mode | Workload | Budget |
|---|---|---|
| continuous L1 | 4 KiB random read QD1 | added mean latency ≤ 0.5 µs |
| continuous L1+L2 (continuous hooks) | 4 KiB random read QD1 | ≤ 1.0 µs |
| continuous L1+L2 | 4 KiB random read, CPU-saturated IOPS | IOPS regression ≤ 3 % |
| continuous L1+L2 | 1 MiB sequential read and write | throughput regression ≤ 1 % |
| profile, 1 in 100 | 4 KiB random read QD1 | ≤ 3 µs added; IOPS regression ≤ 8 % at saturation |
| profile, every command | any | measured and published; diagnostic use only |
| userspace | 64 controllers × 33 queues, 1 s interval | ≤ 2 % of one core; RSS ≤ 64 MiB |
| lost data | continuous, ≤ 200 slow events/s, QD ≤ configured depth | 0 lost events, 0 `map_full` |
| attach/detach | idle host | ≤ 5 s attach; kprobe fallback beyond 10 s; detach ≤ 3 s or reported |

Method: fio on loopback (both small random and large sequential), repeated runs with
nvmetea off/on, alternating order, ≥ 5 runs of ≥ 30 s each. Report mean and stddev.
Overhead is reported separately per mode and per level. BPF program run time is
collected via `bpf_prog_info` with `kernel.bpf_stats_enabled=1` **in the benchmark
VM only**.

## 7. Risks

| Risk | Mitigation |
|---|---|
| fentry attach stalls on busy hosts (F15) | preflight, attach timeout, kprobe restart, parallel attach |
| per-I/O map cost too high at extreme IOPS | measured early (Phase 2). Fallback configuration: request latency from `start_time_ns` at P3 only (stateless, no `inflight` map). Command latency then unavailable, reported |
| struct/inlining drift in future kernels | runtime planner, CO-RE `field_exists`, matrix CI, F4 rule |
| sock_diag cost with many sockets | in-kernel bytecode filter on NVMe/TCP endpoints |
| head vs path semantics confusion (F7) | explicit device kinds and metric names |
| kTLS, polled queues, data digests on 6.17 | detected and flagged; detailed staging marked unsupported until validated |
| validation against real Rocky 9/Ubuntu NVMe/TCP hardware | VM matrix + read-only observation on lab hosts (D-4) |
| licence compatibility of BPF vs userspace | decision D-1; BPF GPL-compatible; no copied ntprof code |

## 8. Decisions

| Id | Decision | Status |
|---|---|---|
| D-1 | Licence | **Decided (2026-11-13):** userspace MIT; BPF sources `Dual MIT/GPL` (GPL-compatible as the kernel requires) |
| D-2 | Integration test environment | dedicated VMs (KVM) when the harness is built. The harness refuses the development host (pre-existing controllers); scoped fault injection runs there via `tools/faultinject/` (authorized 2026-11-13) |
| D-3 | Rust toolchain on the development host | **Done:** user-local rustup, stable 1.100.0 |
| D-4 | Extra real NVMe/TCP hosts | deferred |
| D-5 | Prometheus listener | **Decided:** `nvmetea serve` requires `--listen ADDR:PORT`; there is no default port |
| D-6 | Continuous-mode default level | **Provisional: Level 1 + Level 3 continuous; Level 2 on demand** (`profile`, `record --sample`, TUI `p`). After the slot redesign, Level 1 costs 362 ns per command of program run time, against the 0.5 µs budget. Final once the §6 QD1 benchmark runs in a VM |
| D-7 | Version control / GitHub | **Deferred** by request |

### 8.1 Current focus (2026-11-13)

Development and validation target **Rocky Linux 9 on the development host's 6.12 el9
kernel** first, then the stock Rocky 9 5.14 kernel. Ubuntu 22.04/24.04 and other
kernels follow later. The design keeps them in scope; only the validation order
changes. Runtime claims in `kernel-compatibility.md` stay limited to what has been
validated.
