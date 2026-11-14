# nvmetea — Architecture

Status: Phase 0 deliverable. Last updated 2026-11-13.

Companion documents: `kernel-compatibility.md` (what each kernel offers; probe ids
P*/D*/T*/L*), `latency-model.md` (boundaries, stages, accounting rules),
`implementation-plan.md` (phases, acceptance tests, budgets).

## 1. Scope

nvmetea is a read-only observability tool for Linux NVMe/TCP initiators. It runs on
Rocky Linux 9 and on Ubuntu 22.04 and 24.04 (GA and HWE kernels). It works without
eBPF at a reduced level. With eBPF it attributes command latency to controllers,
queues, CPUs and TCP connections. Out of scope for v1: NVMe/RDMA, SPDK, target-side
instrumentation, vendor APIs, and any action that changes storage or network
configuration.

## 2. Overview

```
                ┌─────────────────────────── collectors (independent, disableable) ───────────────────────────┐
 sysfs, uevents │ Topology ──┐   /proc/diskstats │ BlockStats ──┐   BPF L1 │ NvmeCore ─┐   BPF L2 │ NvmeTcp ─┐ │
                │            │                   │              │          │           │          │          │ │
 sock_diag,     │ Tcp ───────┤   /proc/self      │ SelfStats ───┤          │           │          │          │ │
 iter/tcp, T*   │            │                   │              │          │           │          │          │ │
                └────────────┼───────────────────┼──────────────┼──────────┼───────────┼──────────┼──────────┘ │
                             ▼                   ▼              ▼          ▼           ▼          ▼            │
                       ┌───────────────────────── Correlation engine ─────────────────────────┐                │
                       │ identities & generations, queue↔socket join, record reconstruction   │                │
                       └──────────────────────────────────┬───────────────────────────────────┘                │
                                                          ▼                                                    │
                       ┌─────────────────────────── Telemetry engine ─────────────────────────┐                │
                       │ cumulative → interval deltas, histograms, windows, events, quality   │                │
                       └──────────────────────────────────┬───────────────────────────────────┘                │
                                                          ▼  Arc<Snapshot> (lock-free publish)
             ┌──────────────┬──────────────┬──────────────┼──────────────┬──────────────┐
             ▼              ▼              ▼              ▼              ▼              ▼
            TUI         CLI tables     JSON capture    compare      Prometheus     probe report
```

Every presentation reads the same `Snapshot`. None of them triggers collection or
reads kernel state itself.

## 3. Workspace layout

```
nvmetea/
├── Cargo.toml                  workspace
├── bpf/                        kernel-side C (CO-RE), shared headers
│   ├── kernel_types.h          minimal preserve_access_index declarations (no vmlinux.h)
│   ├── nvmetea.h               shared record/key/counter layouts (C and Rust via bindgen-free mirror)
│   ├── hist.bpf.h              log-linear bucket function (shift ladder, no clz)
│   ├── core.bpf.c              Level 1: P1–P9 (nvme-core, block, lifecycle)
│   ├── tcp_driver.bpf.c        Level 2: D1–D13
│   └── tcp_sock.bpf.c          Level 3: T1, T3–T6
├── crates/
│   ├── nvmetea-core/           model, units, quality, histogram, telemetry engine, events
│   ├── nvmetea-topology/       sysfs, diskstats, uevent parsing and reconciliation
│   ├── nvmetea-tcp/            sock_diag client, /proc/net/tcp fallback, tcp_info decoding
│   ├── nvmetea-bpf/            build.rs (compile + embed), planner, loader, BPF collectors
│   ├── nvmetea-profile/        per-command stage reconstruction, grouping, LAD
│   ├── nvmetea-export/         JSON capture/compare, Prometheus exposition + HTTP
│   ├── nvmetea-tui/            Ratatui views
│   └── nvmetea-cli/            `nvmetea` binary: argument parsing, wiring
├── tests/{fixtures,loopback}/
├── tools/feasibility/          Phase 0 spikes and offline kernel inspection
├── docs/
└── packaging/{rpm,deb,systemd}/
```

Dependency rules, enforced by `cargo deny`-style checks in CI:
- `nvmetea-core` depends on nothing internal.
- Collectors (`topology`, `tcp`, `bpf`) depend on `core` only.
- `profile` depends on `core` only. It is pure logic and testable without BPF.
- Presentation (`export`, `tui`) depends on `core` (and `profile` for its types) and
  **never** on collector crates. Backend structures stay out of the presentation
  layer.
- `cli` is the only crate that wires collectors to presentation.

Eight crates follow the specification's recommended split. Each has a distinct test
surface. `profile` stays separate from `core` because stage reconstruction is the
largest pure-logic unit and has its own fixtures.

## 4. Telemetry model (`nvmetea-core`)

### 4.1 Units and values

- Newtypes carry units: `Nanos(u64)`, `Bytes(u64)`, `Count(u64)`, `Ratio(f64)`, `Cpu(u32)`.
  Conversions to seconds etc. happen only in presentation.
- Every exported quantity is an `Observation<T>`:

```rust
pub struct Observation<T> {
    pub value: Option<T>,          // None ⇔ unavailable; never a zero stand-in
    pub quality: Quality,          // Measured | Derived | Estimated | Unavailable(Reason)
    pub sources: SourceSet,        // probe ids / files the value came from
    pub samples: Option<u64>,      // records behind a distribution or mean
}
```

- `Reason` is the stable reason-code enum from `kernel-compatibility.md` §6.3.

### 4.2 Identities

| Entity | Logical key | Display name | Generation |
|---|---|---|---|
| Host | hostname + `boot_id` | hostname | per boot |
| Subsystem | subsystem NQN | `nvme-subsysN` | n/a (NQN is stable) |
| Controller | (subsystem NQN, transport, traddr, trsvcid, host_traddr, host_iface) | `nvmeN` | **controller generation** (new `nvme_ctrl` object) and **connection epoch** (each entry to LIVE) |
| Queue | (controller, generation, qid) | `nvmeN/qK` | sockets change per epoch |
| TCP connection | socket cookie (unique per boot) | `laddr:lport→raddr:rport` | one per (queue, epoch) |
| Namespace | (subsystem NQN, NSID, NGUID/UUID/EUI-64 when present) | `nvmeXnY` | |
| Path | (namespace, controller) | `nvmeXcYnZ` | follows the controller |

`nvmeN` is a display name only. When a controller disappears, its record moves to
*history* with its final counters and transition log. A later controller that gets
the same name starts a new generation. Its counters never continue the old ones.

### 4.3 Snapshot

```rust
pub struct Snapshot {
    pub seq: u64, pub taken: Instant, pub wall: SystemTime, pub interval: Nanos,
    pub host: HostInfo, pub capabilities: CapabilityReport,
    pub topology: Topology,                    // subsystems, controllers, namespaces, paths, queues
    pub block: BTreeMap<DeviceKey, BlockStats>,
    pub nvme: NvmeStats,                       // per controller/queue/op counters + histograms
    pub driver: Option<DriverStats>,           // worker, send-context, stage histograms
    pub tcp: BTreeMap<QueueKey, TcpStats>,     // and unassociated NVMe/TCP sockets
    pub quality: QualityCounters,              // lost, partial, mismatch, map pressure, …
    pub events: EventCursor,                   // new events since previous snapshot
    pub overhead: SelfStats,
}
```

Snapshots are immutable and published with `arc-swap`. Readers never block the
sampler.

### 4.4 Histograms

One histogram type serves BPF, userspace windows, JSON and Prometheus:

- Log-linear: values in ns. Bucket 0 is `< 256 ns`. Then 8 linear sub-buckets per
  power of two from 2^8 ns to 2^36 ns (≈ 68.7 s). The last bucket is overflow. That
  is 226 buckets, stored in 232 slots.
- Bucket width is at most 12.5 % of its lower edge. The index is computed in BPF with
  a shift ladder. `__builtin_clzll` crashes the BPF backend (nfsview commit 42182f8).
- **Percentile estimator**: the upper edge of the bucket containing rank
  ⌈p·N⌉. That is a conservative estimate with ≤ 12.5 % overstatement. It is labelled
  `derived` with `resolution = 12.5%` in every output.
- With N = 0 a percentile is `None` (unavailable), never 0. With N below a minimum
  (default 20 for p99, 200 for p99.9), it is shown with a `low-sample` marker.
- Windows (1 s, 10 s, 60 s, whole capture) are exact bucket-wise differences of
  cumulative histograms. Nothing is ever reset.

## 5. Collectors

Each collector implements:

```rust
pub trait Collector: Send {
    fn id(&self) -> CollectorId;
    fn plan(&mut self, caps: &Capabilities) -> CollectorPlan;      // chosen backend + reasons
    fn start(&mut self) -> Result<(), CollectorError>;
    fn sample(&mut self, now: Instant, out: &mut SampleSink) -> Result<(), CollectorError>;
    fn stop(&mut self);
}
```

The sampler calls `sample` on each enabled collector every tick. A panic is caught
with `catch_unwind`. An error marks that collector `Degraded`/`Failed` with a reason
and exponential retry backoff. Other collectors keep running, and a failed collector
never stops the process.

| Collector | Inputs | Cadence | Output |
|---|---|---|---|
| Topology | sysfs allow-list (§6.2), uevents (L2), BPF lifecycle events (L3/P9) | events + reconcile every tick (cheap) and full rescan every 10 s | inventory, states, transitions, generations |
| BlockStats | `/proc/diskstats` (fallback `/sys/block/*/stat`), `inflight` | every tick | per head/path device cumulative counters |
| NvmeCore (L1) | BPF `core.bpf.c` maps + ring buffer | maps every tick; ring buffer continuously | per (ctrl, gen, qid, op) counters, histograms, inflight, events |
| NvmeTcp (L2) | BPF `tcp_driver.bpf.c` | as L1 | send context, worker stats, stage histograms; profile records |
| Tcp (L3) | sock_diag every tick (only NVMe/TCP endpoints); `iter/tcp` on topology/epoch change and every 30 s; T3–T6 events | every tick | per-socket `tcp_info`, queue association, transport events |
| SelfStats | `/proc/self/{stat,status}`, BPF map occupancy, `bpf_prog_info` run time (if `kernel.bpf_stats_enabled=1`, never set by nvmetea) | every tick | overhead and pressure |

## 6. Topology collector

### 6.1 Sources and reconciliation

Primary source is direct sysfs inspection:
- `/sys/class/nvme-subsystem/nvme-subsysN/` → subsystem.
- Its `nvmeN` links → controllers.
- `nvmeXnY` → namespace heads (native multipath).
- `/sys/class/nvme/nvmeN/nvmeXcYnZ` → paths. With multipath disabled, a controller's
  namespaces are `nvmeNnY` directly.

`nvme list-subsys -o json` is used only by tests as an independent cross-check and
is never required at run time.

Change detection works in three layers. Missing layers are reported:
1. kobject uevents (`NETLINK_KOBJECT_UEVENT`, unprivileged): `add/remove/change` for
   the `nvme`, `nvme-subsystem` and `block` subsystems, `NVME_EVENT=connected`,
   `NVME_AEN=…`.
2. BPF L3 (`nvme_change_ctrl_state`) and P9 (`nvme_init_ctrl`/`nvme_uninit_ctrl`):
   every transition with an ns timestamp, including ones faster than the poll interval.
3. Reconciliation of sysfs every tick for `state` (one small read per controller) and
   a full rescan every 10 s. This is the correctness fallback. It records
   `transition_source = poll` and notes that shorter transitions may be missed.

### 6.2 Attribute allow-list

The topology collector reads only these attributes, as regular files, with a 4 KiB
read cap. No glob reads. No write-only nodes. No secrets:

- controller: `transport address state cntlid subsysnqn queue_count sqsize kato
  ctrl_loss_tmo reconnect_delay fast_io_fail_tmo numa_node hostnqn hostid model serial
  firmware_rev cntrltype dctype dev`
- subsystem: `subsysnqn subsystype iopolicy model serial firmware_rev`
- namespace/path: `nsid wwid uuid nguid eui csi size ana_state ana_grpid ro hidden
  queue/logical_block_size queue/iostats stat inflight dev`

**Never read:** `dhchap_secret`, `dhchap_ctrl_secret`, `tls_key`,
`tls_configured_key`, `tls_keyring`, `delete_controller`, `reset_controller`,
`rescan_controller`, or any file not on the list. Missing attributes are normal
(they vary by kernel and target). They become `Unavailable(missing_interface)` for
that field. ANA fields are `Unavailable(not_supported_by_controller)` when
`ana_state` is absent on every path, as on the development host's target.

Parsing is defensive. Unknown `address` keys are kept verbatim. Malformed values
produce a per-field error and never a panic. Device names are only used as path
components after validation against `^nvme[0-9]+(c[0-9]+)?n[0-9]+$` (and similar).
They are never passed to a shell.

### 6.3 Lifecycle model

Controller states are `new, live, resetting, connecting, deleting, deleting (noio),
dead`, plus `unknown` for values the kernel adds later. Each controller keeps a
bounded transition log (default 256 entries), with time, from, to, and source
(bpf/uevent/poll). Removed controllers move to history (default the last 64) with
their final counters, so a disappearing controller stays explainable after the fact.

## 7. BPF subsystem (`nvmetea-bpf`, `bpf/`)

### 7.1 Objects and dependencies

| Object | Programs | Requires | Shares maps with |
|---|---|---|---|
| `core` (L1) | P1–P9, L3 | vmlinux BTF + nvme_core module BTF (P1b text fallback otherwise) | — |
| `tcp_driver` (L2) | D1–D13 | `core` loaded; nvme_tcp module BTF | `core`: inflight, per-queue stats |
| `tcp_sock` (L3) | T1, T3–T6 | vmlinux BTF; nvme_tcp module BTF for T1's queue validation | `core`: queue keys |

Each object loads, verifies and attaches independently. Within an object,
individual programs are disabled (`set_autoload(false)`) when their attach point is
ineligible (rule F4), and the plan records which fallback replaced them.

### 7.2 Maps (all bounded; sizes computed at load from topology)

Let Q = Σ over NVMe/TCP controllers of `queue_count`, and D = Σ queue depths
(`(queue_count − 1) × (sqsize + 1) + 32`).

| Map | Type | Key → value | Size | On exhaustion |
|---|---|---|---|---|
| `inflight` | HASH (prealloc) | PDU address → setup time, start time, correlation id, ctrl key, qid, cid, op, bytes, CPU, flags, send stamps (~96 B) | clamp(2·D, 4 Ki, 256 Ki) | command untracked; `map_full{inflight}` += 1; totals still counted |
| `queue_stats` | HASH (prealloc) | (ctrl inst, gen, qid) → counters per op, inflight, high watermark + epoch, send-context counts, worker runs/elapsed | clamp(2·Q, 256, 16 Ki) | aggregated into the controller row, `map_full{queue_stats}` |
| `queue_hist` | HASH (prealloc) | (ctrl inst, gen, qid, op, metric) → u64[232] | clamp(2·Q·4, 1 Ki, 16 Ki) entries (≤ 30 MiB at the cap) | that series unavailable (reason `map_full`); controller aggregate still exact |
| `path_hist` | HASH (prealloc) | (dev_t, op) → u64[232] request latency | 2 × paths × 3 | as above |
| `stage_hist` | HASH | (ctrl inst, gen, op, variant, stage) → u64[232] | bounded by controllers × 64 | as above |
| `ctrl_gen` | ARRAY | ctrl instance → generation | 4096 | instance ≥ 4096: generation 0, flagged |
| `counters` | PERCPU_ARRAY | global totals and quality counters | 1 | — |
| `events` | RINGBUF | lifecycle, errors, timeouts, slow-command records, profile records | 4 MiB default (`--ringbuf-size`) | reserve failure: `events_lost{kind}`; never blocks |
| `rx_ctx`, `send_ctx`, `iow_ctx` | PERCPU_ARRAY | per-thread context tagged with tid | 1 | context lost, not misattributed (ntprof's technique) |
| `detail` (profile) | HASH | PDU address → extended stage record | `--profile-slots` (16 Ki) | sample skipped, counted |

- The kernel maps total ≈ 1–2 MiB on the development host (54 queues). The defaults
  cap the total at < 64 MiB on very large hosts. The plan prints the computed sizes.
- Histogram and counter maps are updated with `__sync_fetch_and_add` in shared
  (non-per-CPU) values. Per-CPU copies would multiply memory by the CPU count (128 on
  the development host). Contention is naturally partitioned by queue, because a
  queue's completions run on few CPUs. Global hot counters are per-CPU.
- **No destructive reads.** Userspace never zeroes maps. It reads cumulative values
  (batch lookup where supported) and differences them. High watermarks use an epoch
  number that userspace advances. BPF resets a watermark when it sees a new epoch.
- **Cleanup.** Map entries of removed controller generations are deleted by
  userspace after a final read, once the controller has been gone longer than the
  grace period (it cannot receive new I/O under that generation).

**As built (Level 1 redesign, 2026-11-13).** The in-flight store and the
per-queue maps differ from the table above. The cost and the reasons are in
`docs/validation/phase-3-driver.md` ("Level 1 redesign").

| Map | Type | Key → value | Size |
|---|---|---|---|
| `slots` | ARRAY | `region base + rq->tag` → {PDU address key, in-flight record} (80 B) | clamp(1.25·D + 4 Ki, 8 Ki, 512 Ki): ≤ 40 MiB |
| `tag_regs` | HASH | NVMe queue (`ctrl instance << 32 \| qid`) → {region base, depth, queue index} | 2 Ki |
| `hctx_regs` | LRU_HASH | hctx address → {request queue, epoch, controller instance, region, queue index, qid, path dev_t} (read-mostly cache) | 4 Ki |
| `requeued` | HASH | PDU address → in-flight record, between a requeue/retry (tag released) and the next dispatch | 4 Ki |
| `qinfo` | ARRAY | queue index → {ctrl instance, qid} | clamp(Q + 64, 128, 16 Ki) |
| `qstats` | ARRAY | queue index → counters per op, in-flight, high watermark + epoch | as `qinfo` |
| `qhist` | ARRAY | queue index × 20 + op × 4 + metric → u64[232] | min(`qinfo`, 903) × 20: ≤ 32 MiB. Queues beyond it count `map_full{hist}` |

Notes:
- **Regions.** A region is allocated from an atomic cursor the first time a
  queue is seen. Regions are keyed by NVMe queue, so resets, reconnects and a
  recreated controller with the same instance reuse them.
- **qid.** It is derived from the tag set (admin tag set → 0, otherwise
  hardware queue + 1), so the fabrics connect queue's Connect commands are
  attributed to the I/O queue they run on.
- **Exhaustion** of slots or queue indices is counted in
  `map_full{inflight|qstats}`. The command is then counted, but not timed.
- **Concurrency.** Slots are published and freed by atomic exchange of the key.
  Completion paths only read registrations, never create them.
- **Generations.** Userspace reads `qinfo[0..next_queue]` and sums by
  (instance, qid). Generations are still userspace-side (P9 deferred).
- **Memory.**
  - The development host: 0.6 MiB of slots and 4.6 MiB of queue histograms.
  - 64 controllers × 32 queues at depth 128: ≈ 58 MiB in total.
  - The bounds are checked by a unit test (`map_sizes_are_bounded`).

### 7.3 Programs: data flow per command (continuous mode)

1. P1 (`raw_tp/nvme_setup_cmd`) runs when `armed` is set. It derives the PDU address
   and applies the TCP test (F18). It reads ctrl instance, gen (`ctrl_gen`), qid
   (queue index), cid, genctr, opcode, bytes and `start_time_ns`. Then it applies the
   `.rodata` filters (controller set, nsid, op), inserts into `inflight`, and bumps
   the queue counters.
   - Existing entry for the same address: if `retries` increased, it is a retry
     (keep the original start, set `RETRIED`). Otherwise it is stale (count it,
     replace it).
   - AER commands are counted but not inserted.
2. L2 send hooks (D1/D2/D6) add `E_IOW_TX`/`E_CMD_SENT` and the send context to the
   entry.
3. D9 (`blk_mq_complete_request_remote`, filtered by the same TCP test on the request)
   adds `E_RSP_PARSED`.
4. P2 (`raw_tp/nvme_complete_rq`) validates the cid, records status and retries, adds
   to the command-latency histogram and error counters, and stamps `E_NVME_DONE`. If
   the disposition will be retry or failover (status + flags), it marks the entry
   instead of finishing it.
5. P3 (`raw_tp/block_rq_complete`) computes request latency and stage values and
   updates the histograms. It emits a slow-command record if latency exceeds the
   threshold (rate-limited), then deletes the entry.

Continuous mode stage histograms: A, B1, B2, **C+D (driver round trip, not split)**,
E1, E2. Splitting C from D needs the per-skb receive hooks (D7/D8/D10). Those run in
profile mode only, on sampled commands.

### 7.4 Profile mode

Explicit `nvmetea profile`. It adds D7, D8, D10, D11 (and `--rx-timestamps`
optionally) and per-command `detail` records for sampled commands. Sampling is
1 in N (`--sample N`, default 100) by `bpf_get_prandom_u32()`, or every command
(`--sample 1`). Optional filters are controller, queue, nsid, op, and size range.
Detail records go out over the ring buffer when the command completes. Timestamp-only
hooks return after one global check while no sampled command is in flight (ntprof's
`inflight` shortcut). Unsampled commands still update every total and histogram.

**As built (Phase 3 part 2, 2026-11-13).**
- **Objects.** `bpf/tcp_driver.bpf.c` is a separate object loaded beside Level 1.
  It has its own raw tracepoints on `nvme_setup_cmd`, `nvme_complete_rq` and
  `block_rq_complete` for the sampled records; Level 1 keeps the totals.
- **Flavours.** Every function hook exists as kprobe/kretprobe and as
  fentry/fexit. Both read arguments as scalars (`bpf_get_func_arg` for fentry), so
  all dereferences are CO-RE reads.
  - `--flavour auto`, the default, uses fentry only after the attach preflight
    (§8 of `kernel-compatibility.md`) passes.
  - If the fentry object fails to load or attach, nvmetea falls back to kprobes
    and says so.
  - An optional program that fails verification is dropped and the object is
    reloaded. The verifier's reason is reported, and the boundaries that program
    provided merge (rule R2).
- **Hot gating, two levels.** A global count of sampled commands in flight is
  checked first. Then a per-queue count, kept in the queue's notification-ring
  entry, means that receive-path hooks do nothing on queues without a sampled
  command.
- **Per-thread contexts.** These are per-CPU slots tagged with the thread id. The
  send context is not inferred from them: B1/B2 split at the entry of the first
  send attempt, and direct-vs-worker comes from the task's `PF_WQ_WORKER` flag.
  (io_work runs on one CPU can interleave when one sleeps on the socket lock.)
- **Worker accounting (D6).** Every io_work run is counted per queue: runs,
  elapsed time, runs that used the 1 ms quota, longest run.
- **`--bpf-stats`.** Holds `BPF_ENABLE_STATS` for the run. It reports per-program
  run time and recursion misses, and nvmetea's BPF time per completed command.
- **Output.** Per variant and size class: a stage table over complete records
  (shares add up to 100 %), the per-controller family means, the queues with the
  most local time, the slowest commands' timelines, worker stats, and a Level 1
  cross-check of the sampled means.
- **Not yet built:**
  - `--rx-timestamps`;
  - D11 (on-CPU worker time);
  - D13 (polled queues);
  - filters other than `--controller`;
  - continuous-mode stage histograms;
  - `record`/`compare`.

### 7.5 Slow-command events

Threshold: `--slow` (fixed), or adaptive by default. Adaptive means max(1 ms, p99.9
of the last 60 s per controller × op), pushed into a BPF map every 10 s. A per-CPU
token bucket limits emission (default 200 events/s total). Suppressed events are
counted. A record carries every boundary the continuous hooks saw, plus queue, CPU,
`io_cpu`, socket cookie, size, op and status. Userspace enriches it with the socket's
`tcp_info` and with retransmission events on that socket within ±50 ms.

## 8. Correlation and telemetry engines

- **Queue↔socket.** T1 produces (cookie, 4-tuple, ctrl inst, gen, qid, io_cpu, flags).
  sock_diag produces (cookie → `tcp_info`). The join is on the cookie, verified by
  4-tuple. A sock_diag dump always runs before the iterator, so that every NVMe/TCP
  socket has a cookie (F12). Without T1, sockets are associated to a controller only
  when (src_addr, traddr, trsvcid) matches exactly one controller. Queue association
  is then `Unavailable(dependency_unavailable)`.
- **Generations.** Per-queue series are keyed with the controller generation. An
  epoch change (reconnect) closes all socket series of that controller and opens new
  ones.
- **Deltas.** rate = Δvalue / Δt, with Δt from `Instant`. If a cumulative value
  decreases, or the generation/epoch changed, that interval's rate is `None` with
  reason `counter_reset`. It is never negative or zero-filled. The first interval
  after start has no rate.
- **History.** A ring buffer of interval summaries per entity (default 900 points).
  An event log (default 10 000 entries) of state transitions, errors, timeouts,
  failovers, slow commands, capability changes and collector failures.
- **Pause/reset baseline (TUI `Space`/`r`).** Pause freezes the displayed snapshot
  while collection continues. Reset baseline moves the display origin of cumulative
  views. Neither touches kernel state.

## 9. Output formats

### 9.1 `nvmetea probe --json`

```json
{ "schema": "nvmetea.probe/1", "tool": {"version": "…"}, "host": {…},
  "privileges": {"effective_caps": […], "lockdown": "integrity", …},
  "btf": {"vmlinux": true, "modules": {"nvme_tcp": "present", …}},
  "probes": [{"id": "D1", "target": "nvme_tcp_try_send_cmd_pdu", "flavour": "fexit",
              "status": "supported|unavailable|failed", "reason": "inlined", "detail": "…"}],
  "plan": [{"family": "nvme_command_latency", "backend": "P1+P2 raw_tp",
            "fallback": "P1b+P2b tracepoint", "quality": "measured"}] }
```

### 9.2 Capture (`nvmetea record`)

`schema: "nvmetea.capture/1"` (semver on the schema; readers refuse unknown major
versions and ignore unknown fields). Contents:
- tool version and BPF object hashes;
- host (hostname, `boot_id`, kernel release, distribution, architecture);
- capability report and plan (the **boundary signature** of each stage);
- filters, start/end wall and monotonic times, interval;
- topology at start and end, plus transitions during the capture;
- per-interval summaries (rates, inflight, TCP gauges);
- cumulative histograms at start and end (exact window histograms by subtraction);
- per-stage aggregates with complete/partial counts;
- events; quality counters (lost, partial, mismatch, untracked, map pressure);
- self overhead.

The full schema is written as `docs/schema/capture-v1.md` in Phase 4, with a JSON
Schema file validated in tests.

### 9.3 `nvmetea compare`

Groups are matched by (controller logical key | namespace key, op, protocol
variant, size class). It reports:
- IOPS/throughput ratio and Δ%;
- percentile changes;
- stage mean changes and LAD (`latency-model.md` §12);
- queue-imbalance changes;
- error/retransmission deltas;
- controller/path state differences.

Non-comparable stages print `not comparable: <reason>`. Like nfs-gaze, ratios are
shown with a "better/worse" direction and absent values as `-`. Unlike nfs-gaze,
every group of both files is compared, not just the first, and the schema version is
checked.

## 10. Prometheus exposition (`nvmetea serve`)

- Plain-text exposition (format 0.0.4), hand-written from the snapshot. A scrape
  never triggers collection. A scrape older than 3 × interval sets
  `nvmetea_snapshot_age_seconds`.
- `nvmetea serve` requires `--listen ADDR:PORT`. There is no default port, which
  avoids colliding with node_exporter's 9100. The documentation examples use
  `127.0.0.1`, and binding a non-loopback address prints a warning. Endpoints are
  `/metrics` and `/healthz`. A bind failure is a startup error.
- Label cardinality is bounded:
  - at most `--prom-max-controllers` (64) and `--prom-max-queues` (128 per
    controller); overflow series go to `qid="other"` and increment
    `nvmetea_prom_series_dropped_total`;
  - no command ids, pointers, cookies, ports or per-event values as labels;
  - per-path and per-queue histograms are opt-in (`--prom-path-latency`,
    `--prom-queue-histograms`).
- Histogram `le` boundaries are a fixed subset of the internal bucket edges (two per
  octave, 1 µs … 68 s). Exported buckets are therefore exact sums of measured
  buckets.

| Family | Type | Labels | Source |
|---|---|---|---|
| `nvmetea_build_info` | gauge | version, bpf | — |
| `nvmetea_collector_up` | gauge | collector | engine |
| `nvmetea_capability_status` | gauge | capability, status, reason | planner |
| `nvmetea_snapshot_age_seconds` | gauge | — | engine |
| `nvmetea_subsystem_info` | gauge | subsystem_nqn, subsystem, iopolicy | sysfs |
| `nvmetea_controller_info` | gauge | controller, subsystem_nqn, transport, traddr, trsvcid, host_traddr | sysfs |
| `nvmetea_controller_state` | gauge (state set) | controller, state | sysfs/L3 |
| `nvmetea_controller_state_transitions_total` | counter | controller, to_state | L3/uevent/poll |
| `nvmetea_controller_generation` | gauge | controller | P9/userspace |
| `nvmetea_controller_queues` | gauge | controller, type | sysfs |
| `nvmetea_controller_queue_depth` | gauge | controller | sysfs |
| `nvmetea_controller_keepalive_latency_seconds` | histogram | controller | P1/P2 |
| `nvmetea_namespace_info` | gauge | namespace, subsystem_nqn, nsid, wwid | sysfs |
| `nvmetea_path_info` / `nvmetea_path_usable` | gauge | path, namespace, controller | sysfs |
| `nvmetea_path_ana_state` | gauge (state set) | path, state | sysfs (only when supported) |
| `nvmetea_block_ios_total` / `_bytes_total` / `_time_seconds_total` | counter | device, op | diskstats |
| `nvmetea_block_inflight` | gauge | device, direction | diskstats |
| `nvmetea_nvme_commands_total` / `_bytes_total` | counter | controller, op | P1/P2 |
| `nvmetea_nvme_errors_total` | counter | controller, op, status_class | P2 |
| `nvmetea_nvme_retries_total`, `_failovers_total`, `_cancellations_total`, `_timeouts_total` | counter | controller | P2/P4–P7/D12 |
| `nvmetea_nvme_command_latency_seconds` | histogram | controller, op | P1/P2 |
| `nvmetea_request_latency_seconds` | histogram | controller, op (+namespace opt-in) | P1/P3 |
| `nvmetea_stage_latency_seconds` | histogram | controller, op, stage | L2 (continuous stages) |
| `nvmetea_queue_commands_total` / `_bytes_total` | counter | controller, qid, op | P1 |
| `nvmetea_queue_inflight` / `_inflight_max` | gauge | controller, qid | P1/P2 |
| `nvmetea_queue_latency_seconds` (`_sum`, `_count`) | summary, no quantiles | controller, qid, op | P1/P2 (histogram opt-in) |
| `nvmetea_queue_sends_total` | counter | controller, qid, context=direct\|deferred | D1 |
| `nvmetea_queue_worker_runs_total` | counter | controller, qid | D6 |
| `nvmetea_queue_worker_seconds_total` | counter | controller, qid, kind=elapsed\|oncpu | D6/D11 |
| `nvmetea_queue_io_cpu` | gauge (-1 = unbound) | controller, qid | T1/P1 |
| `nvmetea_tcp_rtt_seconds`, `_rtt_variance_seconds`, `_min_rtt_seconds`, `_rto_seconds` | gauge | controller, qid | sock_diag |
| `nvmetea_tcp_retransmitted_segments_total`, `_retransmitted_bytes_total` | counter | controller, qid | sock_diag |
| `nvmetea_tcp_bytes_sent_total` / `_received_total` | counter | controller, qid | sock_diag |
| `nvmetea_tcp_unacked_segments`, `_lost_segments`, `_cwnd_segments`, `_ssthresh_segments` | gauge | controller, qid | sock_diag |
| `nvmetea_tcp_send_queue_bytes`, `_receive_queue_bytes`, `_notsent_bytes` | gauge | controller, qid | sock_diag |
| `nvmetea_tcp_limited_seconds_total` | counter | controller, qid, reason=busy\|rwnd\|sndbuf | sock_diag |
| `nvmetea_tcp_congestion_events_total`, `_resets_total` | counter | controller, qid | T5/T6 |
| `nvmetea_bpf_events_lost_total` | counter | kind | BPF |
| `nvmetea_bpf_map_entries` / `_capacity` / `_full_total` | gauge/counter | map | BPF |
| `nvmetea_records_total` | counter | outcome=complete\|partial\|mismatch\|untracked\|order_violation | BPF/engine |
| `nvmetea_bpf_program_run_seconds_total` | counter | program | `bpf_prog_info` (when stats enabled) |
| `nvmetea_process_cpu_seconds_total`, `nvmetea_process_resident_memory_bytes` | counter/gauge | — | /proc/self |

A metric whose source is unavailable is **absent** from the exposition. It is not
exported as 0. Its absence is explained by `nvmetea_capability_status`.

**As built (Phase 4).**
- **Renderer:** `crates/nvmetea-export/src/prom.rs`; the command is `nvmetea serve`.
  The main thread samples and renders every `--interval` (5 s); a `tiny_http`
  thread serves the latest text and appends `nvmetea_snapshot_age_seconds` at
  scrape time.
- **`/healthz`** returns 503 when the snapshot is older than 3 × the interval.
- **Families implemented:**
  - build/collector/capability status, snapshot age;
  - subsystem, controller (info, state set, generation, epoch, queues, depth,
    transitions), namespace and path (info, usable, ANA);
  - block I/O, time and in-flight;
  - NVMe commands, bytes, errors (by op and by status type), retries,
    failovers, requeues;
  - command and request latency histograms per controller × op;
  - queue commands, bytes, in-flight, max, latency sum/count;
  - with Level 3: queue `io_cpu` and per-queue TCP gauges and counters
    (`tcp_info`), plus BPF transport-event counters;
  - BPF lost-event, map-full and record-outcome counters;
  - process CPU and RSS;
  - `nvmetea_prom_series_dropped`.
- **Not yet exported:** keep-alive latency, cancellation and timeout counters,
  stage histograms (continuous Level 2 is not built), send-context and worker
  counters, map entry/capacity gauges, program run time, and the opt-in per-path
  and per-queue histograms.

## 11. CLI and TUI

### 11.1 Commands

| Command | Purpose | Needs |
|---|---|---|
| `nvmetea` | TUI | L0; more with BPF |
| `nvmetea top` | refreshing one-screen summary (non-TUI) | L0+ |
| `nvmetea status` | controller/subsystem health, recent transitions | L0 |
| `nvmetea topology` | subsystem/namespace/path inventory | L0 |
| `nvmetea controllers`, `queues`, `tcp` | tables (`--json`, `--interval`); `queues --op/--queue` | L0/L1/L3 |
| `nvmetea probe [--load] [--json]` | capability discovery and plan; `--load` loads, attaches, samples 1 s and detaches the Level 1 collector | — |
| `nvmetea profile --duration 30s [--sample N] [filters] [--rx-timestamps] [-o file]` | sampled per-command timelines and stage breakdown | L1+L2 |
| `nvmetea record --duration 300s -o capture.json` | capture | L0+ |
| `nvmetea compare a.json b.json` | comparison, LAD | — |
| `nvmetea serve --listen addr:port` | Prometheus (`--listen` required; no default port) | L0+ |

Filters on every data command: `--subsystem <NQN|suffix>`, `--controller nvmeN|traddr`,
`--namespace nvmeXnY|NSID|WWID`, `--queue N`, `--op read|write|flush|admin`,
`--endpoint addr[:port]`. Names are resolved through the topology. Errors explain
what failed and what telemetry that affects, for example: *"BPF unavailable
(permission_denied): showing diskstats aggregates; latency percentiles disabled"*.

### 11.2 TUI

Tabs: Overview, Subsystems, Controllers, Queues, Latency, Breakdown, TCP, Events,
Help. Keys follow the specification: `q`, `h/l`/←/→, `j/k`/↑/↓, `Enter`, `Esc`,
`Space`, `r`, `s`, `f`, `?`, `+/-`. Following nfsview's layout:
- One sampler thread and a UI thread that polls input at 80 ms.
- A full-frame background fill.
- A status line that **persists** collector warnings (nfsview's load error vanished
  after one tick).
- A terminal-restoring panic hook.

Unavailable values render as `-`. Selecting one shows the reason in the detail panel.
Estimated values carry a `~` prefix. Low-sample percentiles are dimmed with a sample
count. Breakdown shows the stage table (means over complete records with share %),
per-stage percentile tables, rolling trends, and the selected slow command's
timeline with its queue, endpoint and nearby TCP symptoms. The combined
remote/transport row is always labelled as such.


**As built (Phase 4).**
- **Crate and command.** `crates/nvmetea-tui` (model, app, ui, term) renders
  `View`s built by `crates/nvmetea-cli/src/cmd/tui.rs`. `nvmetea` with no
  subcommand on a terminal starts it; when piped or with `--json` it prints
  `status`.
- **Threads.** The sampler thread owns the collectors (created in that thread),
  samples every interval (2 s, adjustable 0.25–60 s with `+`/`-`), and keeps a
  1,000-event log.
- **Breakdown tab.** It needs Level 2. `p` starts stage profiling at 1 in 100
  (fentry after the preflight) and `r` resets the aggregates. It shows the stage
  table of the largest variant group, per-queue family means, and the timeline
  of the selected slowest command as a coloured family bar plus a stage list.
- **Keys.** `s` sorts by the next column (unit-aware); `f` cycles the controller
  filter; Space freezes the display while sampling continues.
- **Testing.** `nvmetea __tui-snapshot [--profile]` (hidden) renders every tab as
  text from a live sample, for testing without a terminal.
- **Not yet built:** rolling trends; TCP symptoms next to the slow-command
  timeline (`top` has them); scrolling inside the Overview tables.

## 12. Runtime model

No async runtime. Threads and bounded `crossbeam-channel`s:

| Thread | Work |
|---|---|
| main | CLI/TUI; reads snapshots; sends control messages |
| sampler | ticks (default 1 s, adjustable 250 ms–60 s): collectors → correlation → telemetry → publish |
| events | `epoll` on BPF ring buffer fd(s) and the uevent socket; forwards to the engine through a bounded channel (overflow counted) |
| http (`serve`) | `tiny_http` blocking server rendering from the latest snapshot |
| attach pool (startup only) | parallel fentry attach (kernel-compatibility §8) |

Collectors never block the UI. The UI only ever reads the published snapshot.

## 13. Metric-to-source map

Fallbacks are listed in order. Class: M = measured, D = derived, E = estimated.
Unavailable values carry a reason.

| Metric family | Primary (probe) | Fallbacks | Class | Notes |
|---|---|---|---|---|
| subsystem/controller/namespace/path inventory | sysfs (L1 rescan) | — | M | ANA fields only if exposed |
| controller state, transitions | L3 BPF + uevents | sysfs poll | M | poll: transitions shorter than the interval may be missed (flagged) |
| controller generation / connection epoch | P9 + L3 | uevent/sysfs reconciliation | M | fallback: ≤ 1-interval attribution ambiguity on fast recreate (flagged) |
| keep-alive latency | P1/P2 admin 0x18 | — | M | |
| namespace/path IOPS, throughput | diskstats deltas | `/sys/block/*/stat` | D | namespace from head counters; Ubuntu 5.15: Σ paths (F7) |
| aggregate block service time | diskstats ticks | — | D | ms resolution; **no percentiles** |
| inflight per path device | `/sys/block/*/inflight` | diskstats field 9 | M | not per queue |
| commands/bytes per controller, queue, op | P1 counters (all commands) | diskstats (namespace/path level only) | M | |
| command latency distribution | P1+P2 | P1b+P2b text tracepoints | M (percentiles D) | |
| request latency distribution | P1(`start_time_ns`)+P3 | — | M (percentiles D) | unavailable when `start_time_ns = 0` |
| errors by status class, retries, requeues | P2, P4, P6 | P2 status/retries only | M | |
| failovers / cancellations / timeouts | P5 / P7 / D12 | P2 status inference | M (fallback D) | |
| outstanding per queue (+ high watermark) | P1/P2 tracked | — | M | excludes commands from before arming |
| mean queue occupancy | rate × mean latency | — | D | Little's law |
| stage A, B1, B2, E1, E2 | P1, D1/D2/D6, D9, P2, P3 | D5 for sends | M | |
| stage C+D (continuous) | D1 → D9 | P1 → P2 ("command latency") | M | not split in continuous mode |
| stage C1, D1 (profile) | D10 sequence-mapped notification (C upper / D lower bound); `skb->tstamp` with `--rx-timestamps` (exact) | merged C1+D1 when unresolved | M (bounded) | §5.4 of the latency model |
| READ data phase D2/C2 (profile) | D7+D8 | merged "unclassified receive" | M busy / D wait | |
| R2T write stages (profile) | D3/D4/D2 | merged | M | MULTI_R2T: not separable |
| worker runs, elapsed, CPU distribution, migration | D6 | — | M | |
| worker on-CPU | D6 + D11 | elapsed only (labelled) | D | includes irq time on that CPU |
| worker quota exhaustion | D6 elapsed ≥ 1 ms quota | — | E | |
| direct vs deferred sends, unsent | D1/D2 | — | M | |
| queue ↔ socket association | T1 iterator + cookie join | endpoint match (controller-level) | M / D | queue-level unavailable without T1 |
| RTT, RTT variance, min RTT, RTO, cwnd, ssthresh, unacked, lost, retrans, bytes, notsent, limited times | sock_diag `INET_DIAG_INFO` | `/proc/net/tcp`: queues + retransmit timer only | M | fields gated by `tcp_info` length (older kernels lack newer fields) |
| send/receive queue bytes, socket memory | sock_diag (`SKMEMINFO`) | `/proc/net/tcp` tx/rx queue | M | |
| retransmission events (timestamped) | T3 | Δ`tcpi_total_retrans` per interval | M | |
| TCP state changes, RSTs, congestion events | T4, T6, T5 | sock_diag polling / `tcpi_ca_state` | M | |
| transport symptoms near a slow command | slow record + T3 + sock_diag | interval-level only | D | correlation ≠ causation (shown as context) |
| lost events, map pressure, mismatches, partial/untracked records | BPF counters | — | M | |
| BPF program run time | `bpf_prog_info` (stats enabled by operator) | — | M | unavailable unless `kernel.bpf_stats_enabled=1` |
| nvmetea CPU / memory | `/proc/self` | — | M | |

## 14. Security and safety

- **Read-only.** No writes anywhere under `/sys`, `/proc/sys` or configfs. No
  `nvme-cli` invocations. No module loading by nvmetea. The probe reports whether a
  sock_diag query may autoload `inet_diag` on Ubuntu (F12).
- **Opt-in side effects.** The only kernel behaviour change is `--rx-timestamps`
  (profile mode). It is disclosed in output and captures.
- **No payload capture.** BPF reads command metadata (opcode, nsid, cid, length,
  status) and PDU headers (type, flags, command id). Data buffers, SGLs, keys and
  secrets are never read. Sysfs is read from the allow-list only (§6.2).
- **Network.** The listener is localhost by default. There is no outbound telemetry.
  No DNS lookups (nfsview blocked its sampler on DNS).
- **No shell.** No `std::process::Command` with user- or kernel-derived strings. The
  only child process is nvmetea re-executing itself for the fentry preflight.
- **Least privilege.** Level 0 runs unprivileged. After BPF setup, capabilities not
  needed for map access are dropped (`CAP_SYS_ADMIN`, `CAP_SYSLOG`, `CAP_NET_ADMIN`).
  `CAP_BPF` is kept because map syscalls need it when unprivileged BPF is disabled.
- **Robust parsing.** Fuzz targets cover sysfs, diskstats, `/proc/net/tcp`, netlink
  attributes and capture files. There is no `unwrap` on external input.

## 15. Resource bounds

| Resource | Bound (default) |
|---|---|
| BPF maps | computed from topology, capped < 64 MiB; printed in the plan |
| ring buffer | 4 MiB |
| per-command state | `inflight` map only. Entries are deleted at completion. Stale entries are replaced on reuse and counted |
| userspace history | 900 intervals × entities; 10 000 events; 64 removed controllers |
| capture size | ~O(duration/interval × entities) + 2 histogram snapshots per series |
| threads | ≤ 5 steady state |

Performance budgets and their measurement are in `implementation-plan.md` §6.

## 16. Build, packaging and licensing

- **BPF build.** `nvmetea-bpf/build.rs` compiles `bpf/*.bpf.c` with clang
  (`-target bpf -O2 -g`, CO-RE). It compiles once per target architecture
  (`__TARGET_ARCH_x86` / `arm64` for kprobe argument access) and generates skeletons
  with `libbpf-cargo`. The objects are embedded in the binary. Monitored hosts need
  no clang, bpftool, headers or Rust.
- **Linking.** libbpf, libelf and zlib come from `libbpf-sys` (vendored, static).
  The binary is built against glibc 2.34 (Rocky 9 build container), which also
  covers Ubuntu 22.04 (2.35) and 24.04. CI asserts the `ldd` output is limited to
  libc/libm/libgcc_s/ld-linux. Release targets are `x86_64` and `aarch64`, the latter
  built natively on ARM runners. A fully static musl build is not planned: nfsview
  found the vendored libbpf toolchain impractical with musl.
- **Packages.** RPM (Rocky 9) and DEB (Ubuntu 22.04/24.04), optional systemd unit
  for `serve` (with `AmbientCapabilities=CAP_BPF CAP_PERFMON`), man page and shell
  completions generated by clap.
- **Licensing.** Userspace is MIT. BPF programs must be GPL-compatible to use
  GPL-only helpers, so the BPF sources are `Dual MIT/GPL` (license section string
  `"Dual MIT/GPL"`). ntprof (GPL-2.0) is a design reference: its
  hook selection, the `sk_user_data` transport test, per-thread contexts and the
  receive-timestamp technique are credited in `NOTICE` and these documents. nvmetea's
  code is written from its own documented model and does not copy ntprof sources.
  nfs-gaze and nfsview (MIT) are credited for CLI/TUI patterns.
