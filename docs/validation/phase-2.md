# Phase 2 — Core eBPF latency (Level 1): validation record

Date: 2026-11-13. Host: the development initiator (Rocky Linux 9.6 userspace,
kernel 6.12.117-1.el9, 6 NVMe/TCP controllers × 8 I/O queues of depth 32).

All runs only observed traffic. The workload was an operator-provided 8 KiB random
read load (≈ 400k IOPS across 6 controllers); nvmetea generated no I/O.

## What was built

**`bpf/core.bpf.c`** (Dual MIT/GPL, CO-RE, no `vmlinux.h`):

| Program | Attach | Role |
|---|---|---|
| `nvt_setup_cmd` | `raw_tp/nvme_setup_cmd` | dispatch: TCP test (`ctrl->ops->name == "tcp"`), identity (instance, qid, cid, opcode, nsid, bytes, dev, CPU), in-flight entry, per-queue counters, high watermark |
| `nvt_complete_rq` | `raw_tp/nvme_complete_rq` | command-id validation, NVMe status (by status code type), command latency |
| `nvt_blk_complete` | `raw_tp/block_rq_complete` | request latency (queue and path histograms), stages A and E2, failover/error/retry classification, slow-command events |
| `nvt_requeue` | `raw_tp/block_rq_requeue` | requeue marker |
| `nvt_state_enter/exit` | `kprobe` + `kretprobe` `nvme_change_ctrl_state` | controller state transitions (old, new, accepted) |

Design points carried out from the architecture:
- **Raw tracepoints, not `tp_btf`** (finding F14).
- **No fentry in this phase**, so the RCU-tasks attach stall (F15) cannot occur.
- **Arming** happens only after every required program is attached.
- **Maps** are sized from the topology. They are never reset; userspace differences cumulative values.
- **AER commands** are excluded from in-flight counts and from latency.
- **Separate classes**: retried, requeued, failed-over and failed commands are counted but kept out of the latency histograms.
- **Histogram**: log-linear, 226 buckets, ≤ 12.5 % width.

**Userspace**:
- `nvmetea-bpf::core`: skeleton embedded at build time.
- Per-program attach status, with the three raw tracepoints required and the requeue and lifecycle programs optional.
- If the optional programs fail to load, the object is reloaded without them.
- libbpf and verifier logs are captured into the error.
- Ring buffer for events.
- `nvmetea-core::nvme_engine`: per-queue, per-controller and per-namespace interval statistics; exact means from ns sums; percentiles from interval histograms; generation-aware.

**CLI**:
- `nvmetea queues` (new);
- a latency table in `controllers`;
- latency, per-namespace p50/p99 and slow-command/state events in `top`, with an adaptive slow threshold (≥ 1 ms, about the interval's p99.9, rate-limited in BPF);
- `nvmetea probe --load` (load, attach, sample, detach);
- `--no-bpf`.

## Automated tests

`cargo test --workspace`: **78 passed, 0 failed**. `clippy -D warnings` and
`fmt --check` are clean.

New in this phase:
- **Histogram**: bucket vectors and bounds; contiguity and the ≤ 12.5 % width bound; an exhaustive edge check.
- **BPF ↔ Rust equivalence**: the C `nvt_bucket()` from `bpf/hist.bpf.h` is compiled natively into the test build and compared with the Rust mirror on every bucket edge and 1,000,000 pseudo-random values.
- **Engine**: rates, exact means, percentile ranges, the watermark epoch rule, generation reset, `dev_t` encoding.
- **CLI**: `queues`/`controllers`/`probe --load` without BPF report `disabled` and give no zero-filled latency. Tests always pass `--no-bpf`, so they never load programs onto the host kernel, even as root.

## Live results

| Check | Result |
|---|---|
| Load / attach | 22–40 ms load, 6–7 ms attach. All 6 programs attached, kprobes included |
| BPF completions vs diskstats completions, per controller, same interval (`controllers -i 5 --json`) | **0.001–0.004 %** difference on all 6 controllers |
| BPF mean request latency vs diskstats await, per controller | BPF **0.11–0.14 % lower** on every controller, a constant ≈ 1.6 µs. Expected: diskstats stops the clock later (`blk_account_io_done`) than the `block_rq_complete` tracepoint; both start at `rq->start_time_ns`. |
| Command-id mismatches / stale entries / map-full / lost events | 0 / 0 / 0 / 0 at ≈ 400k IOPS |
| Commands in flight at arming (`untracked_completions`) | ≈ 500 per start (≈ in-flight count), as designed |
| Per-queue view | imbalance across a controller's queues (e.g. 14.9k vs 4,979 IOPS); peaks of 30 in flight against a depth of 32. The same queue index is busiest on every controller (CPU → hctx mapping is identical across controllers and round-robin multipath spreads each thread across all of them) |
| Stage split for 8 KiB reads | A ≈ 1.3 µs, E2 ≈ 0.3 µs; command ≈ request (≈ 1.2–1.4 ms): the time is after dispatch |
| Slow-command events | delivered with per-command A / command / E2 split, submit → completion CPU, queue and nsid |
| Keep-alive (admin) command latency | ≈ 164 µs |
| Unprivileged run | `permission_denied` with remediation; sysfs queue inventory shown; JSON `bpf.state = "unavailable"` |
| Process termination (SIGTERM) while attached | 0 programs and 0 links remain afterwards |

## Defects found during live validation (fixed)

1. **CO-RE kind mismatch.** `nvme_ctrl.state` was declared `int`, but the kernel's
   field is `enum nvme_ctrl_state`, and libbpf refused the relocation. The verifier
   log was surfaced intact. Fixed by declaring the enum.
2. **One optional program failing took down the whole object.** The loader now
   reloads without the optional lifecycle programs and records why.
3. **Hidden multipath path disks have no sysfs `dev` attribute**, so per-namespace
   latency could not be mapped. Device numbers now come from `/proc/diskstats`
   (new finding, recorded in kernel-compatibility F19).
4. **Admin requests were counted as `start_missing`.** They never carry a block
   start time by design; only I/O requests are counted now.

## Not done in this phase (explicitly)

- **Text-tracepoint fallback (P1b/P2b)** for kernels without BTF. Every target
  kernel examined has BTF (kernel-compatibility §3.1). Without BTF, `nvmetea` reports
  the load failure; this is not silent.
- **BPF-side controller generations (P9).** Generations come from the userspace
  tracker. After a delete + recreate of the same `nvmeN`, the first interval is
  reported as `counter_reset`.
- **Map entries of removed controllers** are not deleted. They are harmless: the
  next generation's first interval is marked `counter_reset`.
- **Per-I/O overhead** is not measured. The kernel's BPF run-time statistics
  require `kernel.bpf_stats_enabled=1`, a host-wide setting that was not changed on
  this host. The application workload is closed-loop and remote-dominated
  (~1.3 ms), so throughput is not a sensitive overhead signal here. Measurement is
  planned in the benchmark VM (implementation plan §6).
- **Stock Rocky 9 (5.14) kernel runtime run**: still pending a VM.
