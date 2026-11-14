# Phase 3 (part 2) — Driver-stage timing and profile mode (Level 2): validation record

Date: 2026-11-13. Host: the development initiator (Rocky Linux 9.6 userspace,
kernel 6.12.117-1.el9, 128 CPUs, 6 NVMe/TCP controllers × 8 I/O queues,
round-robin multipath).

**Workload.** Operator-provided `elbencho`: 8 KiB random O_DIRECT reads, 32
threads × iodepth 16, about 330–360k reads/s in total. The target supplies
almost all of the latency, about 1.4 ms per read.

**Fault injection.** Done with `tools/faultinject/` on nvme4 only, as authorized
(`docs/validation/fault-injection.md`).

**Later write workload.** `elbencho` 8 KiB random O_DIRECT writes, about 75–90k
writes/s. It validated R2T and in-capsule write staging against the Phase 0
bpftrace spike (below).

## What was built

**`bpf/tcp_driver.bpf.c`** (Dual MIT/GPL, CO-RE). Sampled commands get a
208-byte boundary record (`nvt_prof`), emitted at block completion:

| Boundary | Hook (probe id) |
|---|---|
| E_SETUP, sampling (1 in N, `bpf_get_prandom_u32`) | `raw_tp/nvme_setup_cmd` |
| E_TX_START: entry of the first send attempt; send context from the task's `PF_WQ_WORKER` | `nvme_tcp_try_send_cmd_pdu` entry (D1) |
| E_CMD_SENT | `nvme_tcp_try_send_cmd_pdu` exit = 1 with `queue->request` cleared (D1). With in-capsule data: `nvme_tcp_try_send_data` / `_ddgst` exit (D2) |
| E_R2T_PROC, E_R2T_START, E_R2T_NOTIFY | `nvme_tcp_setup_h2c_data_pdu` inside a receive call (D4); calls from the send path are continuation PDUs |
| E_H2C_START / E_H2C_SENT, busy_h2c | `nvme_tcp_try_send_data_pdu` entry (D3); `nvme_tcp_try_send_data` entry/exit (D2) |
| receive context (call start, skb `end_seq`) | `nvme_tcp_recv_skb` entry/exit (D7) |
| READ first/last data, busy_c2h, DATA_SUCCESS | `skb_copy_datagram_iter` (+ `_and_hash_`) inside a receive call. Attribution: `queue->pdu` C2H header → command id → record (D8) |
| E_RSP_PARSED, response start and notification | `blk_mq_complete_request_remote` (D9) |
| notification ring per queue: 32 × (time, `rcv_nxt`) | `nvme_tcp_data_ready` (D10f) |
| timeouts | `nvme_tcp_timeout` (D12) |
| E_NVME_DONE, E_BLK_DONE | `raw_tp/nvme_complete_rq`, `raw_tp/block_rq_complete` |
| worker accounting for every io_work run | `nvme_tcp_io_work` entry/exit (D6) |

**Flavours and loading.**
- **Two flavours.** Every function hook is built twice: kprobe/kretprobe and
  fentry/fexit, the latter using `bpf_get_func_arg` scalars.
- **Default.** The **fentry preflight** runs `nvmetea __preflight` in a helper
  process. The helper attaches one empty fentry program to `bpf_fentry_test1`
  within 2 s and ≤ 100 ms; if it passes, fentry is chosen, otherwise kprobes.
- **Fallbacks.**
  - If fentry fails, nvmetea falls back to kprobes.
  - Programs this kernel cannot run (discovery rule F4) are not loaded.
  - An optional program the verifier rejects is dropped and the object is
    reloaded, with the verifier's reason reported.

**Gating.**
- A global count of sampled commands in flight is checked first.
- Then a per-queue count, kept in the queue's notification-ring entry: receive
  hooks do nothing on queues without a sampled command.
- Per-thread contexts are per-CPU slots tagged with the thread id.

**`crates/nvmetea-profile`** (pure logic) holds:
- variant classification;
- the stage partition with rules R1/R2 (missing or out-of-order boundaries merge
  into one unclassified span);
- complete-set aggregation (R3), per-stage histograms (R5), classes (R6), and
  the slowest-command timelines.

**`nvmetea profile`** `[-i S] [--sample N] [--flavour auto|fentry|kprobe] [--slowest N] [--bpf-stats] [--controller …] [--json]` reports, per variant × size class:
- a stage table with mean, share, p50 and p99;
- per-controller family means;
- the queues with the most local time;
- the slowest commands stage by stage;
- io_work statistics;
- a Level 1 cross-check (sampled vs all commands);
- with `--bpf-stats`, per-program run time and recursion misses.

## Automated tests

`cargo test --workspace`: **98 passed, 0 failed**. `clippy -D warnings` and
`fmt --check` are clean. New:

**`nvmetea-profile`, 10 tests:**
- every stage of an R2T write;
- a missing boundary merges its neighbours;
- an order violation is flagged and merged;
- READ data phase split by busy time, with clamping;
- READ with a separate response capsule (C4/D1b);
- in-capsule write and unstaged read;
- no end-to-end interval without start/end;
- complete-set means add up to the end-to-end mean;
- size classes;
- **property:** the spans add up exactly to E_BLK_DONE − E_START for all 4,096
  missing-boundary patterns of an R2T write, with pseudo-random reordering.

**`nvmetea-bpf`:**
- libbpf log parsing of the failing program;
- every flavour carries the required probes;
- record conversion: 0 becomes "missing", and an unbound `io_cpu` becomes
  unavailable.

**CLI:** `profile` refuses `--no-bpf`, and `__preflight` stays hidden.

## Live results

### Loading

| Check | Result |
|---|---|
| fentry preflight | passed, attach **1.1–1.6 ms** |
| fentry object | 16 programs, load ≈ 88 ms, attach ≈ 20 ms |
| kprobe object | 18 programs, load ≈ 24 ms, attach ≈ 39 ms |
| Verifier-rejected optional program (first build: a CO-RE read of a BPF-local struct in D8) | dropped automatically; the other programs ran. The verifier's message ("failed to resolve CO-RE relocation … struct rx_ctx.queue") was reported. Fixed. |

### Consistency

Seven profiled phases, 804k sampled commands, fentry, 1 in 50:

| Check | Result |
|---|---|
| Σ stages ≠ request latency | **0** in every run |
| ring buffer lost / record map full | 0 / 0 |
| partial records (a boundary missing) | ≤ 3 per phase (≤ 0.002 %) |
| sequence-mapped notification unresolved | ≤ 6 per phase with fentry. kprobes: 0.3 % at 1 in 100 and 0.66 % at every command (below) |
| sampled mean request latency vs Level 1 (all commands), per controller | within **0.6 %** in every phase except loss (2.1 %: 1-in-50 sampling of a 200 ms retransmission-timeout tail) |
| READ data copies attributed to their command | 100 % of sampled reads. All completed by a C2H PDU with SUCCESS (no separate response capsule on this target) |

### Where the time goes (baseline)

8 KiB reads, all controllers, 1 in 100, about 17.6k complete records in 5 s:

| Stage | Mean | Share |
|---|---|---|
| A block submission | 2.3 µs | 0.2 % |
| B1 send queueing / B2 command send calls | 4.6 / 2.7 µs | 0.5 % |
| **C1 remote/transport: command → first data** (upper bound) | **1.41 ms** | **98.7 %** |
| D1 receive wakeup (lower bound) / D2a headers / D2 data processing | 4.3 / 2.0 / 1.2 µs | 0.5 % |
| C2 data streaming wait | 0.1 µs | 0 % |
| E1 + E2 completion | 1.4 µs | 0.1 % |

The host's own path (A + B + D + E) is about 20 µs of a 1.4 ms read. The rest is
network plus target.

### Writes: R2T and in-capsule staging, cross-checked against bpftrace

Workload: 8 KiB random writes. This target solicits 8 KiB writes by R2T and takes
4 KiB writes in-capsule.
- **R2T:** 17,834 complete records in 10 s at 1 in 50.
- **In-capsule:** 163 records.
- **Quality:** 0 partial, 0 sum-check failures, 0 unresolved notifications.
- **Level 1 cross-check:** per controller within 2 %.

| Stage (R2T write, mean) | nvmetea | Share |
|---|---|---|
| A / B1 / B2 | 2.6 / 3.7 / 2.8 µs | 0.2 % |
| **C1 command → R2T** (upper bound) | **404 µs** | 7.1 % |
| D1r / D3r R2T wakeup / processing | 4.1 / 0.2 µs | 0.1 % |
| B3 / B4 data queueing / transmit (2.7 µs of B4 in send calls) | 3.0 / 3.4 µs | 0.1 % |
| **C3 data → response** (upper bound) | **5.22 ms** | 92.4 % |
| D1 / D3 / E1 / E2 | 4.4 / 1.3 / 0.6 / 0.9 µs | 0.1 % |

**Independent cross-check.** `tools/feasibility/write_path.bt` (bpftrace, every
R2T write; a different implementation of the same boundaries) ran in the same
window as `nvmetea profile` (1 in 10).

| Stage | bpftrace (879,586 writes) | nvmetea (70,625) | Δ |
|---|---|---|---|
| C1 + D1r + D3r | 402.5 µs | 395.1 µs | −1.8 % |
| C3 | 5,223.5 µs | 5,200.1 µs | −0.4 % |
| D1 + D3 | 9.17 µs | 9.36 µs | +0.19 µs |
| B3 / B4 / B4 busy | 6.50 / 3.43 / 2.67 µs | 6.18 / 3.56 / 2.73 µs | ≤ 0.3 µs |
| request | 5,659.8 µs | 5,632.0 µs | −0.5 % |
| A / E2 | 1.83 / 0.64 µs | 5.10 / 2.73 µs | see below |

**Tracepoint order.** BPF programs on one tracepoint run in attach order. bpftrace
was attached first, so nvmetea's E_SETUP and E_BLK_DONE stamps came after
bpftrace's programs had run. That makes A and E2 longer and B shorter by those
programs' run time.

The same happened in normal use with nvmetea's own Level 1 programs (about 0.8 µs
at dispatch). `nvmetea profile` now attaches the driver object before Level 1.
After that, A is 1.68 µs and E2 0.57 µs, matching bpftrace's unshifted values.

### Attribution under known faults

These are the acceptance tests of `implementation-plan.md` §4 (cases 10 and 11),
run on nvme4. The other five controllers are the same-window control.

**netem delay of 2 ms on egress to nvme4's target**, so the READ command capsule
crosses one delayed hop:

| | nvme4 C1 | control C1 | nvme4 − control |
|---|---|---|---|
| run 3 baseline / delay | 1,534.8 / 3,190.1 µs | 1,504.2 / 1,146.9 µs (mean of 5) | +30.6 → **+2,043.2 µs (Δ +2.01 ms)** |
| run 4 baseline / delay | 1,322.8 / 3,112.2 µs | nvme2: 1,288.0 / 1,074.1 µs | +34.8 → **+2,038.1 µs (Δ +2.00 ms)**. Against the mean of 5: Δ +2.13 ms |

- **Other stages.** All other nvme4 stages changed by **< 1.2 µs**: A, B1, B2,
  D1, D2a, D2, E1, E2. The criterion is X ± max(5 µs, 10 %), with other stages
  moving < 5 µs: **passed**.
- **Control drift.** The controls themselves drifted by up to 0.35 ms between
  windows, as the target's load changed; this is why nvme4 is compared within the
  same window.

**CPU contention on the `io_cpu` of nvme4 qid 1** (CPU 3), compared with nvme4's
other queues and all other queues:

| Phase | nvme4/q1: B | D | C | Other queues: B / D / C |
|---|---|---|---|---|
| baseline (run 4) | 8.8 µs | 10.1 µs | 1.306 ms | 8.1 / 8.8 µs / 1.399 ms |
| **SCHED_FIFO hog, busy 2 ms of every 10 ms** | **183.4 µs** | **178.2 µs** | 1.371 ms | 7.7 / 8.5 µs / 1.392 ms |
| nice −20 CPU-bound hog (run 3) | 8.7 µs | 9.4 µs | 1.390 ms | unchanged |

- **Hogged queue.** B grew by 175 µs (B1, waiting for the worker: 5.3 → 21.1 µs
  as the nvme4 mean) and D by 168 µs (D1, receive wakeup). A queue that gets 80 %
  of the CPU in 2 ms windows predicts about 0.2 ms per worker wakeup.
- **Everything else.** Nothing changed on any other queue.
- **C on the hogged queue rose 72 µs relative to the control.** This is the
  documented bound: while the preempted worker holds the socket lock, packets
  wait in the TCP backlog. Their delivery, and so the notification, comes later
  and is counted in C (`latency-model.md` §5.4: C upper bound, D lower bound).
- **The nice −20 hog changed nothing.** The NVMe/TCP workqueue is `WQ_HIGHPRI`
  (kworkers at nice −20), and a mostly-sleeping kworker is scheduled promptly on
  wakeup against a CPU-bound task of equal priority. So it is a correct
  non-attribution result. Its slowest records exposed a send-context defect,
  which was fixed (next section).

**netem loss of 1 %:** nvme4 C1 rose from +30 µs over the control to **+687 µs**
on average (retransmission recovery). A, B, D and E were unchanged within 1 µs.

### Fixed during validation

| Finding | Change |
|---|---|
| The B1/B2 split used the per-CPU "current io_work run" slot. io_work runs on one CPU can interleave (one sleeps on the socket lock while another runs), and `nvme_tcp_queue_request()` on `io_cpu` sends every pending request of the queue, not only its own. Under the nice −20 hog, records showed 11 ms in "B2 command transmit" flagged as direct sends from another CPU. | E_TX_START is now the entry of the first send attempt (an fentry/kprobe on `nvme_tcp_try_send_cmd_pdu`). B1 = waiting to be sent (worker wakeup, or behind other commands), B2 = the send calls. Direct vs worker comes from `PF_WQ_WORKER` of the sending task. Lost io_work contexts are counted (`worker_ctx_lost`, 0 in 3 s at 330k IOPS). |
| Per-packet hooks did their full work whenever any sampled command was in flight. At 1 in 100 and 330k IOPS that is almost always. | Per-queue hot count: receive hooks return early on queues without a sampled command. Per call: `fe_copy` 161 → 125 ns, `fe_data_ready` 109 → 79 ns. |

## Overhead

Measured with `nvmetea profile --bpf-stats`. This holds `BPF_ENABLE_STATS` for
the run; it is host-wide, adds two clock reads per program run, and is released
at exit. No sysctl was changed.

Program run time covers the program body only. **It excludes the dispatch
around it** (kprobe/ftrace handler, kretprobe trampoline, BPF trampoline), so
the two flavours are not directly comparable by these numbers.

At 330–360k reads/s:

| Configuration | nvmetea BPF time (% of one CPU) | per completed command |
|---|---|---|
| Level 1 alone: `nvt_setup_cmd` 770–890 ns, `nvt_complete_rq` ~300 ns, `nvt_blk_complete` ~355 ns | ≈ 53 % | **≈ 1.45 µs** |
| + Level 2 fentry, 1 in 100 | 83 % | 2.33 µs (Level 2 ≈ 0.85 µs, of which io_work accounting ≈ 0.2 µs) |
| + Level 2 kprobe, 1 in 100 | 73 % | 2.04 µs (kprobe dispatch not included) |
| + Level 2 fentry, every command | 192 % | 5.8 µs |
| + Level 2 kprobe, every command | 182 % | 5.5 µs |

**Level 1 optimization pass (2026-11-13).** Instruments:
- `bpftool prog profile`: hardware counters per program run;
- interleaved A/B runs: same workload, same window, two builds, three rounds each.

| Change | Effect |
|---|---|
| `inflight` map without preallocation (`BPF_F_NO_PREALLOC`, bpf_mem_alloc). Preallocated entries come from per-CPU free lists. Commands are dispatched on one CPU and completed on the queue's io_cpu, so the dispatching CPUs' lists run dry and every insert scans other CPUs' lists. | dispatch 805 → 519 ns; completion programs +125 / +70 ns (entries now arrive cold on the completing CPU). **Net 1.42 → 1.32 µs per command (−6.5 %)**. Superseded by the slot redesign below |
| One bulk read each of `struct request` and `struct nvme_request`, fields at CO-RE offsets (direct reads if a kernel places them beyond the buffer); TCP test by cached `ops` pointer | −350 instructions per dispatch, **no change in cycles**. Kept: fewer helper calls, no downside |
| per-hctx cache of qid/device | −350 instructions, no cycle change; it carried a stale-address risk. **Dropped** |
| per-CPU queue counters, live in-flight count in a separate map | no improvement (an extra map lookup offset it). **Reverted** |

**Hardware counters.**
- `nvt_setup_cmd` runs about 2,800 cycles and 2,900–3,200 instructions per call;
  `nvt_complete_rq` about 2,200 cycles and 1,740 instructions. That is about 1
  instruction per cycle, and fewer instructions did not mean fewer cycles. The
  programs **stall on memory**.
- On this 8-CCD EPYC, cross-die cache misses come from lines written by other
  CPUs: the in-flight hash bucket and its lock, the per-queue counters, and the
  hctx line, where `queue_num` sits next to the frequently updated `nr_active`.
- The structural remedy is the one the plan's risk table names: an in-flight
  store that needs no shared hash. It was built next (below).

**Level 1 redesign: in-flight slots indexed by tag (2026-11-13).**

*Design* (`bpf/core.bpf.c`):
- **Slots.** Each NVMe queue (one blk-mq tag set) gets a region of `nr_tags`
  slots in one BPF array, allocated on first sight from an atomic cursor. A
  command lives at slot `base + rq->tag`. A tag is unique within its tag set
  while the request is in flight, so no hash, lock, allocation or probing is
  needed.
- **Publishing and freeing.** The slot's key (the driver PDU address) is
  published and cleared with an atomic exchange. Completion paths check the
  key, so a stale or foreign slot is never misattributed.
- **Requeued and retried requests** release their driver tag. Their entry
  moves to a small hash until the next dispatch, and the hash is checked only
  while it is non-empty.
- **Per-queue counters and histograms** are arrays indexed by a dense queue
  index assigned at registration (`qinfo[qidx]` = controller instance, qid).
  The lookups compile to pointer arithmetic.
- **Registration caches.** `hctx → (region, queue index, qid, path device)`
  is cached in a read-mostly LRU hash, validated by the request-queue pointer,
  the controller instance and an epoch that userspace advances on topology
  changes.
- **Regions are keyed by NVMe queue**
  (`controller instance << 32 | qid`), not by tag-set address:
  - a reset or reconnect keeps the region;
  - a controller deleted and recreated under the same instance gets its
    region back;
  - a recycled address cannot inherit another controller's queue index.
- **The qid comes from the tag set** (admin tag set → 0, otherwise hardware
  queue + 1). Before this, a request queue without `queuedata` was taken to be
  the admin queue. The fabrics connect queue is such a queue, but it sends its
  Connect commands on the I/O queues, so after a fresh connect an I/O queue's
  statistics could be registered under qid 0.
- **Sizing.**
  - Slots: clamp(1.25 × total queue depth + 4 Ki, 8 Ki, 512 Ki), 80 B each
    (640 KiB at 8 Ki).
  - Queue indices: clamp(queues + 64, 128, 16 Ki).
  - Per-queue histograms: the first 903 queue indices (32 MiB). Queues beyond
    that count `map_full{hist}`.
  - With reuse, the earlier 4× and 2× headroom was no longer needed.
  - Exhaustion is counted (`map_full{inflight|qstats}`). The command is then
    counted, but not timed.

*Cost.* Same-window A/B: the old build (non-preallocated hash, from
`dist/nvmetea` at the time) and the new one ran at the same time on the same
tracepoints, under the same workload. Program run time came from
`BPF_ENABLE_STATS`; each program was attributed to its build by
`/proc/<pid>/exe`.

| Program | Hash (ns/run) | Slots (ns/run) |
|---|---|---|
| `nvt_setup_cmd` | 519 | 116 |
| `nvt_complete_rq` | 403 | 113 |
| `nvt_blk_complete` | 402 | 133 |
| **per command** | **1,324** | **362** |

This is **−73 %**, and below the 0.5 µs budget of `implementation-plan.md` §6 when
read as program run time. The budget's own measure (added mean latency at QD1,
4 KiB random reads, nvmetea off/on, ≥ 5 alternating runs) needs a benchmark
VM. It also includes the tracepoint dispatch around the programs, which run
time leaves out. It is not measured yet.

*Correctness* (live, the operator's elbencho writes, about 30–41k commands/s):
- per path device, Level 1 completions + untracked = diskstats completions;
- mean request latency within 0.06 % of the diskstats-derived mean;
- `mismatch` 0, `stale_replaced` 0, `map_full` 0;
- `inflight_max` ≤ queue depth on every queue;
- the profile's Level 1 cross-check unchanged;
- `serve` output unchanged in shape.

*Reconnect* (`tools/faultinject` phase `rst` on nvme4: RST, error recovery,
reconnect, with `serve` running):
- slot cursor 1,668 → 1,668 and queue cursor 54 → 54: no region or index was
  allocated again;
- the 8 fabrics Connect commands were counted on qids 1–8, one each, as
  `op="other"`;
- `stale_replaced` 0, `map_full` 0;
- the controller returned to `live`.

**Findings:**
- **Level 1 was over its budget before the redesign above** (now 362 ns of
  program run time per command). The plan's budget for continuous Level 1 is
  ≤ 0.5 µs of added mean latency per command at QD1 (`implementation-plan.md` §6).
  The Level 1 programs alone take about 1.45 µs per command on the I/O path, about
  three times the budget, so they need optimization.
  - The likely hot spots are inferred from the code, not profiled (no `perf` on
    this host):
    - atomic adds on per-queue counters shared by the submitting CPUs and the
      completing CPU (cache-line transfers);
    - the preallocated hash insert and delete for every command;
    - about 15 separate `bpf_probe_read_kernel` calls per dispatch.
  - After the optimization pass above: about 1.32 µs per command. The remainder
    is cross-CPU memory traffic; see the follow-up (decision D-6).
- **Profile mode at 1 in 100 adds about 0.85 µs** per command, within the profile
  budget (≤ 3 µs). Recording every command costs about 4 µs per command and is
  diagnostic only, as planned.
- **kprobes lose receive notifications that fentry keeps.**
  - At every command, 0.66 % of sequence mappings were unresolved with kprobes,
    against 0.0006 % with fentry; at 1 in 100, 0.3 % against 0.
  - The kernel's BPF recursion counters show 0 misses for the kprobe programs, so
    the losses happen before BPF runs. Skipped re-entrant kprobes are the probable
    cause, but this is unconfirmed: this host's bpftool does not show kprobe miss
    counts.
  - A lost notification can only make C longer and D shorter, so the bounds stay
    valid.
  - This is why `auto` prefers fentry when the preflight passes.

## Not yet validated / not built

- Multi-PDU READ data streaming. These reads are single-PDU, so C2 ≈ 0.
- Separate response capsules (C4/D1b): this target always sets DATA_SUCCESS.
- **Not built:**
  - D11 (on-CPU worker time);
  - D13 (polled queues: none configured);
  - `--rx-timestamps`;
  - filters other than `--controller`;
  - continuous-mode stage histograms.
- Level 1 added latency at QD1 (the budget's own measure) on a benchmark VM.
  The program run time is 362 ns per command after the redesign.
- Stock Rocky 9 (5.14) and Ubuntu kernels: the flavour, preflight and
  verifier-fallback paths exist but have only run on this 6.12 build.
