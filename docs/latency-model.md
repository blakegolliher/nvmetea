# nvmetea — Command lifecycle and latency accounting model

Status: Phase 0 deliverable. Last updated 2026-11-13.

This document defines what nvmetea measures for each NVMe/TCP command on the
initiator, where each boundary comes from, how intervals are partitioned into
stages, and which parts of a command's life cannot be observed from the
initiator. Probe ids (P*, D*, T*) refer to `kernel-compatibility.md` §5.

The question this model answers:

> A command took 500 µs. Which controller and queue handled it? How much of the
> time was local block-layer work, local transmit, local receive, and local
> completion? How much is left as the combined remote/transport interval? What
> local evidence (CPU, worker, TCP) explains it?

## 1. Measurement principles

1. **One clock.** All timestamps are `CLOCK_MONOTONIC` nanoseconds:
   `bpf_ktime_get_ns()` and the block layer's `ktime_get_ns()`/`blk_time_get_ns()`.
   Only differences between timestamps taken on the same host are used. Wall-clock
   time is derived once per capture for display.
2. **Same command.** An interval is computed only between two boundary events
   correlated to the same command instance (section 4).
3. **Partition, don't sum percentiles.** A command's stages are contiguous,
   non-overlapping intervals that add up exactly to its end-to-end interval.
   Aggregation uses means over the same matched set. Per-stage percentiles are
   reported separately and never summed.
4. **Missing is explicit.** A missing boundary merges the adjacent stages into a
   labelled *unclassified* interval. It is never replaced by an estimate.
5. **Remote is remote.** Everything between the last local outbound boundary and
   the first local inbound boundary is the *combined remote/transport interval*. It
   is never called target latency or network latency.

## 2. Command path on a Linux NVMe/TCP initiator

```
application / filesystem / md / dm
   │ submit_bio(ns head nvmeXnY)              bio-based multipath head
   ▼
nvme_ns_head_submit_bio → path select (iopolicy) → remap to path nvmeXcYnZ
   ▼
blk-mq on the path queue: request allocated ── rq->start_time_ns ............ E_START
   │ plug / scheduler (usually none) / dispatch
   ▼
nvme_tcp_queue_rq
   ├─ nvme_tcp_setup_cmd_pdu → nvme_setup_cmd ── tracepoint, genctr++, cid  E_SETUP
   ├─ nvme_start_request → block_rq_issue, multipath head accounting
   └─ nvme_tcp_queue_request
        ├─ on queue->io_cpu, queue empty, send_mutex free → send now (direct)
        └─ otherwise queue_work_on(io_cpu, io_work)            (deferred)
   ▼
io_work (kworker on io_cpu, 1 ms quota per run, requeues itself)
   ├─ try_send: command PDU (+ in-capsule data, digests)
   │      sendmsg returns ──────────────────────────────────────────── E_CMD_SENT
   └─ try_recv → tcp_read_sock → nvme_tcp_recv_skb (one call per skb)
   ▼
 ………… TCP, NIC, network, target transport, target storage, response …………
   ▼
NIC → softirq → TCP → sk_data_ready → nvme_tcp_data_ready → queue io_work  E_RX_NOTIFY
   ▼
io_work → recv_skb → PDU header parsed
   READ:  C2H data PDU(s): header, data copied skb by skb ──────── E_C2H_FIRST … E_C2H_LAST
          (many skbs, often many io_work runs, interleaved with other commands)
   WRITE (R2T): R2T parsed → H2C data PDU(s) queued → sent ───── E_R2T_PROC, E_H2C_START, E_H2C_SENT
   response capsule (CQE) parsed, or the last C2H with SUCCESS flag
      nvme_try_complete_req → blk_mq_complete_request_remote ─────── E_RSP_PARSED
   ▼  (IPI / softirq to the submitting CPU when needed)
nvme_complete_rq ── tracepoint (retry / failover / end decision) ──────── E_NVME_DONE
   ▼
blk_mq_end_request → block_rq_complete ── tracepoint ──────────────────── E_BLK_DONE
   ▼
bio_endio → multipath head → md/fs → application
```

## 3. Boundary event catalog

| Event | Meaning | Source | Level | Notes |
|---|---|---|---|---|
| `E_START` | blk-mq request started on the path queue | `rq->start_time_ns` read at P1 | 1 | 0 when the queue has no iostats/stats (admin queue, iostats disabled). Since 6.9 and CS9 it may be the plug's cached time, so it can be early by up to the plug duration (F11) |
| `E_SETUP` | driver dispatch: `nvme_setup_cmd` inside `->queue_rq` | P1 | 1 | first dispatch and every retry/requeue re-dispatch |
| `E_IOW_TX` | start of the `io_work` run in which the command's first send attempt ran, or `E_SETUP` if that run started earlier (a run already in progress picked the command up) | D6 + D1 context | 2 | = `E_SETUP` for direct sends. Waiting behind other commands inside a run counts in B2 |
| `E_CMD_SENT` | command capsule (and in-capsule data) handed to TCP (`sendmsg` returned) | D1/D2 (D5) | 2 | "handed to TCP" ≠ "on the wire" |
| `E_R2T_NOTIFY` | first receive notification on the queue socket that preceded the R2T's processing | D10 | 2 | see §5.4 |
| `E_R2T_ARR` | arrival of the skb carrying the R2T | `skb->tstamp` at D7 | 2 (opt-in) | requires `--rx-timestamps` (§5.4) |
| `E_R2T_START` | start of the receive call that processed the R2T | D7 | 2 | |
| `E_R2T_PROC` | R2T parsed | D4 | 2 | first R2T; later R2Ts set a flag |
| `E_H2C_START` | first solicited data PDU begins sending | D3 (D5) | 2 | |
| `E_H2C_SENT` | last solicited data handed to TCP | D2 (D5) | 2 | |
| `E_RX_NOTIFY` | the `sk_data_ready` whose `rcv_nxt` first covered the skb holding the command's response (sequence-mapped) | D10 + D7 | 2 | never earlier than true availability; see §5.4 |
| `E_RSP_ARR` | arrival of the skb carrying the command's first response PDU | `skb->tstamp` at D7 | 2 (opt-in) | `--rx-timestamps` |
| `E_RX_START` | start of the receive call that first processed this command's response | D7 | 2 | |
| `E_C2H_FIRST` | first copy of this READ's data | D8 | 2 (profile) | |
| `E_C2H_LAST` | end of processing of this READ's last data (call exit, or completion inside the call) | D7/D8/D9 | 2 (profile) | |
| `busy_c2h` | sum of this READ's data-processing time inside `[E_C2H_FIRST, E_C2H_LAST]` | D7/D8 | 2 (profile) | elapsed time of calls; see R4 |
| `busy_h2c` | sum of `try_send_data` call time spent on this WRITE's data | D2 entry/exit | 2 (profile) | |
| `E_RSP_PARSED` | response parsed, request handed to blk-mq completion | D9 | 2 | before any completion IPI |
| `E_NVME_DONE` | `nvme_complete_rq` | P2 | 1 | status, retries |
| `E_BLK_DONE` | `block_rq_complete` | P3 | 1 | end of the request on the path |

Per-command context recorded with the boundaries: controller instance and
generation, qid, tag, cid (with genctr), opcode, nsid, bytes, submit CPU, completion
CPU, `io_cpu`, send context (direct/deferred), socket cookie, status, retries, flags
(§4.3).

## 4. Command identity and correlation

### 4.1 In-kernel key

- **Primary**: the address of the command's driver PDU (`rq + sizeof(struct request)`).
  It is unique while the request is in flight, and constant from dispatch to
  completion. The verifier forbids arithmetic on BTF-typed pointers (F14), so programs
  are `raw_tp` with scalar arguments.
- **Validation** at completion: the stored `command_id` must equal
  `nvme_req(rq)->cmd->common.command_id`. The stored `(ctrl_instance, ctrl_gen, qid)`
  must match. A mismatch is counted as `correlation_mismatch`, and the record is
  dropped from latency statistics.
- **Text-format fallback** (P1b/P2b, no module BTF): key `(ctrl_id, qid, cid & 0x0fff)`.
  The tag is unique per hardware queue while in flight. Generation bits are compared
  only when both events carry them (F1).

Kernel addresses never leave the kernel. Userspace receives a synthetic
`correlation_id` (a per-boot 64-bit counter assigned at `E_SETUP`).

### 4.2 Lifecycle generations

| Identity | Changes when | Tracked by |
|---|---|---|
| controller *generation* | the `nvme_ctrl` object is created (delete + reconnect, possibly reusing `nvmeN`) | P9 (BPF-side counter per instance); fallback userspace (uevent/sysfs) |
| connection *epoch* | the controller (re)enters LIVE: reset/reconnect replaces every queue socket | L3 / sysfs state; new socket cookies |
| command *dispatch* | every `E_SETUP` for the same request (retry/requeue) | `genctr` |

Per-queue statistics are keyed by `(ctrl_instance, ctrl_generation, qid)`, so a
recreated `nvme3` never inherits the counters of the old one.

### 4.3 Per-command flags

`WRITE`, `INLINE_DATA`, `R2T`, `MULTI_R2T`, `DATA_SUCCESS` (read completed by C2H
SUCCESS), `DIRECT_SEND`, `RETRIED`, `REQUEUED`, `FAILED_OVER`, `CANCELLED`,
`TIMED_OUT`, `ERROR`, `ADMIN`, `ASYNC_EVENT`, `POLLED`, `TLS`, `DIGEST`,
`START_TS_MISSING`, `ORDER_VIOLATION`, `PARTIAL` (a boundary missing).

## 5. Intervals and stages

### 5.1 Named end-to-end intervals

Each interval has its own metric name. Narrower intervals are never presented
under the end-to-end name.

| Name | Interval | Requires | Metric |
|---|---|---|---|
| **request latency** | `E_START → E_BLK_DONE` | P1, P3, `start_time_ns ≠ 0` | `nvmetea_request_latency_seconds` |
| **command latency** | `E_SETUP → E_NVME_DONE` | P1, P2 | `nvmetea_nvme_command_latency_seconds` |
| **transport round trip (driver view)** | `E_CMD_SENT → E_RSP_PARSED` (single round-trip commands) | D1, D9 | profile output only |
| **keep-alive latency** | admin opcode 0x18, `E_SETUP → E_NVME_DONE` | P1, P2 | `nvmetea_controller_keepalive_latency_seconds` |

Not covered by any interval (section 9): time spent above the path request. This
includes bio submission to the multipath head, path selection, md/dm and filesystem
layers, and plug time before request allocation.

### 5.2 Stage definitions (common to all commands)

The five stage families of the specification. Components in parentheses.

| Stage | Component | Interval | Class |
|---|---|---|---|
| **A** local block submission | A | `E_SETUP − E_START` | measured |
| **B** initiator transmit | B1 worker queueing | `E_IOW_TX − E_SETUP` (0 if direct) | measured |
| | B2 command transmit | `E_CMD_SENT − E_IOW_TX` | measured |
| **C** combined remote/transport | C1 to first response | `E_RX_NOTIFY − E_CMD_SENT` (§5.4) | measured, upper bound (exact with `--rx-timestamps`) |
| **D** initiator receive | D1 receive wakeup | `E_RX_START − E_RX_NOTIFY` | measured, lower bound (exact with `--rx-timestamps`) |
| | D3 response processing | `E_RSP_PARSED − E_RX_START` (single-PDU response) | measured |
| **E** local completion | E1 completion handoff | `E_NVME_DONE − E_RSP_PARSED` (IPI/softirq when the submitter is elsewhere) | measured |
| | E2 completion processing | `E_BLK_DONE − E_NVME_DONE` | measured |

### 5.3 Per-protocol partitions

Every row sums exactly to `E_BLK_DONE − E_START`. Unit tests enforce this.

**Small READ / any command answered by one response PDU** (no data or data
in one PDU):

```
A | B1 | B2 | C1 | D1 | D3 | E1 | E2
```

**Multi-PDU READ.** Data arrives in many skbs while earlier ones are copied:

```
A | B1 | B2 | C1 | D1 | D2a | [ D2 data processing (busy) ⊕ C2 data streaming wait ] | D2b | E1 | E2
D2a = E_C2H_FIRST − E_RX_START          (headers before the first data copy)
span = E_C2H_LAST − E_C2H_FIRST;  D2 = busy_c2h;  C2 = span − busy_c2h
D2b = E_RSP_PARSED − E_C2H_LAST         (response capsule; ≈0 with DATA_SUCCESS)
```

`E_C2H_LAST` is the end of the last receive call's work on the command's data
(the call's exit, or the completion inside it). busy_c2h is therefore always
inside the span, and D2 + C2 = span exactly. Without `DATA_SUCCESS`, when the
response capsule's own notification comes after `E_C2H_LAST`, the tail is split
further:

```
… | D2 ⊕ C2 | C4 | D1b | D3 | E1 | E2
C4  = E_RSP_NOTIFY − E_C2H_LAST         remote/transport: response capsule after the data (upper bound)
D1b = E_RX_START(response) − E_RSP_NOTIFY   receive wakeup for the response (lower bound)
```

A single-PDU READ uses the same partition; its C2 is then close to 0.

`C2` is the part of the data phase in which the host had none of this command's data
to process. It belongs to the combined remote/transport interval, labelled
*"remote/transport: data streaming wait"*. It also contains local receive wake-ups
between data segments, which are not separately attributable per command (R4).

**WRITE with in-capsule data**: the same as a small READ. B2 includes sending the
inline data.

**WRITE solicited by R2T**, two local round trips:

```
A | B1 | B2 | C1 | D1r | D3r | B3 | B4 | C3 | D1 | D3 | E1 | E2
C1  = E_R2T_NOTIFY − E_CMD_SENT        remote/transport, round trip 1 (command → R2T)
D1r = E_R2T_START − E_R2T_NOTIFY      receive wakeup for the R2T
D3r = E_R2T_PROC − E_R2T_START        R2T processing
B3  = E_H2C_START − E_R2T_PROC        transmit queueing (request back on the send list, worker)
B4  = E_H2C_SENT − E_H2C_START        data transmit = busy_h2c (send calls) ⊕ transmit wait
                                       (TCP send-buffer space, worker re-runs)
C3  = E_RX_NOTIFY − E_H2C_SENT        remote/transport, round trip 2 (last data handed to
                                       TCP → response notified)
```

`MULTI_R2T` commands contain further remote round trips inside B4. B4 is then reported
as *"data transmit incl. additional R2T round trips (not separable)"*, and those
commands are excluded from B/C stage means (they keep their end-to-end latency).

The B4 *transmit wait* is often the visible symptom of a network or receive window
limit (send buffer full). It is reported next to TCP `notsent`/`unacked`/`rwnd_limited`
for the same socket. It is not reclassified as remote time, because the host had
work it could not hand to TCP.

### 5.4 The receive boundary: notification vs arrival

C1 ends at the first local evidence that the response reached the host.

1. **Default (no side effects): sequence-mapped `E_RX_NOTIFY`.** At every
   `sk_data_ready` on a queue socket, D10 records `(time, tp->rcv_nxt)` in a small
   per-queue ring. That is the TCP sequence number up to which data has been
   delivered to the socket. When the response is parsed, inside `nvme_tcp_recv_skb`,
   the current skb's `TCP_SKB_CB(skb)->end_seq` is known. `E_RX_NOTIFY` is the
   earliest ring entry whose `rcv_nxt` covers `end_seq`. That is the first moment the
   whole skb holding the response was available to nvme-tcp. Because the response's
   last byte is ≤ `end_seq`, this boundary is never earlier than the true
   availability. **C1 is an upper bound and D1 a lower bound.** The same holds because
   TCP delivery can lag NIC arrival: softirq processing, and backlog processing while
   the reader holds the socket lock, are counted in C1. Both stages carry this bound
   in their labels. If the ring was overwritten before the response was parsed,
   C1+D1 are reported merged as unclassified (`seqnotify_unresolved`).

   *Rejected alternative.* "The first `sk_data_ready` since the receive path last
   drained" is wrong under sustained load. The queue never drains, so an old
   notification gets credited to a later response. On the development host it
   produced spurious receive-wakeup values of up to 8 ms where the sequence-mapped
   value was microseconds (§10). It is neither exact nor a bound.
2. **Opt-in `--rx-timestamps` (profile mode only): `E_RSP_ARR`.** nvmetea opens a
   socket with `SO_TIMESTAMPNS`. The kernel then stamps every received skb after GRO
   (`net_timestamp_check`), system-wide, while it is open. D7 reads `skb->tstamp` of
   the skb holding the command's first response PDU. This boundary is per command and
   is available at any queue depth. C1 then ends at arrival, and D1 contains softirq
   TCP processing, `data_ready` and the worker wake-up. This is ntprof's technique. It
   is opt-in because it changes kernel behaviour for all sockets (a small per-packet
   cost). It is disclosed in the capture metadata. Stamps are `CLOCK_REALTIME` and
   converted with the offset measured at start. A missing or implausible stamp (older
   than 1 s, in the future) falls back to case 1.

### 5.5 Admin, special and failed commands

| Class | Treatment |
|---|---|
| Asynchronous Event Request (opcode 0x0c) | **excluded** from latency (outstanding by design). Counted, and its completions reported as events. |
| Keep-alive (0x18) | own histogram per controller (health signal). Observed 100–150 µs on the R host. |
| Other admin, fabrics commands | separate histograms per opcode class |
| Retried (`retries` > 0 at a later `E_SETUP`) | request latency spans all attempts. The stage breakdown applies to the final attempt, plus component *"retry/requeue time"* = `E_SETUP(final) − E_START`. Excluded from normal stage means. |
| Requeued (P4) | as retried, flag `REQUEUED` |
| Failed over (P5 or derived) | the path request ends at `E_BLK_DONE` but the bio continues on another path. Counted as failover, **excluded** from latency (its duration is not what the application saw). |
| Cancelled (host abort during reset/delete) | counted, excluded from latency, event with age at cancellation |
| Timed out (D12) | event at timeout. If it later completes: separate "timed-out" histogram. |
| Error status | counted by status class. Latency kept in per-status-class histograms, not mixed into success histograms. |
| In flight when instrumentation armed | untracked. Its completion increments `untracked_completions`. |
| Outstanding at end of capture | reported with age; not in histograms |

## 6. Accounting rules

- **R1 — validity.** A stage is computed only if both boundaries belong to the same
  command record and `t_begin ≤ t_end`. A negative interval increments
  `order_violations`, sets `ORDER_VIOLATION`, and makes that span unclassified.
- **R2 — missing boundaries.** If a boundary is missing, the two stages around it
  merge into one *unclassified* interval between the nearest present boundaries. For
  example, without `E_CMD_SENT`, B2 and C1 become "unclassified: dispatch → response
  notification". Totals still add up. The record is `PARTIAL`.
- **R3 — complete-set aggregation.** Aggregate stage tables use only records in
  which every stage of that protocol variant is classified (complete records). The
  end-to-end mean is shown over the same set. Stage share % = stage mean ÷ end-to-end
  mean over that set. The number of complete and partial records is always shown.
- **R4 — busy vs wait.** `busy` is the elapsed time of driver calls attributed to the
  command. When D8 sees another command's data start inside the same call, the
  previous command's interval closes at that copy. Time inside a call after a
  command's last copy, before the next sampled command's first copy, stays with the
  first command. Busy is **elapsed** time. Interrupts and softirqs that run on the CPU
  during the call, and preemption, are included. The on-CPU correction (D11) is
  *derived* and applied only to worker totals (§8), not per command.
- **R5 — no percentile sums.** Stage percentiles describe each stage alone. A
  "typical command" is not built by summing stage percentiles. The slow-command view
  shows individual commands' actual timelines instead.
- **R6 — classes are never mixed.** Aggregates are grouped at least by (operation,
  protocol variant, size class). Variants: small READ, multi-PDU READ, inline WRITE,
  R2T WRITE, MULTI_R2T WRITE, other. Size classes are log2. Errors, retries,
  failovers and admin commands are separate.
- **R7 — sampled vs total.** In profile mode only sampled commands carry stage
  records. Totals (IOPS, bytes, errors) always come from separate unsampled counters.
  Sampled counts are labelled as such and never scaled up to totals.

## 7. Metric classification

| Classification | Definition | Examples |
|---|---|---|
| **measured** | a single interval between two directly observed boundaries of the same command, or a counter incremented at an observed event | request/command latency, A, B1, B2, E1, E2, C1 with an idle receive path, error counts |
| **derived** | arithmetic over measured values under a stated model | rates, `C2 = span − busy`, on-CPU worker time, Little's-law mean queue occupancy, namespace totals summed from paths, histogram percentiles (with stated resolution) |
| **estimated** | uses non-command-specific or heuristic evidence | worker quota exhaustion from elapsed > 1 jiffy, controller↔socket association by endpoint match |

Bounded values are *measured* with a direction attached. Default-mode C1/D1 are an
upper and a lower bound (§5.4), and the bound is shown next to the value in every
output.
| **unavailable** | not observable on this system: always with a reason code | D-stages when D7/D8 cannot attach; request latency when `start_time_ns = 0` |

Each value in every output format carries its classification, source probe ids and
sample count.

## 8. Queue and worker accounting

| Metric | Definition | Class |
|---|---|---|
| configured depth | `sqsize + 1` from sysfs (I/O queues), 32 for the admin queue | measured |
| outstanding (instantaneous) | tracked `E_SETUP` minus tracked completions per queue, read at the snapshot | measured |
| outstanding high watermark | maximum since the previous snapshot epoch (BPF compares against an epoch number userspace advances; no destructive reset) | measured |
| mean occupancy | command rate × mean command latency over the window (Little's law) | derived |
| unsent | dispatched but `E_CMD_SENT` not yet seen | measured (Level 2) |
| direct vs deferred sends | count by send context | measured |
| submit / completion CPU distribution | per (queue, CPU) counters | measured |
| worker invocations | D6 entries per (queue, CPU) | measured |
| worker elapsed | Σ D6 exit − entry | measured |
| worker on-CPU | elapsed − Σ off-CPU intervals of that thread inside D6 (D11). Still includes irq/softirq time on that CPU. | derived |
| worker utilisation | on-CPU (or elapsed, labelled) ÷ wall time | derived |
| worker CPU migration | invocations whose CPU ≠ `io_cpu` (or a changed CPU when `io_cpu` is unbound) | measured |
| worker quota exhaustion | runs with elapsed ≥ the 1 ms quota rounded to jiffies (the kernel then requeues the worker) | estimated |

A kprobe or fentry hit count is never presented as CPU utilisation. Elapsed time is
never presented as CPU time.

**Imbalance evidence** (shown as evidence, not as a verdict):
- per-queue share of commands vs. an even spread (max/mean, coefficient of variation);
- per-queue p99 command latency vs. the controller median;
- worker utilisation per queue next to its outstanding count and throughput trend;
- submission CPUs per queue (blk-mq CPU→queue mapping), including how many CPUs
  share one queue;
- TCP symptoms (retransmissions, `rwnd_limited`, `notsent`) of that queue's socket.

A queue is never called saturated because its depth is high. The view shows depth,
throughput, worker utilisation and latency trend together.

## 9. What the initiator cannot observe

| Component | Where it ends up | Note |
|---|---|---|
| Wire, switches, NICs (both ends) | C | not separable without target-side or hardware timestamps |
| Target transport, target storage, target response preparation | C | out of scope (no target agent) |
| Local TCP/IP stack after `sendmsg` returns (qdisc, driver, NIC TX) | C | per-command attribution not possible |
| Local receive between NIC and TCP (`--rx-timestamps` off) | C | with rx timestamps: moves to D1 |
| Bio-level time above the path request (multipath head, md/dm, filesystem, plug before allocation) | not in any interval | profile-mode bio tracking is a later extension (implementation plan, Phase 3 stretch) |
| Interrupt/softirq time inside driver calls | B/D busy (elapsed) | flagged; worker totals get a derived on-CPU value |
| Clock caching in `start_time_ns` (6.9+, CS9) | A overstated by ≤ the plug duration | documented per kernel |
| TLS (kTLS) record processing | B2/D3 | detailed receive staging unsupported on TLS queues until validated |
| Polled queues | D | needs D13; otherwise D stages unavailable on poll queues |
| Commands in flight before arming | none | counted as untracked |

## 10. Phase 0 empirical validation (el9 6.12 development host)

### 10.1 READ path and correlation

Read-only observation of an application workload that was already running. nvmetea
generated no I/O. 15 s window, bpftrace programs equivalent to P1/P2/P3/D1/D2/D6/D7
(`tools/feasibility/spike3.bt`).

**Correlation checks**

| Check | Result |
|---|---|
| NVMe/TCP commands observed (setup → completion by PDU address) | 183,601 (183,565 READ on I/O queues + 36 admin keep-alives) |
| READ commands vs `/proc/diskstats` read delta over all path devices | **183,565 = 183,565** |
| completion `command_id` ≠ setup `command_id` | 0 |
| `command_id ≠ (genctr<<12)\|tag` | 0 |
| driver queue index ≠ tracepoint qid semantics (`hctx->queue_num+1`, 0 for admin) | 0 |
| PCIe commands rejected by the transport test | 16 of 16 (no TCP command rejected) |
| `start_time_ns == 0` | 36, exactly the admin requests (F11) |
| completions without a send stamp | 0 |

**Stage distributions** (log2 histograms; READ sizes 4 KiB–1 MiB, mostly 512 KiB–1 MiB)

| Interval | Bulk of the distribution | Notes |
|---|---|---|
| A: `E_START → E_SETUP` | 2–16 µs (mode 4–8 µs) | |
| B: `E_SETUP → E_CMD_SENT`, deferred (97.8 % of commands) | 4–16 µs (mode 4–8 µs) | submitted on a CPU other than the queue's `io_cpu`, so the send waits for the worker |
| B: direct (2.2 %) | 2–8 µs | |
| C+D: `E_CMD_SENT → E_NVME_DONE` | 256 µs–2 ms | dominated by remote/transport plus receive of up to 1 MiB of C2H data; D7/D8 split pending traffic |
| E2: `E_NVME_DONE → E_BLK_DONE` | 0.5–1 µs | |
| Request latency `E_START → E_BLK_DONE` | 256 µs–2 ms | |
| io_work elapsed | bimodal: 128–256 ns (no work) and 2–128 µs | 790k invocations in 15 s |
| keep-alive `E_CMD_SENT → E_NVME_DONE` | 100–150 µs | per-controller health signal |

**What this already shows** for the motivating question: on this host the local
stages A+B+E2 account for roughly 10–25 µs of a ~0.5–2 ms read. The rest is C+D.
Separating D (local receive processing of up to 1 MiB) from C (remote/transport)
needs the READ data-phase hooks D7/D8. These attach on this kernel; data validation
is pending READ traffic. The queue-level view also exposed a strong imbalance.
Per controller, qid 3 handled about 230 commands while qid 4 handled about 8,150, a
35× spread from blk-mq's CPU→queue mapping and the submitting threads' CPUs. That is
the kind of local evidence nvmetea is meant to surface.

### 10.2 WRITE path (R2T and in-capsule), sequence-mapped receive boundary

An `elbencho` run provided by the operator: 128 KiB random O_DIRECT writes, 32
threads × iodepth 16, on XFS over an md RAID0 of the NVMe/TCP namespaces. The
observation was read-only and nvmetea generated nothing. Two 10 s windows used
`tools/feasibility/write_path.bt`.

**Correctness**

| Check | Result |
|---|---|
| WRITE commands set up (second window) | 249,014 |
| classified R2T / in-capsule / unclassified | 242,879 / 5,619 (≤ ~8 KiB) / 24 |
| R2T records with every boundary present and ordered | 242,873. 6 partial or out of order |
| Σ stages ≠ request latency (per record, exact integer ns) | **0** |
| multi-R2T commands | 0. 12 extra H2C PDUs were set up from the send path (data split at `maxh2cdata`), correctly not counted as R2Ts |
| response boundary resolved by sequence mapping | 242,834. 155 unresolved (ring overwritten) |
| sequence-mapped notification earlier than the last data handed to TCP (causality violation) | **0** |
| "first notify since drain" heuristic earlier than the sequence-mapped boundary | 242,587. The difference was < 2 µs for 95 % of them, and up to 4–8 ms in the tail. This is why it was rejected (§5.4). |

**Where the time went** (means over 242,873 complete R2T writes; exact per-CPU sums)

| Stage | Mean | Share |
|---|---|---|
| A block submission | 2.6 µs | 0.04 % |
| B1+B2 command transmit | 10.8 µs | 0.18 % |
| C1+D1r+D3r command → R2T parsed (round trip 1; R2T receive wakeup mode 4–8 µs) | 264.0 µs | 4.3 % |
| B3 R2T parsed → data send starts | 6.5 µs | 0.11 % |
| B4 data transmit, 94 % busy in `try_send_data` | 13.6 µs | 0.22 % |
| **C3 data handed to TCP → response delivered by TCP** (remote/transport, upper bound) | **5,804.4 µs** | **95.0 %** |
| D1+D3 response delivered → parsed (local receive, lower bound) | 7.2 µs | 0.12 % |
| E1 completion handoff | 2.8 µs | 0.05 % |
| E2 completion processing | 0.4 µs | 0.01 % |
| **request latency** | **6,112.4 µs** | Σ stages = 6,112.4 µs |

For this workload the initiator-side local work is ≈ 54 µs (0.9 %) of a 6.1 ms
write. The rest is remote/transport, almost entirely after the data was handed to
TCP. Even with a conservative bound, the sequence-mapped boundary found a few genuine
local outliers: 9 of 242,834 responses waited 4–16 ms between TCP delivery and
processing. Those are the commands for which the slow-command view should show
worker and CPU evidence.

### 10.3 READ data phase (D7/D8), 8 KiB reads

An operator-provided 8 KiB random-read workload (≈ 400k IOPS over 6 controllers),
observed read-only with `tools/feasibility/spike4.bt` for 10 s.

- **4,035,299 READs fully staged** (99.94 %): 2,522 had no send stamp because they
  were in flight at attach, and 34 C2H copies were unmatched.
- A first run that kept its `(queue, cid)` index without cleanup hit bpftrace's
  default 4,096-key map limit; about 24,576 `(queue, cid)` combinations are live here.
  That run left 80 % of reads unmatched. This is a sizing lesson the real loader
  carries over: index entries are deleted at completion, and the maps are sized from
  topology (`architecture.md` §7.2).
- Shape: send → first data copy 0.5–2 ms; data-phase span < 1 µs (one C2H PDU,
  1.008 copies per read on average); last copy → `nvme_complete_rq` 0.5–2 µs.
- **Multi-PDU READs (≥ 128 KiB) are still unvalidated** on this host: the observed
  READ workloads were 8 KiB here and up to 1 MiB in §10.1, which predates D8.

## 11. Validation strategy for the model

Boundary-attribution tests (loopback harness, implementation plan §5) inject a known
delay into one place and check that **only** the expected stage moves:

| Injection | Expected to move | Must not move |
|---|---|---|
| `netem delay` X µs on the target link | C1 (and C3 for R2T writes) by ≈ X | A, B, D, E |
| null_blk `completion_nsec` Y | C1 by ≈ Y | A, B, D, E |
| CPU hog pinned to the queue's `io_cpu` | B1, D1 | C (beyond noise) |
| `netem loss` | C, retransmission counters of that queue's socket | other queues' sockets |
| block-layer delay (scheduler or plugging) | A | B–E |
| completions forced across CPUs (`rq_affinity`) | E1 | others |

The sum check (Σ stages = request latency) runs on every record in tests and as a
continuous self-check (`order_violations`, `partial_records` counters).

Cross-tool comparison: ntprof's host-only boundaries `H_START`, `H_QUEUE_RQ`,
`H_CMD_SENT`, `H_NVME_DONE` and `H_BLK_DONE` are the same kernel events as
`E_START`, `E_SETUP`, `E_CMD_SENT`, `E_NVME_DONE` and `E_BLK_DONE`. Stage means are
compared with ntprof on the same workload. Where boundaries differ (for example,
ntprof always uses skb arrival), the comparison is per matching component only.
Differences that come from different boundaries are not bugs.

## 12. Latency Amplification Degree (compare)

For two captures (baseline B, loaded L), per comparable group (operation, protocol
variant, size class, and optionally controller):

```
LAD(stage) = mean_L(stage) / mean_B(stage)
```

A stage is comparable only if both captures measured it with the same **boundary
signature**: the set of boundary sources and the rx-timestamp mode, recorded in each
capture. Both must also have at least N complete records (default 100). Otherwise the
compare output prints `not comparable` and the reason (different instrumentation,
too few samples, stage unavailable). The stage with the largest LAD is highlighted,
following NTProf (NSDI '25), applied to initiator-observable stages only. The
combined remote/transport stage C is compared like any other. A high LAD there says
"remote/transport got slower". It does not say which of network or target did.
