# Fault injection on a live NVMe/TCP initiator: validation record

Date: 2026-11-13. Host: the development initiator (Rocky Linux 9.6 userspace,
kernel 6.12.117-1.el9, 6 NVMe/TCP controllers to one subsystem, 8 I/O queues
each, native multipath with the round-robin policy).

**Workload.** An operator-provided `elbencho` run: 32 KiB random O_DIRECT writes,
32 threads × iodepth 16, on XFS over md RAID0 of the namespaces, about 48k
writes/s in total. Writes larger than about 8 KiB use R2T on this target
(`latency-model.md` §10.2).

**Authorization.** The operator stated that the host is not production and
authorized fault injection on it. nvmetea stayed read-only; every impairment was
made by `tools/faultinject/nvmetcp-faults.sh`.

## Method

The script impairs **one** controller (nvme4). Its target address is used by no
other controller, and five other live paths kept the workload running. Phases:

| Phase | Length | Impairment |
|---|---|---|
| baseline | 15 s | none (redirect installed, netem pass-through) |
| loss | 25 s | `netem loss 1%` on egress to nvme4's target |
| recover1 | 15 s | none |
| delay | 25 s | `netem delay 2ms` on the same egress |
| recover2 | 15 s | none |
| rst | 35 s | `ss -K` destroys nvme4's qid-3 connection |

**Observers.** nvmetea observed throughout:
- `top -i 1 --json`, with the event log, slow commands and transport context;
- one `queues --json` interval spanning each phase;
- `tcp --json` before and after the RST.

`tools/faultinject/analyze.py` turns these into the tables below.

There were two runs.
- **Run 2 is the clean record.** Only nvme4's packets were redirected (clsact
  egress u32 → mirred) to a temporary ifb whose root qdisc is netem. Phases
  switched with `tc qdisc change`, which is lossless.
- **Run 1 replaced the NIC's root qdisc** with prio + netem. It replicates every
  result, but it had harness artifacts (§5).

Unless noted, numbers are from run 2.

## 1. Packet loss: attribution to the right connections

Per-connection counters from one `queues` interval (22 s) inside the loss phase,
summed per controller:

| Controller | RETR_EV (T3) | recovery entries (T5) | RTO entries (T5) | retrans seg/s (`tcp_info`) |
|---|---|---|---|---|
| **nvme4 (impaired)** | **7,399** | **4,948** | **52** | **392** |
| nvme2, nvme3, nvme5, nvme6, nvme7 | 0 each | 0 | 0 | 0.0 |

- **Cross-check.** netem dropped **6,324** skbs in the phase.
  - RETR_EV counts retransmitted skbs from `tcp_retransmit_skb`. It is 17 % above
    the drops: RTO recovery retransmits more than the lost skb, and tail-loss
    probes add more.
  - `tcp_info` counts segments; under TSO, skb and segment counts differ, as
    labelled. The 392 seg/s × 22 s ≈ 8.6k segments is the same order.
  - Run 1: 7,177 drops, 8,166 RETR_EV.
- **Baseline.** During the 12 s baseline interval, nvme4 had 1 retransmission
  and 1 recovery entry; every other controller had 0.
- **Slow commands.**
  - nvme4 had 89 slow commands in the loss phase; **74 (83 %)** had transport
    events on their own queue's connection within ±50 ms.
  - The other controllers had 33 slow commands and **0** with events. Run 1:
    102 of 135 on nvme4.

  A typical record:
  ```
  slow write nvme4/q4 nsid 5 32KiB: request 210.52ms (A 2.3us, cmd 210.51ms, E2 1.5us) cpu 30->27
    | conn srtt 167us (min 13us)
    | TCP on this queue's connection: 6x congestion: fast recovery, 1x congestion: loss (RTO), 11x retransmission
  ```
  It answers the tool's question directly:
  - 210.5 ms of the 210.52 ms is between dispatch and NVMe completion (CMD);
  - the local stages are 2.3 µs and 1.5 µs;
  - the queue's own connection went through an RTO (~200 ms minimum) inside
    the command's lifetime.

  The record shows this as context next to the command, not as a cause.
- **Latency.**
  - nvme4's mean write CMD rose from 8.06 ms (baseline) to 10.79 ms, and p99
    from 18.9 ms to 27.3 ms.
  - The other controllers moved between −1.3 ms and +1.2 ms (the target's own
    variation).
  - A p50 (~3 µs) and E2 p50 (~1 µs) were unchanged on every controller.

## 2. Added delay: visible in RTT and CMD, not in events

| Controller | RTT median (queue connections) | write CMD mean, baseline → delay | A p50 / E2 p50 |
|---|---|---|---|
| **nvme4 (impaired)** | **58 µs → 2,060 µs** (+2.00 ms) | **8.06 → 12.55 ms (+4.49 ms)** | 3.1 / 1.0 µs, unchanged |
| others | unchanged (48–246 µs) | −1.8 … +0.5 ms | unchanged |

- **RTT.** `tcp_info` RTT on nvme4's connections rose by exactly the injected
  2 ms. No other controller changed.
- **CMD.** nvme4's CMD rose by 4.49 ms (run 1: 3.07 ms; against the recovery
  phases: 3.4–3.9 ms).
  - The expected wire cost for an R2T write is +4 ms, because the command
    capsule and the H2C data each cross the delayed egress.
  - The rest is within the target's own drift, which moved the other
    controllers by up to ±1.8 ms.
  - Level 1 cannot split wire time from target time inside CMD. Level 2 can:
    C1 (command → R2T) and C3 (data → response) each carry one crossing.
    That is Phase 3 part 2.
- **No events, correctly.** Delay without loss produces no retransmission, RST
  or congestion events. Slow commands in this phase therefore carried "no TCP
  events on this queue's connection".
- **RTT context added.** Before this run, nothing pointed at the transport.
  `top` now attaches the connection's smoothed and minimum RTT to every slow
  command:
  ```
  slow write nvme4/q6 nsid 4 32KiB: request 30.67ms (A 1.4us, cmd 30.67ms, E2 0.6us) cpu 46->43
    | conn srtt 2.05ms (min 12us) | no TCP events on this queue's connection
  ```
  The median srtt on slow nvme4 commands was 2,060 µs in the delay phase. On
  other controllers' slow commands it was 144 µs.

## 3. Connection reset: transport events and controller lifecycle

`ss -K` aborted nvme4's qid-3 connection: `tcp_abort` → `ECONNABORTED`, active
RST, `TCP_CLOSE`. That triggered nvme-tcp error recovery. nvmetea recorded:

**Transport events (T3–T7)**, matching `tcp_abort` and the driver's teardown:

| Connection | Events |
|---|---|
| nvme4 q3 (the aborted one) | RST sent, socket error 103 (`ECONNABORTED`), ESTAB → CLOSE |
| nvme4 q0–q2, q4–q8 | ESTAB → FIN-WAIT-1 (`kernel_sock_shutdown` in queue teardown) |
| all other controllers | none |

**Controller lifecycle (L3 kprobe, poll and uevent)**:

| Time (s) | Source | Transition |
|---|---|---|
| 0 | bpf | live → resetting |
| +0.004 … +0.010 | bpf | 9 × resetting → resetting **rejected**: further error-recovery attempts from the other queues' sockets, refused by the state machine |
| +0.011 | bpf | resetting → connecting (teardown took 11 ms) |
| +0.472 | poll | live → connecting. The 1 s poll missed `resetting`, so the precise sequence comes only from BPF |
| +10.751 | bpf, uevent | connecting → live (`reconnect_delay` = 10 s, plus about 0.75 s to connect) |

- **Generation and epoch.** The generation stayed at 4 (same controller); the
  epoch went from 1 to 2.
- **Connections.** After the reconnect, all **9 of nvme4's connections had new
  cookies and ports**, and all 45 of the other controllers' connections were
  unchanged.
- **Failovers.** **23** commands were counted as failed over when the queues
  were torn down (run 1: 50). They are kept out of the latency histograms, and
  in-flight dropped to 0.
- **Multipath.** During the 10.75 s outage, total completions stayed at 90 % of
  the pre-reset rate: the other five paths went from 39,991 to 43,359 writes/s.
  nvme4 completed 169k writes in the 32 s RST interval; the other controllers
  completed about 261k each.
- **Closed connections.** All nine old connections are reported `closed: true`
  in the RST interval, with the events that ended them: q3 has resets = 1,
  socket_errors = 1, state_changes = 1, and the others have state_changes = 1.
  Before this run they were silently missing (§4).

## 4. Changes made because of these runs

| Finding | Change |
|---|---|
| `queues` listed only connections in the current queue table. A connection reset during the interval disappeared, together with the RST and error that ended it. | `engine::queue_connections` takes the previous and current queue tables. Connections that are gone are reported with `closed: true` and their event deltas: the BPF LRU keeps the closed socket's counters. `tcp_info` is unavailable with the new reason `connection_closed`, and the table shows `CLOSED(<last state>)`. Unit test `connection_closed_during_interval_keeps_its_events`. |
| A reconnect emits about 11 uevents within 40 ms: the controller, plus a change on every namespace of the multipath head. `top` re-sampled on each, so it computed rates over 4 ms intervals. | `top` collects a uevent burst for up to 100 ms before sampling. Run 2 shows one 0.325 s sample at the reconnect. |
| Delay leaves no transport events, so slow commands under pure delay pointed nowhere. | `top` adds `conn srtt X (min Y)` to every slow command (sock_diag, joined by cookie). |

Tests: `cargo test --workspace` **84 passed** (one new); `clippy -D warnings` and
`fmt --check` are clean.

## 5. Harness findings (not nvmetea defects)

- **Replacing the NIC's root qdisc (run 1) disturbs every controller.**
  - Each swap (mq → prio → mq) discarded the packets queued on all tx queues.
    nvmetea saw this correctly as a burst of 70–100 retransmissions and fast
    recoveries on *every* controller at each phase boundary. That is itself a
    clean example of a host-wide versus a per-connection transport event.
  - When the root was deleted, the kernel re-created default fq_codel children
    with `quantum 9014` (the current MTU), not the boot-time `quantum 1514`.
  - The default qdiscs have handle 0 and cannot be `change`d. The quantum
    therefore stays 9014 until the qdiscs are next re-created (e.g. reboot).
    Run 2 left the qdiscs byte-identical, compared automatically.
- **Adding or removing clsact also causes a one-time, device-wide blip.** On
  every controller, 13–23 retransmissions and a few CWR and recovery entries
  appeared at the moment the redirect was installed, 2 s before the baseline.
  This is consistent with the device's tx queues being deactivated during the
  graft. It falls outside every measured phase; in-phase switches use
  `tc qdisc change` on the ifb only.
- **Removing the delay reorders packets.** When `delay 2ms` was switched back to
  pass-through, new packets overtook the ones still held in netem. Within the
  same millisecond, nvmetea attributed 37 retransmissions and 8 fast-recovery
  entries across nvme4's eight I/O queues, and none to other controllers.
  These are spurious retransmits from duplicate ACKs. They occurred between two
  phase marks, so they are in no phase's interval.
- **netem statistics count `Sent … pkt` in GSO segments, but drops in skbs.**
  The drop ratio against the "sent" count therefore reads 0.6 % for `loss 1%`.

## 6. Not validated by these runs

- **RST received** (a target-side reset) and target-initiated close. Only a
  host-side abort was exercised; the T6 receive hook has not yet fired on an
  NVMe socket.
- Keep-alive timeout, I/O timeout and controller *removal* paths. `ctrl_loss_tmo`
  is off on this host, so the controller always reconnects.
- **Loss on the receive direction.** Responses and R2Ts were not impaired;
  egress-only netem cannot reach them.
- The wire versus target split inside CMD (Level 2, Phase 3 part 2).
- Read workloads under fault: this workload was writes only.
