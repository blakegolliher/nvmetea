# Phase 3 (part 1) — Queue ↔ TCP connection correlation: validation record

Date: 2026-11-13. Host: the development initiator (Rocky Linux 9.6 userspace,
kernel 6.12.117-1.el9, 6 NVMe/TCP controllers × 9 queues = 54 connections).
All runs only observed traffic; the workloads were operator-provided.

Driver-stage timing (D1–D13, Level 2) is the second part of Phase 3 and is not
covered here.

## What was built

**`bpf/tcp_sock.bpf.c`** (Dual MIT/GPL, CO-RE), loaded independently of the
Level 1 object:

| Program | Attach | Role |
|---|---|---|
| `nvt_iter_tcp` | `iter/tcp` (T1) | On demand, walks the kernel's TCP sockets. A socket counts as an NVMe/TCP queue socket only when `sk_user_data → nvme_tcp_queue → sock → sk` points back to it and the controller's `ops->name == "tcp"`. Emits cookie, controller instance, qid (`(queue − ctrl->queues) / sizeof`, bounds-checked against `queue_count`), 4-tuple, state, `io_cpu`, digest and TLS flags. Generates missing cookies (`bpf_get_socket_cookie`). |
| `nvt_tcp_retransmit` | `raw_tp/tcp_retransmit_skb` (T3) | retransmissions |
| `nvt_sock_state` | `raw_tp/inet_sock_set_state` (T4) | state changes |
| `nvt_cong_state` | `raw_tp/tcp_cong_state_set` (T5) | entries into CWR / Recovery / Loss (absent on 5.15, so optional) |
| `nvt_rst_rx`, `nvt_rst_tx` | `raw_tp/tcp_receive_reset`, `tcp_send_reset` (T6) | RSTs |
| `nvt_sk_error` | `raw_tp/inet_sk_error_report` (T7) | socket errors (`sk_err`) |

- **Events.** These are attributed in the kernel to (controller, qid), counted
  exactly per socket cookie in an LRU map, and emitted, rate-limited, with
  CLOCK_MONOTONIC timestamps.
- **Loading.** Every program attaches individually and is optional. If the
  iterator cannot load, the object reloads without it and the event hooks keep
  working.
- **Cost.** The iterator has no per-packet cost. The event hooks run for every
  TCP event on the host and return after a few reads for non-NVMe sockets.

**Userspace**:
- `nvmetea-bpf::tcpsock`.
- `nvmetea-core::engine::queue_connections`, which joins T1 with sock_diag
  `tcp_info` by cookie and adds BPF event deltas.
- The kernel-identified ownership replaces the Phase 1 endpoint match whenever it
  is available. Disagreements are counted.

**CLI**:
- `nvmetea tcp` (root) fills QID and IO_CPU and adds RETR_EV/RST/ERR per
  connection. Unprivileged, it keeps the endpoint match and states why.
- `nvmetea queues` adds a QUEUE CONNECTIONS table: RTT, RTT variance, cwnd,
  unacked, lost, retransmit rate, retransmit/loss/recovery/RST/error events,
  send queue, notsent, busy/rwnd/sndbuf-limited %.
- `nvmetea top` shows transport events and annotates every slow command with the
  transport events on *its own queue's connection* within ±50 ms of its lifetime.
  That is shown as context, not as a cause.
- `nvmetea probe --load` loads, iterates and detaches the TCP object too.

## Automated tests

`cargo test --workspace`: **83 passed, 0 failed**; `clippy -D warnings` and
`fmt --check` clean. New in this part:
- iterator address decoding (IPv4, v4-mapped IPv6);
- event record parsing;
- the cookie join with event deltas, including a queue socket missing from the
  dump (unavailable, not zero) and hooks that ran but saw nothing (a measured zero);
- CLI without BPF: `association: derived`; QID, IO_CPU and event fields
  unavailable with reasons; empty connection list.

## Live results

| Check | Result |
|---|---|
| Load / attach (TCP object) | 19 ms / 0.4 ms. All 7 programs attached (iterator + 6 raw tracepoints) |
| Iterator | **54 queue sockets in 0.72 ms** |
| Iterator table vs Phase 0 bpftrace recordings (a different method: setup-path `sk_user_data`) — cookie, local port, io_cpu for every (controller, qid) | **54/54 identical** |
| Iterator table vs `ss -tnie` — cookie and remote endpoint | **54/54 identical** |
| Kernel-identified controller vs Phase 1 endpoint match | 0 disagreements |
| `queues --json` vs `tcp --json` cookies per (controller, qid) | 0 mismatches. Every controller has qids 0–8; all 54 carry `tcp_info` and event counts |
| Admin queue `io_cpu` | reported as unbound (`WORK_CPU_UNBOUND`), matching the driver |
| Event hooks execute and the NVMe filter rejects other sockets | 5 loopback connections to local sshd during an observation: **46 TCP events seen host-wide, 0 attributed to NVMe** |
| Slow-write annotation (writes of 36–47 ms) | "no TCP events on this queue's connection": local transport symptoms are absent for those commands |
| After exit | 0 programs, 0 links |

## Not yet validated

- ~~**Positive event path on an NVMe socket.**~~ Validated later the same day by
  fault injection on this host: packet loss, added delay and a connection reset on
  one controller. See `docs/validation/fault-injection.md`. A target-side reset
  (RST received) is still to be exercised in the loopback harness VM
  (implementation plan §4, case 9).
- `tcp_cong_state_set` is absent on Ubuntu 5.15. There, congestion state is
  available only as `tcpi_ca_state` from sock_diag (planned fallback; not yet
  displayed).
- TLS-enabled queues: the flag is reported, but no TLS connection exists here.
- **Retransmission units.** RETR_EV (tracepoint, skbs) and RETRANS/RETR/s
  (`tcp_info`, segments) can differ under TSO. Both are labelled.
