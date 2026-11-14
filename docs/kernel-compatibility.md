# nvmetea — Kernel compatibility and probe feasibility

Status: Phase 0 deliverable. Last updated 2026-11-13.

This document records what nvmetea can rely on in each supported kernel family,
what it must discover at run time, and what evidence supports each claim. The
probe catalog in section 5 is the instrumentation matrix that the loader (Phase 2+)
implements.

## 1. Principles

1. **Detect, never infer.** `uname -r` is not used to decide anything; it is
   printed for the operator. RHEL/Rocky 5.14 kernels carry 6.x backports; Ubuntu
   ships GA, HWE, OEM and cloud flavours of the same version number.
2. A capability is reported **supported** only after its dependencies are verified
   on the running system: interface present, permission granted, BTF types
   resolvable, program accepted by the verifier, and attach succeeded.
3. Every unavailable capability carries a **reason code** (section 6.3) and the
   metrics that depend on it are reported as unavailable, never as zero.
4. One kernel family's behaviour is never assumed for another: the probe catalog
   lists per-build evidence and the runtime planner re-checks it.

Evidence classes used below:

| Code | Meaning |
|---|---|
| **R** | Runtime-validated: programs loaded, attached and produced cross-checked data on a live NVMe/TCP initiator |
| **B** | Binary-inspected: the distribution's own `vmlinuz`, `config` and module `.ko` files were inspected offline (BTF types, BTF `FUNC` records, ELF symbol tables). Not booted. |
| **S** | Source-inspected: kernel source at the named tag/tree. Compiled inlining is **not** knowable from source. |

## 2. Kernels examined in Phase 0

| Kernel | Distribution | Evidence | Notes |
|---|---|---|---|
| 6.12.117-1.el9 | Rocky 9.6 userspace, non-distribution LTS kernel (development host) | **R** + B | Live initiator: 6 NVMe/TCP controllers to one subsystem, 1 admin + 8 I/O queues each, native multipath, plus one PCIe controller |
| 5.14.0-570.58.1.el9_6 | Rocky Linux 9.6 distribution kernel | B | Modules on disk; `vmlinuz` from the Rocky mirror |
| 5.14.0-687.66.1.el9_8 | Rocky Linux 9.8 distribution kernel | B | Installed, not booted |
| 5.15.0-198-generic | Ubuntu 22.04 GA | B (+S jammy tree at 5.15.189) | `nvme-tcp.ko` is in `linux-modules-extra` |
| 6.8.0-149-generic | Ubuntu 24.04 GA (same source as 22.04 HWE 6.8) | B (+S noble tree) | |
| 6.17.0-42-generic | Ubuntu 24.04 HWE | B | |
| v5.14, v5.15, v6.1, v6.5, v6.8, v6.11, v6.12, v7.3 | upstream | S | `drivers/nvme/host/{tcp,core,multipath,trace,nvme}.*`, `include/trace/events/block.h`, `block/blk-mq.c` |
| CentOS Stream 9 `main` | RHEL 9 development tree | S | Proxy for RHEL 9 backports; individual Rocky minors may lag |

Runtime validation on the stock Rocky 9 and Ubuntu kernels is still **outstanding**
(section 9). Nothing in this document claims runtime support for them yet.

The offline inspection script is `tools/feasibility/inspect_kernel.sh`; the runtime
feasibility programs are `tools/feasibility/spike3.bt` and `spike4.bt`.

## 3. Capability matrix

`Y` = present and usable, `-` = absent, `i` = present in source but inlined in this
build (no attach point), `c` = only a compiler clone (`.constprop`/`.isra`) exists:
**not** attachable by argument (see F4).

### 3.1 Platform

| Capability | el9 6.12 (R) | Rocky 9.6 | Rocky 9.8 | Ubuntu 5.15 | Ubuntu 6.8 | Ubuntu 6.17 |
|---|---|---|---|---|---|---|
| vmlinux BTF (`CONFIG_DEBUG_INFO_BTF`) | Y | Y | Y | Y | Y | Y |
| BPF ISA v3 with atomic fetch operations (objects are built with `-mcpu=v3`; kernel 5.12+) | Y | Y | Y | Y | Y | Y |
| Module BTF (`CONFIG_DEBUG_INFO_BTF_MODULES`, `.BTF` in `nvme-tcp.ko`, `nvme-core.ko`) | Y | Y | Y | Y | Y | Y |
| `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS` (fentry/fexit) | Y | Y | Y | Y | Y | Y |
| `CONFIG_FPROBE` (kprobe_multi) | Y | Y | Y | - | Y | Y |
| `CONFIG_KPROBE_EVENTS` | Y | Y | Y | Y | Y | Y |
| `CONFIG_INET_DIAG` / `INET_TCP_DIAG` | built-in | built-in | built-in | **module** | **module** | **module** |
| `CONFIG_NVME_TCP_TLS` | Y | Y | Y | - | Y | Y |
| `CONFIG_NVME_MULTIPATH` | Y | Y | Y | Y | Y | Y |
| null_blk, nvmet-tcp, netem as modules (test harness) | Y | Y | Y | Y | Y | Y |
| `bpf_fentry_test1` (fentry preflight target) | Y | Y | Y | Y | Y | Y |

### 3.2 Tracepoints (BTF `btf_trace_*` typedefs present)

| Tracepoint | el9 6.12 | Rocky 9.6 | Rocky 9.8 | Ubuntu 5.15 | Ubuntu 6.8 | Ubuntu 6.17 |
|---|---|---|---|---|---|---|
| `nvme:nvme_setup_cmd(req, cmd)` | Y | Y | Y | Y | Y | Y |
| `nvme:nvme_complete_rq(req)` | Y | Y | Y | Y | Y | Y |
| `nvme:nvme_async_event`, `nvme:nvme_sq` | Y | Y | Y | Y | Y | Y |
| `block:block_rq_complete`, `block_rq_issue`, `block_rq_insert`, `block_rq_requeue`, `block_bio_queue`, `block_bio_remap` | Y | Y | Y | Y | Y | Y |
| `block:block_io_start` / `block_io_done` | Y | Y | Y | **-** | Y | Y |
| `block:block_rq_error` | Y | Y | Y | **-** | Y | Y |
| `tcp:tcp_retransmit_skb`, `tcp_probe`, `tcp_send_reset`, `tcp_receive_reset`, `tcp_destroy_sock`, `tcp_rcv_space_adjust` | Y | Y | Y | Y | Y | Y |
| `tcp:tcp_cong_state_set` | Y | Y | Y | **-** | Y | Y |
| `sock:inet_sock_set_state`, `sock_exceed_buf_limit`, `sock_rcvqueue_full` | Y | Y | Y | Y | Y | Y |
| `sock:sk_data_ready` (fired by `nvme_tcp_data_ready`) | Y | Y | Y | **-** | Y | Y |

### 3.3 NVMe/TCP host driver attach points (`nvme_tcp` module)

`Y` means: an ELF `FUNC` symbol with exactly this name **and** a BTF `FUNC` record
of the same name. On the R host it was also confirmed in
`available_filter_functions`.

| Function | el9 6.12 | Rocky 9.6 | Rocky 9.8 | Ubuntu 5.15 | Ubuntu 6.8 | Ubuntu 6.17 |
|---|---|---|---|---|---|---|
| `nvme_tcp_queue_rq` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_io_work` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_try_send` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_try_send_cmd_pdu` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_try_send_data` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_try_send_data_pdu` | Y | Y | Y | **i** | Y | Y |
| `nvme_tcp_try_send_ddgst` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_try_recv` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_recv_skb` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_recv_pdu` | **i** | Y | Y | Y | Y | Y |
| `nvme_tcp_recv_data` | **i** | Y | Y | Y | Y | Y |
| `nvme_tcp_handle_c2h_data` | i | i | i | i | **Y** | i |
| `nvme_tcp_handle_r2t` | i | i | **c** | i | **Y** | **Y** |
| `nvme_tcp_handle_comp`, `nvme_tcp_process_nvme_cqe` | i | i | i | i | i | i |
| `nvme_tcp_setup_h2c_data_pdu` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_setup_cmd_pdu` | **i** | Y | Y | Y | Y | Y |
| `nvme_tcp_data_ready`, `nvme_tcp_state_change`, `nvme_tcp_write_space` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_poll` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_timeout` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_error_recovery_work`, `nvme_tcp_reconnect_ctrl_work` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_set_queue_io_cpu` | i | i | Y | i | Y | Y |

### 3.4 nvme-core and vmlinux functions used by fallbacks

| Function | Availability (R on 6.12, B elsewhere) | Used for |
|---|---|---|
| `nvme_change_ctrl_state` (nvme_core) | Y on all six | controller state transitions |
| `nvme_init_ctrl` / `nvme_uninit_ctrl` | Y on all six | controller object creation/destruction → BPF-side controller generation |
| `nvme_failover_req`, `nvme_cancel_request`, `nvme_keep_alive_end_io`, `nvme_host_path_error` | Y on all six | failover, cancel, keep-alive latency, path errors |
| `nvme_retry_req` | Y except **Ubuntu 5.15** (inlined) | retry decision; fallback: re-dispatch at P1 with `retries` > 0 |
| `nvme_mpath_start_request`, `nvme_end_req`, `nvme_complete_batch_req` | Y except **Ubuntu 5.15** | not required; informational |
| `blk_mq_complete_request_remote` (vmlinux BTF) | Y (B) | completion parsed, before any IPI |
| `skb_copy_datagram_iter` (vmlinux BTF) | Y (B) | READ data copy |
| `skb_copy_and_hash_datagram_iter` | Y except **Ubuntu 6.17** | READ data copy with data digest |
| `kernel_sendpage`, `sock_no_sendpage` | 5.14 (RHEL 9), 5.15 only | send fallback where `try_send_*` are inlined |
| `sock_sendmsg` | Y | send fallback (6.5+ path) |

### 3.5 Structure layout and semantics

| Item | el9 6.12 | Rocky 9.6 | Rocky 9.8 | Ubuntu 5.15 | Ubuntu 6.8 | Ubuntu 6.17 |
|---|---|---|---|---|---|---|
| `nvme_request.genctr` (cid = genctr<<12 \| tag) | Y | Y | Y | Y | Y | Y |
| `nvme_request.start_time` (multipath head accounting) | Y | Y | Y | **-** | Y | Y |
| `request.start_time_ns`, `io_start_time_ns`, `alloc_time_ns` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_queue.{sock, io_cpu, pdu, request, ctrl, nr_cqe}` | Y | Y | Y | Y | Y | Y |
| `nvme_tcp_queue.tls_enabled` | Y | Y | Y | **-** | Y | Y |
| `nvme_tcp_queue.rcv_hash` / `rcv_crc` | hash | hash | hash | hash | hash | **crc** |
| `nvme_tcp_request.h2cdata_left/offset` | Y | Y | Y | **-** | Y | Y |
| `nvme_tcp_request.data_recvd` | Y | **-** | Y | **-** | Y | **-** |
| `sock_common.skc_cookie` | Y | Y | Y | Y | Y | Y |

## 4. Findings that drive the design

**F1 — `nvme_complete_rq`'s `cid` field changed meaning (S).** In upstream v5.14 and
v5.15 the completion tracepoint records `req->tag`, while `nvme_setup_cmd` records
`cmd->common.command_id` (`genctr << 12 | tag` since 5.15). From v6.1 both record the
command id. The fix is in the current jammy tree (5.15.189), CentOS Stream 9, and
noble. Older Ubuntu 22.04 kernels predate it. Consequences:

- Primary correlation never uses tracepoint text fields. It keys on the request
  address taken from the raw tracepoint arguments (section 5, P1/P2).
- The text-format fallback (P1b) matches on `(ctrl_id, qid, cid & 0x0fff)`. That is
  the tag, which is unique while the command is in flight. It checks the generation
  bits only when both events carry them.

**F2 — Command ids are reused (S, R).** A 4-bit generation counter is folded into
the cid, so at a constant tag the cid repeats every 16 dispatches. Each dispatch,
including a retry, increments `genctr`. Run-time check on the R host: 183,601
commands, every `command_id == (genctr & 0xf) << 12 | tag`, with no exceptions. The cid
is therefore an in-flight identity only. It is never used as a permanent request id.

**F3 — Inlining differs per build (B, R).** See 3.3. The same source compiles
`nvme_tcp_recv_pdu`, `nvme_tcp_recv_data` and `nvme_tcp_setup_cmd_pdu` out of line on
Rocky 9 and Ubuntu, but inlines them on the el9 6.12 build. Only Ubuntu 6.8 keeps
`nvme_tcp_handle_c2h_data` out of line. Probe selection is per running kernel, from
`available_filter_functions` + BTF + kallsyms, never from a table like 3.3.

**F4 — BTF can name a function that has no attachable symbol (B).** Rocky 9.8's
module BTF has `FUNC nvme_tcp_handle_r2t`, but the only text symbol is
`nvme_tcp_handle_r2t.constprop.0`, a clone whose calling convention differs from the
BTF prototype. Attach rule: a function hook is eligible only if **(a)** a BTF `FUNC`
with that exact name exists, **(b)** a text symbol with exactly that name exists in
`/proc/kallsyms` for the right module, and **(c)** the name is in
`available_filter_functions` (for fentry). Symbols with `.constprop`, `.isra`,
`.part` or `.cold` suffixes are never probed by argument.

**F5 — Send API changed in 6.5 (S, B).** Upstream ≤ 6.4, Ubuntu 5.15 and RHEL 9 send
with `kernel_sendpage()`. 6.5+ use `sock_sendmsg()` with `MSG_SPLICE_PAGES`. This only
matters for the fallback used where all three `try_send_*` helpers are inlined (not
observed in any build examined; ntprof reports it for MLNX OFED on 5.15).

**F6 — `block_io_start`/`block_io_done` exist from 6.5, and are backported to RHEL 9
(S, B).** They are absent on Ubuntu 5.15. nvmetea does not require them. The request
start boundary comes from `rq->start_time_ns` (F11).

**F7 — Multipath head I/O accounting exists from upstream ≈6.3 and in RHEL 9 (S, B).**
It is absent on Ubuntu 5.15 (`nvme_request` has no `start_time`). On those kernels
`/proc/diskstats` for `nvmeXnY` stays at zero while the hidden per-path devices
`nvmeXcYnZ` count I/O. The passive collector detects this (head counters flat while
path counters move) and derives namespace totals by summing paths. That is marked
`derived`. Where head accounting exists, it starts at dispatch on the path
(`nvme_mpath_start_request`) with jiffies resolution. It is not the same boundary as
the bio submission.

**F8 — Event tracepoints vary (B).** `sk_data_ready` (the clean per-socket "data
reached nvme-tcp" boundary), `tcp_cong_state_set` and `block_rq_error` are missing on
Ubuntu 5.15. Each dependent metric has its own fallback: a function hook on
`nvme_tcp_data_ready`, `tcp_info.tcpi_ca_state` sampling, and the
`block_rq_complete` error argument.

**F9 — Structure fields drift (B).** `tls_enabled` is absent on 5.15. `rcv_hash`
became `rcv_crc` in 6.17. `data_recvd` and `h2cdata_*` come and go. BPF code reads
optional fields only under `bpf_core_field_exists()` and never depends on fields it
does not need.

**F10 — `io_cpu` must be read, not computed (S, R).** Upstream 6.12 assigns
`io_cpu = cpumask_next_wrap(qid - 2, …)`. The el9 6.12.117 build spreads I/O queues
per controller (observed io_cpus 0–61 across 48 queues). The admin queue, and every
queue when `wq_unbound=Y`, use `WORK_CPU_UNBOUND` (observed value 8192). nvmetea reads
`queue->io_cpu` through BTF.

**F11 — The request start timestamp is conditional (S, R).** `rq->start_time_ns` is
set only when `blk_mq_need_time_stamp()` is true, which is typically iostats
enabled. It is 0 for admin requests. Observed on the R host: all 36 admin keep-alive
requests had 0, and all 183,565 I/O requests had a valid value. From upstream 6.9
(and in CentOS Stream 9) the value comes from `blk_time_get_ns()`, which may return
the plug's cached time. That can be earlier than the real allocation by up to the
plug duration. The block-submission stage can therefore be **overstated** by that
amount. When `start_time_ns == 0`, the end-to-end interval is unavailable for that
command. The narrower dispatch-to-completion interval is reported under its own
name.

**F12 — sock_diag sees nvme-tcp kernel sockets without privileges (R).** `ss -tnie`
as an unprivileged user listed all 54 sockets with full `tcp_info` and a socket
cookie. The cookie is generated lazily on the first sock_diag query. The BPF value
`skc_cookie` read through `queue->sock->sk` matched the sock_diag cookie for all 54
queues (e.g. cookie `0x2001` and local port 38616 on both sides). This is the
queue↔socket join key. On Ubuntu, `inet_diag`/`tcp_diag` are modules. A sock_diag
query may autoload them, and `nvmetea probe` reports whether they are loaded.

**F13 — Data-digest receive path differs on 6.17 (B).**
`skb_copy_and_hash_datagram_iter` is gone. READ data-phase staging with data digests
enabled is unsupported until validated there. The command-level latency is
unaffected.

**F14 — BTF-typed tracepoint pointers cannot be offset (R).** The verifier rejects
`rq + sizeof(struct request)` on a `tp_btf` argument ("pointer arithmetic on
trusted_ptr_or_null_ prohibited"). nvmetea therefore uses **`raw_tp`** programs.
Their arguments are scalars; every dereference goes through `BPF_CORE_READ`. The same
approach is used by ntprof.

**F15 — fentry/fexit attach can stall on busy systems (ntprof, S).** Attaching
or detaching trampolines waits for `synchronize_rcu_tasks()`. A thread that never
blocks voluntarily (polling, saturating fio) can hold this wait for tens of seconds.
ntprof measured 33–60 s on a loaded 6.8 guest. nvmetea's attach strategy is in
section 8. On the idle-to-moderately-loaded R host, 11 programs (6 fentry/fexit)
attached in about 3 s, including bpftrace start-up.

**F16 — Sensitive sysfs attributes sit next to the useful ones (R).** Controllers
expose `dhchap_secret`, `dhchap_ctrl_secret` (mode 0600) and, with TLS, `tls_key` and
related attributes. The topology collector reads only an explicit allow-list of
attributes (architecture §6.2). It never globs, and it never opens write-only nodes
such as `delete_controller`, `reset_controller` or `rescan_controller`.

**F17 — Kernel lockdown (S).** In `integrity` mode (common with Secure Boot on Ubuntu
and RHEL) kprobes, `bpf_probe_read_kernel` and tracefs remain available.
`confidentiality` mode blocks all three, which leaves Level 0 only. `nvmetea probe`
reads `/sys/kernel/security/lockdown`.

**F19 — Hidden multipath path disks have no sysfs `dev` attribute (R).** The
`nvmeXcYnZ` devices are `GENHD_FL_HIDDEN`. `/sys/block/nvme2c2n1/dev` does not
exist, but the device number appears in `/proc/diskstats` (`259 5 nvme2c2n1 …`).
BPF identifies a request's path by `rq->q->disk->part0->bd_dev`. nvmetea joins
the two through `/proc/diskstats`.

**F20 — CO-RE field kinds must match (R).** Declaring the kernel's
`enum nvme_ctrl_state state` as `int` in `kernel_types.h` makes libbpf reject the
relocation ("failed to resolve CO-RE relocation … nvme_ctrl.state"). Local
declarations use the kernel's kind (enum vs int), not just its size.

**F18 — Admin and PCIe traffic share the core tracepoints (R).** `nvme_setup_cmd` fires
for every transport. The R host's PCIe controller produced 16 commands during the
run. The NVMe/TCP test is
`req→queue→sock→sk→sk_user_data == queue`, as in ntprof. All 16 PCIe commands were
rejected, and no TCP command was lost.

## 5. Probe catalog (instrumentation matrix)

Each probe has a stable id used in `nvmetea probe` output and in data-quality
reports. "Flavours" lists preference order. "Cost" is a class, not a measurement:
**H** = runs for every I/O, **P** = per packet/skb or per socket call, **E** =
event-rate (rare), **S** = sampled-only work beyond a cheap early return.

### 5.1 Level 1 — command lifecycle (nvme-core and block layer)

| Id | Attach point | Flavours | Provides | Cost | Fallback |
|---|---|---|---|---|---|
| P1 | `nvme:nvme_setup_cmd` | `raw_tp` (CO-RE) → `tracepoint` text (P1b) | dispatch boundary; ctrl instance, qid (queue index), tag, cid, genctr, opcode, nsid, bytes, submit CPU, `rq->start_time_ns`, transport test, queue→socket | H | P1b: offsets parsed from the tracepoint `format` file, key `(ctrl_id, qid, cid&0xfff)`, TCP filter by ctrl_id set, bytes from cdw12 × LBA size |
| P2 | `nvme:nvme_complete_rq` | `raw_tp` → `tracepoint` text | NVMe completion boundary, status, retries, completion CPU | H | as P1b |
| P3 | `block:block_rq_complete` | `raw_tp` | block completion boundary (end-to-end end) | H | none: end-to-end unavailable without P1+P3 on the request address |
| P4 | `block:block_rq_requeue` | `raw_tp` | requeue marker | E | retry count from P2 only |
| P5 | `nvme_failover_req` | fentry → kprobe | multipath failover of a request | E | inferred at P2 from path-error status + `REQ_NVME_MPATH` (derived) |
| P6 | `nvme_retry_req` | fentry → kprobe | retry decision (with delay) | E | P1 re-dispatch with `retries` > 0 (required on Ubuntu 5.15) |
| P9 | `nvme_init_ctrl` exit / `nvme_uninit_ctrl` entry | fexit/fentry → kprobe | controller object lifetime → BPF-side generation number per instance | E | userspace generation from uevents/sysfs (a fast delete+recreate can be misattributed for ≤ 1 poll interval; reported) |
| P7 | `nvme_cancel_request` | fentry → kprobe | host-side cancellation (reset/delete) | E | status `NVME_SC_HOST_ABORTED_CMD` at P2 |
| P8 | `nvme_keep_alive_end_io` | fentry → kprobe | keep-alive completion (per-controller health) | E | admin-queue commands from P1/P2 with opcode 0x18 |

### 5.2 Level 2 — NVMe/TCP driver

| Id | Attach point | Flavours | Provides | Cost | Fallback |
|---|---|---|---|---|---|
| D1 | `nvme_tcp_try_send_cmd_pdu` exit = 1 and `queue->request == NULL` | fexit → kretprobe | command (and in-capsule data) handed to TCP; direct vs worker context | H | D5 |
| D2 | `nvme_tcp_try_send_data` / `_ddgst` exit = 1 and request cleared | fexit → kretprobe | in-capsule write data or solicited H2C data fully handed to TCP | H | D5 |
| D3 | `nvme_tcp_try_send_data_pdu` entry | fentry → kprobe | start of solicited H2C data | H (writes) | D5 (Ubuntu 5.15: inlined) |
| D4 | `nvme_tcp_setup_h2c_data_pdu` entry (inside receive context) | fentry → kprobe | R2T parsed | H (writes) | none (R2T timing unavailable) |
| D5 | `nvme_tcp_try_send` entry/exit + `sock_sendmsg` / `kernel_sendpage` entry | fentry/fexit → kprobe | D1–D3 equivalents where those helpers are inlined (ntprof's fallback) | P | stage B unavailable |
| D6 | `nvme_tcp_io_work` entry/exit | fentry/fexit → kprobe/kretprobe | worker invocations, elapsed time, CPU, quota exhaustion (> 1 ms) | H | worker metrics unavailable |
| D7 | `nvme_tcp_recv_skb` entry/exit | fentry/fexit → kprobe/kretprobe | receive context (queue, skb, arrival stamp) per call | P | receive staging unavailable |
| D8 | `skb_copy_datagram_iter` / `skb_copy_and_hash_datagram_iter` entry (only inside D7 context, only while a sampled READ is in flight) | fentry → kprobe | first/last C2H data copy, data-phase busy time | P/S | READ data phase unavailable (whole span stays "unclassified receive") |
| D9 | `blk_mq_complete_request_remote` entry (inside D7 context) | fentry → kprobe | response parsed, request handed to blk-mq | H | P2 (handoff not separable) |
| D10 | `sock:sk_data_ready` (or `nvme_tcp_data_ready` entry), filtered to queue sockets | `raw_tp` → fentry → kprobe | per-queue ring of `(time, tcp_sock.rcv_nxt)`; mapped to the response skb's `tcp_skb_cb.end_seq` at D7 → sequence-mapped receive notification (latency model §5.4) | P | receive wakeup delay unavailable (C1+D1 merged) |
| D11 | `sched:sched_switch` (only for threads inside D6) | `raw_tp` | off-CPU time inside the worker → on-CPU estimate | P (system-wide context switches) | worker CPU time reported as elapsed only |
| D12 | `nvme_tcp_timeout` | fentry → kprobe | command timeout event (queue, cid) | E | none (timeouts seen only as error status) |
| D13 | `nvme_tcp_poll` entry/exit | fentry → kprobe | receive context for polled queues | P | polled queues: receive staging unavailable |

### 5.3 Level 3 — TCP correlation

| Id | Attach point | Flavours | Provides | Cost | Fallback |
|---|---|---|---|---|---|
| T1 | `iter/tcp` BPF iterator | `iter` | queue → socket table: cookie, 4-tuple, ctrl, qid, io_cpu, digest/TLS flags, validated through `sk_user_data` and the queue index range | on demand | controller-level endpoint match (derived), queue-level unavailable |
| T2 | sock_diag (`NETLINK_SOCK_DIAG`, `INET_DIAG_INFO`, `_SKMEMINFO`, `_CONG`) | netlink, unprivileged | RTT, RTT variance, retransmissions, unacked, cwnd, send/recv queue, notsent, delivery rate, busy/limited times | periodic | `/proc/net/tcp{,6}`: queues, retransmit timer, socket inode; **no RTT** |
| T3 | `tcp:tcp_retransmit_skb` (filtered to NVMe/TCP sockets) | `raw_tp` | timestamped retransmissions per queue socket | E (per retransmit) | T2 counter deltas (no event times) |
| T4 | `sock:inet_sock_set_state` (filtered) | `raw_tp` | connection state changes of queue sockets | E | T2 state polling |
| T5 | `tcp:tcp_cong_state_set` (filtered) | `raw_tp` | entry into loss/recovery states | E | T2 `tcpi_ca_state` sampling (5.15) |
| T6 | `tcp:tcp_send_reset` / `tcp_receive_reset` (filtered) | `raw_tp` | RSTs on queue sockets | E | T2/T4 |

### 5.4 Lifecycle (any level)

| Id | Source | Provides | Fallback |
|---|---|---|---|
| L1 | sysfs reconciliation (`/sys/class/nvme*`) | inventory, state, addresses, queue counts | none needed (always available) |
| L2 | kobject uevents (`NETLINK_KOBJECT_UEVENT`, unprivileged) | controller/namespace add/remove/change, `NVME_EVENT=connected`, `NVME_AEN` | L1 polling |
| L3 | `nvme_change_ctrl_state` fentry/fexit | every state transition with ns timestamp, including transitions shorter than the poll interval | L1/L2 (fast transitions can be missed; reported) |
| L4 | `nvme:nvme_async_event` | AENs (incl. ANA change notices) | L2 `NVME_AEN` |

## 6. Runtime capability discovery (`nvmetea probe`)

### 6.1 Procedure

The probe runs the same planner the collectors use. It changes nothing:

1. **Identity**: `/etc/os-release`, `uname`, architecture, `/proc/sys/kernel/random/boot_id`,
   kernel command line.
2. **Privileges**: effective capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`,
   `CAP_NET_ADMIN`, `CAP_SYSLOG`), `kernel.unprivileged_bpf_disabled`,
   `kernel.perf_event_paranoid`, `kernel.kptr_restrict`, lockdown mode, SELinux/AppArmor
   status.
3. **BTF**: `/sys/kernel/btf/vmlinux`. For each of `nvme_core`, `nvme_tcp`,
   `nvme_fabrics`, check the module is loaded (`/sys/module/<m>`), and check
   `/sys/kernel/btf/<m>` exists and parses with the base BTF.
4. **Tracepoints**: existence through BTF `btf_trace_*` typedefs (needs no tracefs).
   Where tracefs is readable, also check the event directory and `format` file. The
   text fallback depends on it.
5. **Functions**: for each catalog hook, check BTF `FUNC` + exact kallsyms text
   symbol + `available_filter_functions` (rule F4). Note inlining and clones.
6. **BPF features** (libbpf probes): program types (`tracing`, `raw_tracepoint`,
   `kprobe`, `iter`), map types (`ringbuf`, `percpu_array`, `hash`, `lru_hash`),
   helpers (`bpf_ringbuf_reserve`, `bpf_get_socket_cookie` for tracing,
   `bpf_get_attach_cookie`, `bpf_loop`), kprobe_multi, BPF stats (`kernel.bpf_stats_enabled`).
7. **Socket diagnostics**: a sock_diag dump filtered to the discovered target ports.
   Report success, `EPERM`, or "inet_diag not loaded".
8. **Controlled load** (`--load`, default on when privileged): load each BPF object
   **without attaching**. That exercises CO-RE relocation and the verifier. Record
   the verifier log on rejection.
9. **Controlled attach** (`--attach`, opt-in): attach each eligible program for ≤ 2 s
   and detach. fentry candidates first go through the disposable-process preflight
   (section 8).
10. **Plan**: for every metric family, print the chosen backend, the fallback that
    would be used, and the reason the better ones were not chosen.

Output: human-readable by default, `--json` for the same content (schema in
`architecture.md` §9).

### 6.2 Distinguishing failure kinds

| Observation | Classified as |
|---|---|
| attach point absent from BTF/kallsyms/tracefs | `missing_interface` |
| function exists only as an inlined body or a suffixed clone | `inlined` / `unsafe_clone` |
| `EPERM`/`EACCES` from `bpf()` or `perf_event_open()`, or lockdown denial | `permission_denied` / `kernel_lockdown` |
| program rejected at load with a verifier log | `verifier_rejected` (log saved) |
| CO-RE relocation failure (type/field not found) | `btf_mismatch` |
| load OK, attach returns an error | `attach_failed` (errno kept) |
| attach exceeded its time budget | `attach_timeout` |
| prerequisite program/collector unavailable | `dependency_unavailable` |
| module not loaded (e.g. no NVMe/TCP controllers yet) | `module_not_loaded` |
| disabled by option or config | `disabled_by_user` |

### 6.3 Reason codes and remediation

Reason codes are stable strings in JSON and Prometheus (`reason` label of
`nvmetea_capability`). Each carries one-line remediation text, for example:

| Code | Remediation shown |
|---|---|
| `btf_vmlinux_missing` | Kernel built without `CONFIG_DEBUG_INFO_BTF`; only Level 0 and text-format tracepoints are available. |
| `btf_module_missing` | The `nvme_tcp` module carries no BTF (often an out-of-tree/DKMS build). Driver-stage timing is disabled. Provide BTF with `--btf-dir` (generated from module DWARF) to enable it. |
| `permission_denied` | Run as root or grant `CAP_BPF,CAP_PERFMON` (+`CAP_SYSLOG` for symbol checks). |
| `kernel_lockdown` | Lockdown `confidentiality` blocks kernel tracing; only passive monitoring is possible. |
| `inlined` | This kernel inlined `<fn>`; using `<fallback>`. |
| `attach_timeout` | fentry attach waited > N s (busy CPUs holding an RCU-tasks grace period); switched to kprobes. |
| `inet_diag_unavailable` | Socket diagnostics unavailable; TCP RTT and congestion metrics disabled, `/proc/net/tcp` used for queue sizes. |

## 7. Privileges

| Feature family | Minimum |
|---|---|
| Level 0 (sysfs, diskstats, sock_diag, uevents) | none (unprivileged). Some sysfs attributes are root-only; they are listed as such. |
| Reading tracepoint `format` files (text fallback only) | tracefs access (root by default) |
| Level 1–3 BPF | `CAP_BPF` + `CAP_PERFMON`. `CAP_SYS_ADMIN` on kernels/LSM policies that still require it; the probe reports the actual result. |
| kallsyms addresses (attach-rule checks) | `CAP_SYSLOG` or `kptr_restrict` permitting it |
| `iter/tcp` | `CAP_BPF` + `CAP_PERFMON` (reads kernel memory) |

`CAP_BPF` alone is never assumed sufficient. The probe tests the real operation.

## 8. Attach strategy

1. **Flavour per object, then per program.** Prefer `raw_tp` for tracepoints, then
   fentry/fexit for functions when (a) the module has BTF, (b) rule F4 passes, and
   (c) the preflight passes. Otherwise use kprobe/kretprobe. kprobe_multi is used only
   when `CONFIG_FPROBE` and the helper probe pass.
2. **Preflight.** A re-executed helper process (`nvmetea __preflight`) attaches a
   one-instruction fentry program to `bpf_fentry_test1`. If it does not succeed within
   2 s, fentry is skipped. The helper is abandoned, not waited for. A separate process
   is used because `fork()` in a threaded Rust process is unsafe.
3. **Parallel attach with a budget.** fentry programs attach from a small thread pool,
   because ftrace waits overlap. If the whole set exceeds 10 s, nvmetea detaches what
   attached and restarts the object with kprobes. The reason is shown.
4. **Arming.** Every program checks a global `armed` flag. Nothing is counted until the
   whole object set is attached, so commands that started earlier cannot produce
   partial records. Commands in flight at arming time are excluded; their completions
   are counted as `untracked_completion`.
5. **Independence.** Objects are split by level (L1 core, L2 driver, L3 TCP,
   lifecycle). An object that fails leaves the others running. Shared maps are reused
   by file descriptor.
6. **Detach.** On exit, links are dropped in parallel. If detaching takes longer than
   3 s, nvmetea says so and exits; the kernel finishes removal.
7. **Errors are never swallowed.** Verifier logs are captured to the capability report
   and to `--debug` output.

## 9. Validation status and remaining gaps

| Item | Status |
|---|---|
| Level 1 collector (`core.bpf.c`, libbpf CO-RE loader) on el9 6.12 | **R**: all programs load and attach (raw_tp ×4, kprobe/kretprobe). Counts within 0.004 % and mean request latency within 0.14 % of diskstats on every controller at ≈ 400k IOPS (`docs/validation/phase-2.md`) |
| Level 1 slot redesign on el9 6.12 (in-flight array by tag, queue-keyed registration, qid from the tag set: `request_queue.tag_set`, `nvme_ctrl.admin_tagset`, `blk_mq_hw_ctx.tags`, `blk_mq_tags.nr_tags`) | **R**: loads and attaches, as root and as a dynamic user with CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN. Completions + untracked equal diskstats; 0 mismatches and 0 stale entries; reconnect reuses regions (`docs/validation/phase-3-driver.md`, `phase-5.md`). Without `tag_set`/`admin_tagset` in BTF, it falls back to the `queuedata` test (not exercised) |
| L1 + L2 submission and worker hooks on el9 6.12 (bpftrace spikes) | **R**: 183,601 commands cross-checked (counts equal to the diskstats delta, 0 cid/qid mismatches, 0 transport misclassification). See `latency-model.md` §10. |
| Queue↔socket join on el9 6.12 | **R**: all 54 queues matched sock_diag cookie and port |
| T1 `iter/tcp` queue table and T3–T7 event hooks (`tcp_sock.bpf.c`) on el9 6.12 | **R**: 54/54 queue sockets identical to Phase 0 recordings and to `ss`. Hooks fire for host TCP events and the NVMe filter rejected all 46 non-NVMe events in a test (`docs/validation/phase-3-tcp.md`). **Positive path under fault injection** (`docs/validation/fault-injection.md`):
- 1 % loss on one controller: 7,399 retransmissions, 4,948 recovery entries and 52 RTO entries, all on that controller's queues and 0 elsewhere.
- Connection abort: RST sent, `ECONNABORTED`, ESTAB→CLOSE on the aborted queue, and FIN-WAIT-1 on the 8 torn-down queues.

RST *received* has not yet fired on an NVMe socket. |
| L3 controller lifecycle (`nvme_change_ctrl_state` kprobe) on el9 6.12 | **R**: a live reset recorded live→resetting→connecting→live with ms timestamps, including 9 rejected re-entries. Same generation, epoch +1, 9/9 new queue cookies, 23–50 failovers counted (`docs/validation/fault-injection.md`) |
| Level 2 driver object (`tcp_driver.bpf.c`) on el9 6.12, kprobe and fentry flavours | **R**:
- every program loads and attaches;
- fentry preflight 1.1–1.6 ms;
- 804k sampled reads with 0 sum-check failures;
- sampled means within 0.6 % of Level 1;
- 2 ms netem delay lands in C1 (+2.00–2.13 ms), other stages < 1.2 µs;
- a duty-cycled RT hog on one queue's io_cpu raises only that queue's B and D;
- kprobes leave 0.3–0.66 % of notifications unresolved, fentry ≤ 0.0006 %.

- live R2T and in-capsule writes agree with an independent bpftrace implementation within 1.8 % per stage.

See `docs/validation/phase-3-driver.md`. |
| READ data-phase hooks (D7–D8) on el9 6.12 | **R** for single-PDU reads: 4,035,299 8 KiB READs staged, 99.94 % matched (`latency-model.md` §10.3). Multi-PDU reads still pending. |
| R2T and in-capsule WRITE staging (D1–D4, D9, P1–P3) on el9 6.12 | **R**: 242,873 complete R2T records with an exact sum check (0 failures). Inline vs R2T classification and H2C continuation vs new R2T both correct (`latency-model.md` §10.2) |
| Sequence-mapped receive notification (D10 + D7) on el9 6.12 | **R**: resolved 99.98 % of responses with 0 causality violations; the drain heuristic was shown to be unsound and rejected |
| R2T writes, inline writes on other kernels; multi-R2T | not yet: needs the loopback harness |
| Rocky 9.6/9.8 stock kernels | **B** only. Runtime validation required (VM) |
| Ubuntu 22.04 5.15 GA, 24.04 6.8, 24.04 HWE 6.17 | **B** only. Runtime validation required (VM) |
| Ubuntu 22.04 kernels older than the cid fix (F1) | S only. Text fallback correctness to be tested |
| aarch64 | Not examined |
| Missing-BTF, lockdown, permission-failure paths | Planned harness cases (implementation-plan §5) |
