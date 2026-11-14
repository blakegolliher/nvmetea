# Prometheus metrics reference

`nvmetea serve --listen ADDR:PORT` serves these families on `/metrics` in the
Prometheus text format 0.0.4. `/healthz` returns 200 while the snapshot is
fresh, and 503 once it is older than 3 × `--interval`.

The list was taken from a live scrape on the development host (6 NVMe/TCP
controllers × 8 I/O queues, `nvmetea` 0.1.0): 60 families, 4,000–5,100 series
(the count grows as more ops appear: each op adds a histogram).
`nvmetea_path_ana_state` is also defined, but it only appears where
controllers report ANA.

## Conventions

- **Absent, not zero.**
  - When a source is unavailable, its families are left out; they are not
    exported as 0.
  - `nvmetea_collector_up` and `nvmetea_capability_status` say why. For
    example, without BPF privileges every Level 1 family is absent, and
    `nvmetea_collector_up{collector="bpf_core"}` is 0.
- **Counters** are cumulative since nvmetea started, except:
  - `tcp_*_total` from `tcp_info` belong to the connection, so they reset
    when a queue reconnects;
  - BPF counters start at load.

  Use `rate()` and `increase()`; both handle resets.
- **Units** are seconds and bytes, as the metric names say.
- **Histograms.**
  - The `le` edges are the 53 internal bucket boundaries of nvmetea's
    log-linear histogram: 2^k ns and 1.5·2^k ns for k = 10…35, plus 2^36 ns,
    written in seconds.
  - Every exported bucket is an exact sum of measured buckets: no
    interpolation, no resampling.
  - `_sum` comes from exact nanosecond sums kept in BPF.
- **Cardinality.**
  - At most `--prom-max-controllers` controllers (default 64); further
    controllers are dropped.
  - At most `--prom-max-queues` queues per controller (default 128); further
    queues are aggregated into `qid="other"`.
  - `nvmetea_prom_series_dropped` counts both.
  - Labels never carry ids, pointers, command ids, cookies or port numbers,
    with one exception: `trsvcid` on `nvmetea_controller_info`, which is the
    target's service port and stable.
- **Quality.** Every value comes from a measured or derived source; nothing is
  estimated. The source column below names the collector.

Collectors (`collector` label of `nvmetea_collector_up`):

| Collector | Source | Needs |
|---|---|---|
| `topology` | sysfs `/sys/class/nvme*`, uevents | nothing |
| `diskstats` | `/proc/diskstats` | nothing |
| `sock_diag` | NETLINK_SOCK_DIAG, `tcp_info` | nothing for own-netns sockets. Kernel-owned NVMe/TCP sockets are visible to unprivileged users on the tested kernels |
| `bpf_core` | Level 1 BPF (`core.bpf.c`) | CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN (module BTF), or root |
| `bpf_tcp` | Level 3 BPF (`tcp_sock.bpf.c`) | as above |

Capabilities (`capability` label of `nvmetea_capability_status`):

| Capability | Families |
|---|---|
| `nvme_latency` | `nvmetea_nvme_*`, `nvmetea_request_latency_seconds`, `nvmetea_queue_*` (except `queue_io_cpu`), `nvmetea_bpf_*`, `nvmetea_records_total` |
| `tcp_info` | `nvmetea_tcp_*` from `tcp_info` and sock_diag |
| `transport_events` | `nvmetea_tcp_retransmit_events_total`, `_congestion_events_total`, `_resets_total`, `_socket_errors_total` |
| `queue_sockets` | the mapping from a queue to its socket. Without it, `nvmetea_tcp_*` and `nvmetea_queue_io_cpu` are absent |

`status` is `active`, `degraded` or `unavailable`. `reason` is one of the
reason codes in [troubleshooting.md](troubleshooting.md#reason-codes).

## Exporter

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `nvmetea_build_info` | gauge | `version` | always 1 |
| `nvmetea_collector_up` | gauge | `collector` | 1 when the collector produced data in the last snapshot |
| `nvmetea_capability_status` | gauge | `capability`, `status`, `reason` | 1 for the current status of each capability |
| `nvmetea_process_cpu_seconds_total` | counter | — | CPU time of the nvmetea process (user + system) |
| `nvmetea_process_resident_memory_bytes` | gauge | — | resident memory of nvmetea |
| `nvmetea_prom_series_dropped` | gauge | — | series dropped or aggregated by the cardinality limits in this exposition |
| `nvmetea_snapshot_age_seconds` | gauge | — | age of the snapshot the scrape was rendered from. A scrape never triggers collection |

## Topology and state (sysfs)

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `nvmetea_subsystem_info` | gauge | `subsystem`, `subsystem_nqn`, `iopolicy` | one per NVMe subsystem |
| `nvmetea_controller_info` | gauge | `controller`, `subsystem_nqn`, `transport`, `traddr`, `trsvcid`, `host_traddr` | one per controller |
| `nvmetea_controller_state` | gauge | `controller`, `state` | state set: 1 for the current state (`new`, `live`, `resetting`, `connecting`, `deleting`, `deleting (no IO)`, `dead`) |
| `nvmetea_controller_generation` | gauge | `controller` | object generation: changes when `nvmeN` is deleted and recreated |
| `nvmetea_controller_epoch` | gauge | `controller` | connection epoch: +1 every time the controller enters `live` |
| `nvmetea_controller_queues` | gauge | `controller`, `type` | queues by type (`io` only today: the queue count from sysfs, minus the admin queue) |
| `nvmetea_controller_queue_depth` | gauge | `controller` | I/O queue depth (sqsize + 1) |
| `nvmetea_controller_state_transitions_total` | counter | `controller`, `to_state` | state transitions seen since start |
| `nvmetea_namespace_info` | gauge | `namespace`, `nsid`, `subsystem_nqn`, `wwid` | multipath head or direct namespace |
| `nvmetea_path_info` | gauge | `controller`, `namespace`, `path` | a namespace's path through a controller |
| `nvmetea_path_usable` | gauge | `path` | 1 when the path's controller is live and ANA, if reported, allows I/O |
| `nvmetea_path_ana_state` | gauge | `path`, `state` | ANA state set, only when the controller reports ANA |

Every series of `nvmetea_controller_state` for a controller is present, with
1 on the current state, so `nvmetea_controller_state{state="live"} == 0` is a
valid alert.

## Block layer (`/proc/diskstats`)

`device` is the block device: the multipath head (`nvme2n1`) or a path
(`nvme2c2n1`). Heads count requests once. Paths count what was sent through
each controller.

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `nvmetea_block_ios_total` | counter | `device`, `op` | completed I/Os (`read`, `write`) |
| `nvmetea_block_bytes_total` | counter | `device`, `op` | bytes of completed I/O |
| `nvmetea_block_time_seconds_total` | counter | `device`, `op` | time spent on I/O (diskstats milliseconds) |
| `nvmetea_block_inflight` | gauge | `device` | I/Os in flight |

## NVMe commands (Level 1 BPF)

These families count NVMe/TCP commands at the driver: `nvme_setup_cmd` for
dispatch, `nvme_complete_rq` and `block_rq_complete` for completion. Only
commands of NVMe/TCP controllers are seen. `op` is one of:
- `read`, `write`, `flush`;
- `other`: every other I/O-queue opcode, including Dataset Management
  (discard) and fabrics Connect;
- `admin`: admin-queue commands. AERs are counted but never timed, because
  they stay outstanding by design.

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `nvmetea_nvme_commands_total` | counter | `controller`, `op` | commands dispatched, including retries |
| `nvmetea_nvme_bytes_total` | counter | `controller`, `op` | bytes of first dispatches |
| `nvmetea_nvme_errors_total` | counter | `controller`, `op` | completions with a non-zero NVMe status |
| `nvmetea_nvme_error_status_total` | counter | `controller`, `status_type` | error completions by status code type: 0 generic, 1 command specific, 2 media, 3 path, 7 vendor |
| `nvmetea_nvme_retries_total` | counter | `controller` | commands dispatched again after a retryable status |
| `nvmetea_nvme_failovers_total` | counter | `controller` | requests failed over to another path |
| `nvmetea_nvme_requeues_total` | counter | `controller` | requests requeued by blk-mq |
| `nvmetea_nvme_command_latency_seconds` | histogram | `controller`, `op` | `nvme_setup_cmd` → `nvme_complete_rq`, per dispatch |
| `nvmetea_request_latency_seconds` | histogram | `controller`, `op` | block request start (`start_time_ns`) → `block_rq_complete` on the path device |

**Retried and failed-over commands** are excluded from both latency
histograms; they are counted in `retries` and `failovers`. A retry's
first-dispatch time is kept internally, so a later release can add a
retry-inclusive histogram without changing these.

**Command latency vs request latency.** Request latency starts in the block
layer, before the driver is involved. It includes block submission (stage A)
and the completion handoff (E). Command latency starts at the driver's command
setup. `nvmetea profile` splits both into stages; see `latency-model.md`.

## Queues (Level 1 BPF; `queue_io_cpu` from sysfs and sock_diag)

`qid` is the NVMe queue id: 0 is the admin queue, and 1…N are I/O queues
(hardware queue k is NVMe queue k + 1).

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `nvmetea_queue_commands_total` | counter | `controller`, `qid`, `op` | commands dispatched |
| `nvmetea_queue_bytes_total` | counter | `controller`, `qid`, `op` | bytes dispatched |
| `nvmetea_queue_inflight` | gauge | `controller`, `qid` | commands in flight at the snapshot |
| `nvmetea_queue_inflight_max` | gauge | `controller`, `qid` | largest in-flight count between the last two snapshots (exact: BPF keeps the high watermark) |
| `nvmetea_queue_latency_seconds` | summary (`_sum`, `_count`; no quantiles) | `controller`, `qid`, `op` | request latency per I/O queue: sum and count |
| `nvmetea_queue_io_cpu` | gauge | `controller`, `qid` | CPU of the queue's I/O worker (−1 = unbound) |

Per-queue histograms are collected in BPF but not exported. With 48 queues ×
5 ops × 54 buckets, they would dominate the exposition. Mean per-queue latency
is `rate(_sum) / rate(_count)`. `nvmetea queues` shows per-queue percentiles.

## BPF data quality

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `nvmetea_records_total` | counter | `outcome` | command records by outcome (see below) |
| `nvmetea_bpf_map_full_total` | counter | `map` | insertions that failed for lack of space: `inflight` (no slot region left for a new queue), `qstats` (no queue index left), `hist` (path histogram map full, or a queue beyond the per-queue histogram budget of 903 queues) |
| `nvmetea_bpf_events_lost_total` | counter | `kind` | `ringbuf`: ring buffer full; `slow_suppressed`: slow-command records over the rate limit |

`outcome` values:

| Outcome | Meaning | Expected |
|---|---|---|
| `dispatched` | commands seen at dispatch | — |
| `untracked` | completed, but the dispatch was not seen | right after start: commands already in flight when nvmetea loaded. A steady increase means dispatches are missed |
| `mismatch` | the in-flight entry's command id differs from the completion's | 0 |
| `stale_replaced` | a dispatch found an unfinished entry on its tag (a completion was missed) | 0, apart from controller teardown with commands in flight |
| `start_missing` | the block request had no start time | 0 for file-system and fio I/O. Passthrough commands (Connect, admin) have none |
| `order_violation` | completion timestamps out of order | 0 |

## TCP (sock_diag and `tcp_info`; events from Level 3 BPF)

One series per I/O queue connection. The admin queue's connection is not
exported per queue.

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `nvmetea_tcp_rtt_seconds` | gauge | `controller`, `qid` | smoothed RTT |
| `nvmetea_tcp_rtt_variance_seconds` | gauge | `controller`, `qid` | RTT variance |
| `nvmetea_tcp_min_rtt_seconds` | gauge | `controller`, `qid` | minimum RTT |
| `nvmetea_tcp_rto_seconds` | gauge | `controller`, `qid` | retransmission timeout |
| `nvmetea_tcp_retransmitted_segments_total` | counter | `controller`, `qid` | retransmitted segments (resets on reconnect) |
| `nvmetea_tcp_retransmitted_bytes_total` | counter | `controller`, `qid` | retransmitted bytes |
| `nvmetea_tcp_bytes_sent_total` | counter | `controller`, `qid` | bytes sent |
| `nvmetea_tcp_bytes_received_total` | counter | `controller`, `qid` | bytes received |
| `nvmetea_tcp_unacked_segments` | gauge | `controller`, `qid` | unacknowledged segments |
| `nvmetea_tcp_lost_segments` | gauge | `controller`, `qid` | segments considered lost |
| `nvmetea_tcp_cwnd_segments` | gauge | `controller`, `qid` | congestion window |
| `nvmetea_tcp_ssthresh_segments` | gauge | `controller`, `qid` | slow-start threshold |
| `nvmetea_tcp_send_queue_bytes` | gauge | `controller`, `qid` | send queue |
| `nvmetea_tcp_receive_queue_bytes` | gauge | `controller`, `qid` | receive queue |
| `nvmetea_tcp_notsent_bytes` | gauge | `controller`, `qid` | bytes queued but not yet sent |
| `nvmetea_tcp_limited_seconds_total` | counter | `controller`, `qid`, `reason` | time busy (`busy`), limited by the receive window (`rwnd`) or by the send buffer (`sndbuf`) |
| `nvmetea_tcp_retransmit_events_total` | counter | `controller`, `qid` | retransmitted skbs (`tcp_retransmit_skb`) |
| `nvmetea_tcp_congestion_events_total` | counter | `controller`, `qid`, `state` | entries into `cwr`, `recovery` or `loss` |
| `nvmetea_tcp_resets_total` | counter | `controller`, `qid` | RSTs sent or received |
| `nvmetea_tcp_socket_errors_total` | counter | `controller`, `qid` | socket errors (`inet_sk_error_report`) |

`busy` time grows on every active connection. That is normal: it is
`tcpi_busy_time`. `rwnd` and `sndbuf` are the ones that point at a limit.

## Example queries

```promql
# Request latency p99 per controller and op (5 m window)
histogram_quantile(0.99, sum by (controller, op, le) (rate(nvmetea_request_latency_seconds_bucket[5m])))

# Mean latency per queue: finds a slow queue or a hot CPU
rate(nvmetea_queue_latency_seconds_sum[1m]) / rate(nvmetea_queue_latency_seconds_count[1m])

# Error and path-error rate
sum by (controller) (rate(nvmetea_nvme_errors_total[5m]))
rate(nvmetea_nvme_error_status_total{status_type="3"}[5m])

# Controllers not live
nvmetea_controller_state{state="live"} == 0

# Retransmissions per queue connection
rate(nvmetea_tcp_retransmitted_segments_total[5m]) > 0

# BPF data you cannot trust right now
increase(nvmetea_bpf_map_full_total[10m]) > 0 or increase(nvmetea_bpf_events_lost_total{kind="ringbuf"}[10m]) > 0

# The exporter itself
nvmetea_snapshot_age_seconds > 3 * 5
rate(nvmetea_process_cpu_seconds_total[5m])
```

## Not exported yet

These are measured but not exported:
- keep-alive latency;
- cancellation and timeout counters;
- per-queue histograms;
- driver stage histograms (Level 2 runs on demand, in `profile` and `record`);
- send-context and worker counters;
- BPF map usage and program run time.

`--prom-path-latency` and `--prom-queue-histograms` (opt-in extras in the
architecture) are not built.
