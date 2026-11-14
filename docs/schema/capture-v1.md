# `nvmetea.capture/1`

The capture file is written by `nvmetea record` and read by `nvmetea compare`. The
machine-checkable form is [`capture-v1.schema.json`](capture-v1.schema.json)
(JSON Schema 2020-12). A test validates `record`'s output against it
(`crates/nvmetea-export/tests/schema.rs`). Set `NVMETEA_CAPTURE=<file>` to also
validate a real capture.

## Versioning

- `schema` is `nvmetea.capture/<major>[.<minor>]`.
- **Readers refuse an unknown major version.** A newer minor version only adds
  fields, and readers **ignore unknown fields**.
- The capture has its own types (`crates/nvmetea-export/src/capture.rs`). It is
  not a dump of internal structures, so the file format does not change when the
  model does.

## Conventions

- Times: `*_unix_s` are wall-clock seconds; `t_s` are seconds since the capture
  start.
- Latency sums are integer nanoseconds (`sum_ns`); means and percentiles are
  derived from them.
- **Unavailable is `null` or absent, never 0.** For example, `read_mean_us` is
  `null` without Level 1, and `stages` is absent without `--sample`.
- **Controllers** are identified across captures by `key`: subsystem NQN,
  transport, `traddr`, `trsvcid`, `host_traddr`. `nvmeN` (`controller`/`name`) is
  informational: it changes across reboots and reconnects.
- **Histograms** (`dist.hist`) are sparse `[bucket index, count]` pairs of the
  log-linear histogram (`docs/architecture.md` §4.4). Bucket 0 is < 256 ns. Buckets
  1–224 split each octave 2^8…2^36 ns into 8 linear sub-buckets. Bucket 225 is
  ≥ 2^36 ns. Percentiles are bucket upper edges (≤ 12.5 % high).
- **Window data** (`latency`, `queues`, `controllers`) are differences of
  cumulative kernel counters between the first and last sample: exact, and not
  rebuilt from rates.

## Top-level fields

| Field | Content |
|---|---|
| `tool`, `host` | nvmetea version; hostname, `boot_id`, kernel release, distribution, architecture |
| `boundary_signature` | instrumentation behind each quantity: `request`, `command` (Level 1 hooks), `stages` (Level 2 flavour, active probe ids, sampling), `tcp` (sock_diag or procnet). **Stage LAD is computed only when `stages` agrees** |
| `capabilities` | `nvme_latency`, `transport_events`, `stage_profile` with status and reason |
| `filters` | `--controller` / `--subsystem` / `--namespace` in effect |
| `start_unix_s`, `end_unix_s`, `duration_s`, `interval_s` | window and per-interval summary period |
| `topology_start`, `topology_end` | controllers (name, key, state, generation, epoch, queues, depth) and namespaces with paths and ANA state |
| `transitions` | controller transitions during the capture (time, controller, change, source: poll, uevent, bpf) |
| `intervals` | per interval and controller: IOPS and bytes/s (diskstats), Level 1 request means, in-flight, TCP RTT median, retransmitted segments/s |
| `latency` | per controller × op × metric (`command`, `request`, `stage_a`, `stage_e2`): count, exact sum (command and request), window histogram |
| `queues` | per controller × qid × op: dispatched, bytes, completed, NVMe errors over the window |
| `controllers` | per controller: retries, failovers, requeues, NVMe errors, TCP retransmitted segments (connections present at both ends of the window) |
| `stages` | optional Level 2 aggregates (below) |
| `events` | slow commands with transport context, controller state changes, TCP events, timeouts. At most 20,000; `quality.events_dropped` counts the rest |
| `quality` | Level 1 and Level 2 collector counters over the window: lost events, untracked completions, cid mismatches, map pressure, unresolved notifications, … |
| `self_overhead` | CPU seconds and peak RSS of the recording process |

### `stages`

`sample_every`, `flavour` (`fentry`/`kprobe`), `records`, `sum_check_failures`,
and `groups`. Each group has:
- **Identity:** `controller` and `key` (both `null` = all controllers), `op`,
  `variant` (`read`, `write R2T`, `write in-capsule`, …), and `size_class`
  (floor(log2(bytes))).
- **Counts:** `complete`, `partial` (a boundary was missing; not in the
  distributions), and `excluded` (retried, timed out, failed).
- **Distributions:** `request` (E_START → E_BLK_DONE over the complete records)
  and `stages`. Each stage has an `id` (A, B1, … E2, latency model §5), `family`,
  `label`, `bound` (upper/lower bound for the notification-delimited stages), and
  `dist`.

Stage distributions cover complete records only, so each group's stage means add
up to its request mean.

## Compare

`nvmetea compare BASELINE CURRENT [--min-samples N] [--json]` matches controllers
by `key`. It reports:
- **Throughput:** IOPS and MiB/s per controller × op.
- **Level 1 latency:** mean and p99 deltas.
- **Stages, LAD = mean_current / mean_baseline** (latency model §12), per stage
  group. Stages are compared only with equal `boundary_signature.stages` and at
  least N complete records (default 100) in both captures; otherwise the output
  says `not comparable: <reason>`. The largest LAD among stages carrying ≥ 1 % of
  the request latency is highlighted.
- **Errors and retransmissions:** window totals.
- **States:** state differences and transition counts.

The output schema is `nvmetea.compare/1`.
