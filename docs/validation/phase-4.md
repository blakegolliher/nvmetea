# Phase 4 — TUI, capture, compare, Prometheus: validation record

Date: 2026-11-13. Host: the development initiator (Rocky Linux 9.6 userspace,
kernel 6.12.117-1.el9, 6 NVMe/TCP controllers × 8 I/O queues). Workload: the
operator's `elbencho` 8 KiB random writes, about 64k writes/s.

## What was built

| Piece | Where | Summary |
|---|---|---|
| Prometheus exposition | `crates/nvmetea-export/src/prom.rs`, `nvmetea serve --listen ADDR:PORT` | text format 0.0.4 rendered from the published snapshot; a scrape never collects |
| Capture | `crates/nvmetea-export/src/capture.rs`, `nvmetea record`, `docs/schema/capture-v1.{md,schema.json}` | own serde types; refuses an unknown major version, ignores unknown fields |
| Compare | `crates/nvmetea-export/src/compare.rs`, `nvmetea compare` | throughput, latency, stage LAD, errors and retransmissions, state differences |
| TUI | `crates/nvmetea-tui`, `crates/nvmetea-cli/src/cmd/tui.rs`, `nvmetea` | 9 tabs, sampler thread, 80 ms input polling, terminal-restoring panic hook |

**Prometheus exposition.**
- `/metrics` and `/healthz` (503 when the snapshot is older than 3 × the interval).
- `--listen` is required. A non-loopback address prints a warning, and a bind
  failure is an error.
- Unavailable sources are **absent**, explained by `nvmetea_capability_status`
  and `nvmetea_collector_up`.
- Cardinality: at most 64 controllers; at most 128 queues per controller, the
  rest aggregated into `qid="other"`; no ids, pointers, cookies or ports as
  labels.
- Histogram `le` edges are 53 internal bucket boundaries (2^k and 1.5·2^k ns,
  k = 10…35, and 2^36 ns), so every bucket is an exact sum of measured buckets.
  `_sum` comes from exact ns sums.

**Capture.** Holds:
- topology at start and end, and transitions;
- per-interval rates;
- Level 1 window histograms and queue/controller counters (end − start of the
  kernel's cumulative values);
- optional Level 2 stage aggregates;
- events (≤ 20,000), quality counters, self overhead;
- the boundary signature per quantity.

**Compare.**
- Controllers are matched by key (subsystem NQN + address), not `nvmeN`.
- LAD = current mean / baseline mean. It is computed only with an equal stage
  boundary signature and ≥ 100 complete records in both captures; otherwise the
  output says `not comparable: <reason>`.
- The largest LAD among stages carrying ≥ 1 % of the request latency is
  highlighted.

**TUI.**
- Tabs: Overview, Subsystems, Controllers, Queues, Latency, Breakdown (stage
  profiling on demand with `p`), TCP, Events, Help.
- Unavailable values render as `-`, and Enter shows the reason; dim marks low
  sample counts; collector warnings stay on the status line.
- Keys: q, h/l/←/→, j/k/↑/↓, Enter/Esc, Space, s, f, +/-, p, r, ?.

## Automated tests

`cargo test --workspace`: **115 passed, 0 failed**. `clippy -D warnings` and
`fmt --check` are clean. New in this phase:

**Exposition:**
- well-formedness: every sample after its `TYPE`, values parse;
- the `qid="other"` aggregation and the dropped-series count;
- histograms cumulative, with `+Inf` = `_count` and an exact `_sum`;
- absent-not-zero;
- label escaping;
- every exported edge is an internal bucket boundary.

**Capture:**
- sparse histogram round trip;
- version policy: refuse major 2, reject a non-capture and invalid JSON;
- unknown fields ignored.

**Schema** (`crates/nvmetea-export/tests/schema.rs`):
- a generated capture validates against `capture-v1.schema.json`. The validator
  covers type, required, properties, items, prefixItems, min/maxItems, enum,
  oneOf, additionalProperties and `$ref`;
- deliberate violations are caught;
- `NVMETEA_CAPTURE=<file>` validates a real capture. The capture recorded during
  the delay test below passed.

**Compare:**
- LAD with matching by controller key across different `nvmeN` names;
- the largest-LAD highlight;
- not-comparable reasons: too few records, different instrumentation.

**TUI:**
- rendering through ratatui's TestBackend: Overview (`-` for unavailable values,
  the reason in the detail panel, the persistent warning), Breakdown (stage
  table, slow-command timeline), Help;
- keymap and controls;
- unit-aware sort keys.

**CLI:**
- `serve` requires `--listen` and reports bad addresses;
- `serve` without BPF serves `/metrics`, where BPF families are absent and
  `collector_up{bpf_core} 0` appears with reason `disabled_by_user`;
- plain `nvmetea` (no subcommand) falls back to `status` when stdout is not a
  terminal.

## Live results

| Check | Result |
|---|---|
| `serve` scrape | 59 families, 3,282 series, `/healthz` 200 |
| Exposition validator: TYPE before samples, duplicates, histogram monotonicity and `+Inf` = `_count`, counters non-decreasing across two scrapes | 0 errors over 18 histogram series. `promtool` is not installed on this host |
| `record`: 8 s and 10–15 s captures with stage profiling at 1 in 20/50 | about 100–130 KiB each. Level 1 quality counters 0; Level 2 47,846 records, 0 lost, 0 unresolved |
| `compare`: two captures of the same workload | stage LAD 0.89–1.05 (within the target's own drift) |
| **`compare`, baseline vs a 2 ms netem delay on nvme4** (`tools/faultinject`, captures inside each phase) | **nvme4 R2T writes: C1 command → R2T 217 µs → 2.23 ms, LAD 10.28, highlighted as the largest.** C3 5.29 → 8.27 ms (the second delayed crossing plus target drift; nvme2's C3 rose 0.5 ms in the same window). nvme4 request LAD 1.90. Other controllers' request LAD 0.88–1.08 |
| TUI on the live host (`__tui-snapshot --profile`, every tab rendered as text) | all tabs filled with live data: 6 controllers and 10 namespaces (6/6 paths); 54 queues with `io_cpu` and RTT; Level 1 percentiles; Breakdown with 2,437 records and 0 sum-check failures; 54 queue connections |

## Not yet built

- **TUI:**
  - rolling trends;
  - TCP symptoms next to the slow-command timeline (`top` shows them);
  - scrolling within the Overview tables.
- **Exposition:**
  - keep-alive latency histogram; cancellation and timeout counters;
  - stage histograms (continuous Level 2 is not built), send-context and worker
    counters;
  - map entry/capacity gauges and program run time;
  - `--prom-path-latency` and `--prom-queue-histograms`;
  - `promtool check metrics` in CI.
- **Capture:**
  - BPF object hashes;
  - `--rx-timestamps` (not built in Level 2 either);
  - histograms are stored as window differences rather than as start and end
    cumulative histograms. The information is the same for compare; it is not
    the architecture's wording.
- **Compare:** queue-imbalance changes.
