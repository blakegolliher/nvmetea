# Troubleshooting

Start with `nvmetea probe`. It needs no privileges and prints what this kernel
and these privileges allow:
- the host;
- privilege: effective capabilities, `unprivileged_bpf_disabled`,
  `kptr_restrict`, lockdown;
- BTF state of vmlinux and the NVMe modules, and kernel config;
- every attach point with its fallback;
- the plan: which collector serves each metric family, and why not when it
  cannot.

`sudo nvmetea probe --load` also loads and attaches Levels 1 and 3 for a short
sample. It reports the verifier log when a program is rejected.

nvmetea never fabricates a value. An unavailable metric shows as `-` in the
TUI, `null` with a `reason` in JSON, and is absent in Prometheus. The reason is
always one of the codes below.

## Reason codes

| Code | Meaning | What to do |
|---|---|---|
| `permission_denied` | not enough privilege for BPF, `/proc/kallsyms` or tracefs | run as root, or grant CAP_BPF, CAP_PERFMON **and CAP_SYS_ADMIN**. CAP_SYSLOG is needed for symbol checks in `probe` only. See [Privileges](#privileges) |
| `kernel_lockdown` | lockdown in confidentiality mode blocks BPF tracing | passive monitoring only (topology, diskstats, sock_diag) |
| `btf_vmlinux_missing` | kernel built without `CONFIG_DEBUG_INFO_BTF` | passive monitoring only |
| `btf_module_missing` | `nvme_core` or `nvme_tcp` carries no BTF, often an out-of-tree or DKMS build | Level 1 needs `nvme_core` BTF; driver stages need `nvme_tcp` BTF. `--btf-dir` is not built yet |
| `btf_mismatch` | a type or field nvmetea needs is missing from this kernel's BTF | report the kernel build (`probe --json`) |
| `verifier_rejected` | the verifier refused a program on this kernel | `probe --load` prints the log. Optional Level 2 programs are dropped one by one, and only their stages become unavailable |
| `attach_failed` | a program loaded but could not attach | see [Driver stages](#driver-stages-profile) for fentry |
| `module_not_loaded` | `nvme_tcp` not loaded | it loads with the first NVMe/TCP controller |
| `inlined` | the function was inlined in this build; a fallback is used | none; `probe` names the fallback |
| `unsafe_clone` | only a `.constprop`/`.isra` clone exists | never probed by argument; the fallback is used |
| `dependency_unavailable` | a prerequisite collector is unavailable | look at the prerequisite's reason |
| `disabled_by_user` | turned off by an option (`--no-bpf`) | — |
| `not_implemented` | not built in this release | — |
| `first_interval` | a rate needs two samples | it appears at the next interval |
| `counter_reset` | counter reset or identity change in this interval (reconnect, controller recreated) | the next interval is valid |
| `no_samples` | nothing happened in this interval | — |
| `ambiguous` | several candidates match, so attribution would be a guess | e.g. two controllers sharing one TCP endpoint; with BPF, Level 3 maps sockets to queues exactly |
| `inet_diag_unavailable` | sock_diag for TCP is unavailable | `modprobe tcp_diag` (or `inet_diag`) |
| `missing_interface` | the kernel or target does not expose this | — |
| `not_supported_by_controller` | the controller does not report it (e.g. ANA) | — |
| `not_applicable` | not applicable to this entity | — |
| `connection_closed` | the connection closed during the interval | see the controller's events |
| `parse_error` | unexpected kernel data | report it with `probe --json` |

## Privileges

| Need | Why |
|---|---|
| CAP_BPF | load programs and create maps |
| CAP_PERFMON | tracing programs, `bpf_probe_read_kernel` |
| **CAP_SYS_ADMIN** | libbpf reads **module** BTF (`nvme_core`, `nvme_tcp`) through BTF object ids for CO-RE relocation. Without it, the load fails and nvmetea reports `permission_denied` with this explanation |
| CAP_SYS_RESOURCE | kernels that charge BPF memory to `RLIMIT_MEMLOCK` instead of the memory cgroup |
| CAP_SYSLOG | `probe` only: read `/proc/kallsyms` addresses for symbol checks |

The packaged unit (`nvmetea-exporter.service`) limits the bounding and ambient
sets to exactly CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN and CAP_SYS_RESOURCE, and
adds `ProtectSystem=strict`, `NoNewPrivileges` and the usual sandboxing. All
collectors were verified active under it on the development host. Removing
CAP_SYS_ADMIN disables every BPF collector.

Without any of these, nvmetea still shows topology, controller state, path
state, diskstats rates and per-connection TCP diagnostics.

## Symptoms

**All latency and queue metrics are absent; `collector_up{collector="bpf_core"} 0`.**
Look at `nvmetea_capability_status{capability="nvme_latency"}` or run
`nvmetea probe`. The reason is one of `permission_denied`, `btf_*`,
`verifier_rejected` or `kernel_lockdown`.

**`records_total{outcome="untracked"}` is non-zero.**
- Right after start this is expected: those commands were already in flight
  when nvmetea armed.
- It should stop growing within a second. If it keeps growing, dispatches are
  being missed. Report the kernel build.

**`stale_replaced` grows.**
- A dispatch found an unfinished entry on its tag, which means a completion
  was missed.
- Expected only when a controller is torn down with commands in flight.
- During normal I/O it should stay 0. It stayed 0 in every validation run.

**`bpf_map_full_total` > 0.**
- In-flight slots and queue indices are sized at load from the topology
  (`probe --load --json` shows the values under `bpf_load.config`):
  - slots: the total queue depth + 25 % + 4,096. At least 8,192, at most
    512 Ki (40 MiB);
  - queue indices: the queue count + 64;
  - per-queue histograms: the first 903 queue indices (32 MiB).
- A queue keeps its region and index across resets and reconnects. A
  controller deleted and recreated under the same `nvmeN` gets them back.
- New space is used only by:
  - controllers with new instance numbers;
  - a queue whose depth changed.
- What each map name means:
  - `inflight` or `qstats`: a queue that appeared after start found no space.
    Its commands are counted but not timed (`inflight`), or not counted per
    queue (`qstats`).
  - `hist` with more than 903 queues: the histograms of queues beyond the
    budget are missing. Their counters and latency sums are still exact.
- Restart nvmetea to resize from the current topology.

**`bpf_events_lost_total{kind="ringbuf"}` > 0.**
- Slow-command and lifecycle records were dropped because the ring buffer was
  full and userspace was not reading fast enough.
- Counts and histograms are unaffected.
- `slow_suppressed` is the deliberate rate limit (4 records per CPU per
  second), not a loss.

**`/healthz` returns 503.**
- The snapshot is older than 3 × `--interval`, so the sampler is stalled or
  slower than the interval.
- `nvmetea_snapshot_age_seconds` shows by how much.
- Raise `--interval`, or look for CPU starvation of the nvmetea process.

**`qid="other"` series, `nvmetea_prom_series_dropped` > 0.**
Cardinality limits: more than `--prom-max-queues` queues per controller, or
more than `--prom-max-controllers` controllers. See
[metrics.md](metrics.md#conventions).

**TCP metrics absent, `queue_sockets` unavailable.**
- `inet_diag_unavailable`: run `modprobe tcp_diag`.
- `ambiguous`: two controllers share an endpoint and BPF is unavailable to
  tell them apart.

**`tcp_retransmitted_*` dropped to a lower value.**
These come from `tcp_info`, which belongs to the connection. A reconnect makes a
new socket. `rate()` handles it; the TUI shows `counter_reset` for that
interval.

**Commands counted under `op="other"` on I/O queues after a reconnect.**
Those are fabrics Connect commands, one per queue per reconnect. Admin-queue
commands are `op="admin"`.

**nvmetea latency differs from fio's `clat`.**
- They measure different spans:
  - request latency starts at the block layer's `start_time_ns` on the path
    device;
  - command latency starts at `nvme_setup_cmd`;
  - fio's `clat` starts at submission in userspace and ends at reaping.
- `latency-model.md` lists each boundary.
- Under multipath, the head device adds the path selection.

## Driver stages (`profile`)

- **fentry or kprobe.**
  - `--flavour auto` runs an attach preflight: a helper process attaches one
    fentry program with a 2 s deadline.
  - fentry is used only if the preflight attaches within 100 ms. Otherwise
    nvmetea uses kprobes, and the report says why.
  - On busy hosts, fentry attach can stall on `synchronize_rcu_tasks`.
- **"notification unresolved".**
  - kprobes can skip re-entrant hits, so a few receive notifications are
    lost. In validation this was 0.3–0.7 % with kprobes and about 0 with
    fentry.
  - A lost notification only lengthens C and shortens D, so the bounds stay
    valid.
  - Prefer fentry where it attaches.
- **"sum check failures".**
  - Stages are supposed to sum to the request latency. A failure means a
    boundary was out of order. It has been 0 in every validation run.
  - Report it with `--json`.
- **Cost.** Measured as BPF run time on the development host:
  - 1 in 100 (the default) adds about 0.85 µs per command;
  - `--sample 1` adds about 4 µs per command. It is diagnostic only.
- **`--bpf-stats`** turns on BPF run-time statistics host-wide for the run
  (`BPF_ENABLE_STATS`). They are released when nvmetea exits.

## Stopping nvmetea

The first SIGINT (Ctrl-C) or SIGTERM asks the long-running commands to finish:
- `record` stops early and **writes the capture** with the actual duration;
- `profile` reports what it sampled so far;
- `serve` stops after the current snapshot;
- the TUI restores the terminal. In the TUI, Ctrl-C is a key, like `q`.

Another signal more than 0.5 s later terminates immediately. Closer ones count
as the same request, because `timeout` and terminals can deliver one stop twice.
Other commands (`top`, `queues -i`, …) stop at once.

Also:
- BPF programs are attached by link file descriptors, so they detach when the
  process exits for any reason, including SIGKILL. Nothing stays attached.
- A process started in the background from a non-interactive shell (or under
  `nohup`) inherits an ignored SIGINT, and nvmetea keeps it ignored. Stop it
  with SIGTERM.
- After a SIGKILL of the TUI, run `reset`.

## Several instances

- Each nvmetea process loads its own programs. Their costs add, and their
  data is independent.
- `profile` attaches the driver object before Level 1, so its timestamps do
  not include Level 1's run time: programs on one tracepoint run in attach
  order. A second instance's Level 1 already attached earlier is included.
  Profile with one instance running.

## Reporting a problem

Include:
- `nvmetea probe --json`, and `sudo nvmetea probe --load --json`;
- `uname -r` and the distribution;
- for stage problems, `nvmetea profile --json` with `--sample 1` for 5 s.

None of these contain secrets: nvmetea never reads `dhchap_*` or TLS key
attributes. They do contain NQNs and addresses.
