# Phase 0 feasibility tools

Evidence behind `docs/kernel-compatibility.md` and `docs/latency-model.md` §10.
These are throwaway validation programs, **not** nvmetea's implementation. The
production loader is libbpf CO-RE with `raw_tp` programs (finding F14).

| File | What it validates | Needs |
|---|---|---|
| `spike3.bt` | P1/P2/P3 correlation by driver-PDU address, NVMe/TCP transport test, qid and cid/genctr semantics, stages A/B/E, direct vs deferred sends, io_work, queue↔socket cookie | root, bpftrace ≥ 0.21, module BTF |
| `spike4.bt` | READ data phase (D7/D8): first/last C2H copy, busy vs wait | as above; READ traffic |
| `write_path.bt` | WRITE staging: inline vs R2T, D1–D4/D9, exact per-record sum check, sequence-mapped `sk_data_ready` receive boundary vs the rejected drain heuristic | as above; WRITE traffic |
| `inspect_kernel.sh` | offline inspection of a distribution kernel build (vmlinux BTF, module BTF, attachable nvme_tcp functions, tracepoints, struct fields) without booting it | bpftool, readelf, an extracted `vmlinux` (`scripts/extract-vmlinux`) |

All `.bt` programs only observe. They generate no I/O, and they exit by themselves
(10–15 s). They attach fentry/fexit programs, so on a CPU-saturated host the attach
itself can take a long time (finding F15). Run them with `sudo bpftrace <file>`.

Note that `+=` on a bpftrace scalar map is not atomic across CPUs. Aggregates in
these scripts use `count()`/`sum()`/`hist()`, which are per-CPU.
