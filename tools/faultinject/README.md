# Fault injection against one NVMe/TCP controller

`nvmetcp-faults.sh` impairs **one** controller's TCP connections on a live
initiator and records what nvmetea reports while it does. `analyze.py`
summarises the records. Both exist to validate nvmetea's transport evidence
(T3–T7 events, `tcp_info`, controller lifecycle, failover counters) against a
known cause. nvmetea itself stays read-only; this script is the only part that
changes anything.

**Disruptive. Only on hosts where disturbing I/O is acceptable.**

```sh
cargo build --release
sudo tools/faultinject/nvmetcp-faults.sh --yes nvme4 ./fi-out
python3 -I tools/faultinject/analyze.py ./fi-out nvme4 > fi-out/report.md
```

Phases (env overrides in the script header):

| Phase | Default | What changes |
|---|---|---|
| baseline | 15 s | redirect installed, netem pass-through |
| loss | 25 s | `netem loss 1%` on egress to the controller's target address |
| recover1 | 15 s | pass-through |
| delay | 25 s | `netem delay 2ms` on the same egress |
| recover2 | 15 s | pass-through |
| rst | 35 s | `ss -K` destroys the qid-3 connection: RST, `ECONNABORTED`, controller error recovery, reconnect after `reconnect_delay` |

**Scoping and safety.** The script refuses to run unless:
- the controller is live NVMe/TCP;
- another live path to the same subsystem exists, so multipath keeps I/O running;
- its target IPv4 address is used by no other controller.

Only packets to that address are redirected, by a clsact egress u32 filter, to
a temporary ifb device whose root qdisc is netem. The NIC's root and per-queue
qdiscs are never replaced. Phase switches use `tc qdisc change`, which is
lossless. On exit, including Ctrl-C, the script:
- removes the filter, clsact and the ifb;
- unloads the modules it loaded;
- compares the NIC's qdiscs before and after.

The first version of the script replaced the NIC's root qdisc. That dropped the
packets queued on every tx queue at each switch, which showed up as a burst of
about 100 retransmissions per controller. Re-creating the default qdiscs also
changed fq_codel's `quantum` from the boot-time 1514 to 9014, the current MTU.
The ifb design avoids both.

Outputs:
- `top.ndjson`: 1 s samples with the event log;
- `queues-<phase>.json`: one interval spanning each phase;
- `tcp-before.json` and `tcp-after.json`;
- `phases.log` and `netem.log`, which hold timestamps;
- `netem-<phase>.txt`: netem drop statistics for each phase;
- `ss-kill.txt`;
- `qdisc-before.txt` and `qdisc-after.txt`.
