#!/usr/bin/env python3
"""Summarise a nvmetcp-faults.sh run: what nvmetea reported per phase for the
impaired controller versus the untouched controllers.

Usage: python3 -I analyze.py OUTDIR CTRL
Reads only the run's own output files (nvmetea JSON, tc, ss); no kernel access.
"""
import collections
import json
import os
import re
import statistics
import sys


def load_phases(out):
    marks = {}
    with open(os.path.join(out, "phases.log")) as f:
        for line in f:
            k, t = line.split()
            marks[k] = float(t)
    phases = []
    for k, a in sorted(marks.items(), key=lambda x: x[1]):
        if not k.endswith("_start"):
            continue
        name = k[: -len("_start")]
        b = marks.get(name + "_end")
        if b:
            phases.append((name, a, b))
    return phases, marks


def phase_of(t, phases):
    for name, a, b in phases:
        if a <= t < b:
            return name
    return None


def val(o):
    return o.get("value") if isinstance(o, dict) else o


def read_ndjson(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # last line may be cut by the kill
    return rows


def wmean(pairs):
    n = sum(w for _, w in pairs)
    return sum(v * w for v, w in pairs) / n if n else None


def fmt(v, unit="", nd=1):
    if v is None:
        return "-"
    return f"{v:.{nd}f}{unit}"


def per_second_table(top, phases, ctrl):
    """Per phase x controller: write command latency (BPF), completions/s,
    TCP retransmitted segments/s and RTT median (sock_diag)."""
    acc = collections.defaultdict(lambda: collections.defaultdict(list))
    for r in top:
        ph = phase_of(r["t"] - r.get("interval_s", 1) / 2, phases)
        if not ph:
            continue
        for c in r.get("controllers", []):
            tcp = c.get("tcp", {})
            acc[(ph, c["name"])]["retr"].append(val(tcp.get("retrans_segments_per_s")))
            acc[(ph, c["name"])]["rtt"].append(val(tcp.get("rtt_median_us")))
        nv = r.get("nvme") or {}
        for c in nv.get("controllers", []):
            for o in c.get("ops", []):
                if o["op"] != "write":
                    continue
                cmd = o["command"]
                n = cmd.get("samples") or 0
                acc[(ph, c["controller"])]["mean"].append((val(cmd["mean_us"]), n))
                acc[(ph, c["controller"])]["p99"].append(val(cmd["p99_us"]))
                acc[(ph, c["controller"])]["cps"].append(val(o["completed_per_s"]))
    names = sorted({k[1] for k in acc})
    lines = ["| phase | controller | write cmd mean | p99 (median of 1 s) | completions/s | TCP retrans seg/s | RTT median |",
             "|---|---|---|---|---|---|---|"]
    for ph, _, _ in phases:
        for n in names:
            d = acc.get((ph, n))
            if not d:
                continue
            mean = wmean([(v, w) for v, w in d["mean"] if v is not None])
            p99 = [x for x in d["p99"] if x is not None]
            cps = [x for x in d["cps"] if x is not None]
            retr = [x for x in d["retr"] if x is not None]
            rtt = [x for x in d["rtt"] if x is not None]
            mark = " **(impaired)**" if n == ctrl and ph in ("loss", "delay", "rst", "cpuhog", "rthog") else ""
            lines.append(
                f"| {ph} | {n}{mark} | {fmt(mean and mean / 1e3, ' ms', 2)} | "
                f"{fmt(statistics.median(p99) / 1e3 if p99 else None, ' ms', 1)} | "
                f"{fmt(statistics.mean(cps) if cps else None, '', 0)} | "
                f"{fmt(statistics.mean(retr) if retr else None, '', 1)} | "
                f"{fmt(statistics.median(rtt) if rtt else None, ' us', 0)} |"
            )
    return "\n".join(lines)


SLOW = re.compile(r"^slow (\w+) (nvme\d+)/q(\d+) .*? request ([\d.]+)(us|ms|s) .*?\| (.*)$")
TCPEV = re.compile(r"^tcp (nvme\d+)/q(\d+): (.*)$")


def events(top, phases):
    seen = set()
    out = []
    for r in top:
        for e in r.get("events", []):
            k = (round(e["at"], 6), e["text"])
            if k in seen:
                continue
            seen.add(k)
            out.append((e["at"], e["text"]))
    out.sort()
    return out


def event_summary(evs, phases, ctrl):
    slow = collections.Counter()
    slow_ctx = collections.Counter()
    tcp = collections.Counter()
    other = []
    for t, text in evs:
        ph = phase_of(t, phases) or "-"
        m = SLOW.match(text)
        if m:
            slow[(ph, m.group(2))] += 1
            if "TCP on this queue's connection:" in m.group(6):
                slow_ctx[(ph, m.group(2))] += 1
            continue
        m = TCPEV.match(text)
        if m:
            kind = re.sub(r"\d+$", "N", m.group(3)) if m.group(3).startswith("socket error") else m.group(3)
            tcp[(ph, m.group(1), m.group(3))] += 1
            continue
        other.append((t, ph, text))
    lines = ["Slow commands reported by `top` (threshold adapts to the worst p99.9) and how many carried "
             "transport events on their own queue's connection:", "",
             "| phase | controller | slow commands | with TCP events on own connection |", "|---|---|---|---|"]
    for (ph, c), n in sorted(slow.items()):
        lines.append(f"| {ph} | {c} | {n} | {slow_ctx[(ph, c)]} |")
    lines += ["", "TCP events shown by `top` (ring-buffer events are rate-limited; exact counts are in the "
              "per-connection tables):", "", "| phase | controller | event | count |", "|---|---|---|---|"]
    for (ph, c, k), n in sorted(tcp.items()):
        lines.append(f"| {ph} | {c} | {k} | {n} |")
    lines += ["", "Lifecycle / other events:", ""]
    for t, ph, text in other:
        lines.append(f"- `{t:.3f}` [{ph}] {text}")
    return "\n".join(lines), slow, slow_ctx, tcp


CONN_FIELDS = ("retransmit_events", "loss_entries", "recovery_entries", "resets", "socket_errors", "state_changes")


def conn_table(out, phases):
    lines = ["Per-connection counters from `nvmetea queues --json` (one interval bracketing each phase), "
             "summed per controller:", "",
             "| phase | controller | conns | RETR_EV | loss entries | recovery entries | RST | sk errors | "
             "state changes | retrans seg/s (tcp_info) | RTT median | failovers/s | retries/s | requeues/s | "
             "error completions/s |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    raw = {}
    for ph, _, _ in phases:
        p = os.path.join(out, f"queues-{ph}.json")
        if not os.path.exists(p):
            continue
        try:
            d = json.load(open(p))
        except json.JSONDecodeError:
            continue
        raw[ph] = d
        agg = collections.defaultdict(lambda: collections.defaultdict(float))
        rtts = collections.defaultdict(list)
        for c in d.get("connections", []):
            a = agg[c["controller"]]
            a["conns"] += 0 if c.get("closed") else 1
            a["closed"] += 1 if c.get("closed") else 0
            for f in CONN_FIELDS:
                v = val(c.get(f))
                if v is not None:
                    a[f] += v
            v = val((c.get("interval") or {}).get("retrans_segments_per_s"))
            if v is not None:
                a["retr_s"] += v
            if val(c.get("rtt_us")) is not None and c["qid"] != 0 and not c.get("closed"):
                rtts[c["controller"]].append(val(c["rtt_us"]))
        for q in d.get("queues", []):
            a = agg[q["controller"]]
            for f in ("failovers_per_s", "retries_per_s", "requeues_per_s", "error_completions_per_s"):
                v = val(q.get(f))
                if v is not None:
                    a[f] += v
        for name in sorted(agg):
            a = agg[name]
            rt = statistics.median(rtts[name]) if rtts[name] else None
            lines.append(
                f"| {ph} | {name} | {int(a['conns'])}{' + %d closed' % a['closed'] if a['closed'] else ''} | " + " | ".join(str(int(a[f])) for f in CONN_FIELDS)
                + f" | {a['retr_s']:.1f} | {fmt(rt, ' us', 0)} | {a['failovers_per_s']:.2f} | "
                f"{a['retries_per_s']:.2f} | {a['requeues_per_s']:.2f} | {a['error_completions_per_s']:.2f} |"
            )
    return "\n".join(lines), raw


def stage_table(raw):
    """Write latency split per controller: CMD (dispatch -> NVMe completion: wire +
    target) vs the local stages A (block start -> dispatch) and E2 (NVMe completion
    -> block completion). Stage means are not kept, so their p50/p99 are shown as
    the median / max over the controller's queues."""
    lines = ["| phase | controller | writes | CMD mean | REQ mean | A p50 (median of queues) | A p99 (max) | "
             "E2 p50 (median of queues) | E2 p99 (max) |", "|---|---|---|---|---|---|---|---|---|"]
    for ph, d in raw.items():
        acc = collections.defaultdict(lambda: collections.defaultdict(list))
        for q in d.get("queues", []):
            for o in q["ops"]:
                if o["op"] != "write":
                    continue
                a = acc[q["controller"]]
                for m in ("command", "request"):
                    v = val(o[m]["mean_us"])
                    if v is not None:
                        a[m].append((v, o[m]["samples"]))
                for m in ("stage_a", "stage_e2"):
                    for pct in ("p50_us", "p99_us"):
                        v = val(o[m][pct])
                        if v is not None:
                            a[m + pct].append(v)
        for c in sorted(acc):
            a = acc[c]
            n = sum(w for _, w in a["command"])
            med = lambda k: statistics.median(a[k]) if a[k] else None  # noqa: E731
            mx = lambda k: max(a[k]) if a[k] else None  # noqa: E731
            cm, rm = wmean(a["command"]), wmean(a["request"])
            lines.append(
                f"| {ph} | {c} | {n} | {fmt(cm and cm / 1e3, ' ms', 2)} | {fmt(rm and rm / 1e3, ' ms', 2)} | "
                f"{fmt(med('stage_ap50_us'), ' us')} | {fmt(mx('stage_ap99_us'), ' us')} | "
                f"{fmt(med('stage_e2p50_us'), ' us')} | {fmt(mx('stage_e2p99_us'), ' us')} |"
            )
    return "\n".join(lines)


def lifecycle(top, ctrl):
    """Generation / epoch / state of CTRL per sample where anything changed, with
    failovers and in-flight commands from the BPF queue counters."""
    lines = ["| t | generation | epoch | state | completions/s | failovers/s | in flight |", "|---|---|---|---|---|---|---|"]
    prev = None
    for r in top:
        c = next((x for x in r.get("controllers", []) if x["name"] == ctrl), None)
        if not c:
            continue
        nv = r.get("nvme") or {}
        k = next((x for x in nv.get("controllers", []) if x["controller"] == ctrl), None)
        qs = [q for q in nv.get("queues", []) if q["controller"] == ctrl]
        cps = sum(val(o["completed_per_s"]) or 0 for o in k["ops"]) if k else None
        fo = sum(val(q["failovers_per_s"]) or 0 for q in qs) if qs else None
        inf = val(k["inflight"]) if k else None
        key = (c["generation"], c["epoch"], c["state"])
        if key != prev or (fo or 0) > 0:
            lines.append(f"| {r['t']:.3f} | {key[0]} | {key[1]} | {key[2]} | {fmt(cps, '', 0)} | {fmt(fo, '', 1)} | "
                         f"{inf if inf is not None else '-'} | ({r.get('interval_s', 0):.3f} s interval)")
        prev = key
    return "\n".join(lines)


def closed_connections(raw):
    lines = []
    for ph, d in raw.items():
        for c in d.get("connections", []):
            if c.get("closed"):
                ev = ", ".join(f"{f}={val(c.get(f))}" for f in CONN_FIELDS)
                lines.append(f"- [{ph}] {c['controller']} qid {c['qid']} cookie {c['cookie']} last state "
                             f"{c['state']}: {ev}")
    return "\n".join(lines) or "- none"


FAM = ("A", "B", "C", "D", "E")


def profile_tables(out, phases, ctrl, hog):
    """Stage breakdown per phase from `nvmetea profile --json` (Level 2)."""
    lines = []
    rows = []
    for ph, _, _ in phases:
        p = os.path.join(out, f"profile-{ph}.json")
        if not os.path.exists(p):
            continue
        try:
            d = json.load(open(p))
        except json.JSONDecodeError:
            continue
        # per controller: the largest complete group
        best = {}
        for g in d.get("groups", []):
            if g["controller"] == "all" or not g["complete"]:
                continue
            if g["complete"] > best.get(g["controller"], {}).get("complete", 0):
                best[g["controller"]] = g
        for c, g in sorted(best.items()):
            rows.append((ph, c, g, d))
    if not rows:
        return "no profile records"
    lines += ["Stage-family means per controller (largest variant group; complete records; `nvmetea profile`):", "",
              "| phase | controller | variant | records (partial) | request mean | A | B | C | D | E |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for ph, c, g, d in rows:
        f = g["families"]
        mark = " **(impaired)**" if c == ctrl and ph in ("loss", "delay", "cpuhog", "rthog") else ""
        lines.append(
            f"| {ph} | {c}{mark} | {g['variant']} {g['size_class']} | {g['complete']} ({g['excluded']['partial']}) | "
            f"{fmt(g['request_mean_us'] and g['request_mean_us'] / 1e3, ' ms', 3)} | "
            + " | ".join(fmt(f.get(k), " us", 1) for k in FAM) + " |"
        )
    lines += ["", f"Stages of {ctrl} per phase (mean, µs):", ""]
    stage_ids = []
    per = {}
    for ph, c, g, d in rows:
        if c != ctrl:
            continue
        per[ph] = {st["stage"]: st["mean_us"] for st in g["stages"]}
        for st in g["stages"]:
            if st["stage"] not in stage_ids:
                stage_ids.append(st["stage"])
    if per:
        lines.append("| stage | " + " | ".join(per) + " |")
        lines.append("|---|" + "---|" * len(per))
        for sid in stage_ids:
            lines.append(f"| {sid} | " + " | ".join(fmt(per[ph].get(sid), "", 1) for ph in per) + " |")
    if hog is not None:
        hph, hog = hog
        p = os.path.join(out, f"profile-{hph}.json")
        b = os.path.join(out, "profile-baseline.json")
        if os.path.exists(p):
            lines += ["", f"{hph}: queues whose io_cpu is CPU {hog} vs all other queues (complete records):", "",
                      "| phase | queues | records | request mean | B | C | D |", "|---|---|---|---|---|---|---|"]
            for ph, path in (("baseline", b), (hph, p)):
                if not os.path.exists(path):
                    continue
                qs = json.load(open(path)).get("queues", [])
                for label, sel in ((f"io_cpu {hog}", [q for q in qs if q.get("io_cpu") == hog]),
                                   ("other queues", [q for q in qs if q.get("io_cpu") != hog])):
                    n = sum(q["complete"] for q in sel)
                    if not n:
                        continue
                    w = lambda k: sum(q["families"].get(k, 0) * q["complete"] for q in sel) / n  # noqa: E731
                    rq = sum((q["request_mean_us"] or 0) * q["complete"] for q in sel) / n
                    names = ", ".join(f"{q['controller']}/q{q['qid']}" for q in sel) if len(sel) <= 3 else f"{len(sel)} queues"
                    lines.append(f"| {ph} | {label}: {names} | {n} | {rq / 1e3:.3f} ms | {w('B'):.1f} us | "
                                 f"{w('C') / 1e3:.3f} ms | {w('D'):.1f} us |")
    return "\n".join(lines)


def cookies(path, ctrl_filter=None):
    d = json.load(open(path))
    m = {}
    for s in d["sockets"]:
        if s.get("controller") is None:
            continue
        m[(s["controller"], val(s["qid"]))] = (s.get("cookie"), s["local"])
    return m


def main():
    out, ctrl = sys.argv[1], sys.argv[2]
    phases, marks = load_phases(out)
    top = read_ndjson(os.path.join(out, "top.ndjson"))
    print(f"# Fault-injection run {os.path.basename(os.path.abspath(out))}\n")
    print(open(os.path.join(out, "setup.txt")).read().strip(), "\n")
    print("Phases (s from baseline start):", ", ".join(
        f"{n} {a - phases[0][1]:.0f}-{b - phases[0][1]:.0f}" for n, a, b in phases), "\n")
    print(f"`top` samples: {len(top)}\n")
    print(per_second_table(top, phases, ctrl), "\n")
    text, *_ = event_summary(events(top, phases), phases, ctrl)
    print(text, "\n")
    ct, raw = conn_table(out, phases)
    print(ct, "\n")
    print("Write latency by stage (`queues --json`):\n")
    print(stage_table(raw), "\n")
    print("Connections that closed during an interval (`closed: true`):\n")
    print(closed_connections(raw), "\n")
    hog = None
    for line in open(os.path.join(out, "setup.txt")):
        m = re.match(r"(cpuhog|rthog): \S+ qid \d+ io_cpu (\d+)", line)
        if m:
            hog = (m.group(1), int(m.group(2)))
    print(profile_tables(out, phases, ctrl, hog), "\n")
    print(f"{ctrl} lifecycle per `top` sample:\n")
    print(lifecycle(top, ctrl), "\n")
    b, a = os.path.join(out, "tcp-before.json"), os.path.join(out, "tcp-after.json")
    if os.path.exists(b) and os.path.exists(a):
        cb, ca = cookies(b), cookies(a)
        changed = collections.Counter()
        same = collections.Counter()
        for k, v in cb.items():
            (changed if ca.get(k) != v else same)[k[0]] += 1
        print("Queue connections before vs after the RST phase (cookie, local endpoint) per controller:\n")
        for c in sorted(set(k[0] for k in cb) | set(k[0] for k in ca)):
            print(f"- {c}: {same[c]} unchanged, {changed[c]} replaced, "
                  f"{sum(1 for k in ca if k[0] == c)} queues after")
        print()
    for f in ("ss-kill.txt", "netem-baseline.txt", "netem-loss.txt", "netem-delay.txt", "netem.log"):
        p = os.path.join(out, f)
        if os.path.exists(p):
            print(f"`{f}`:\n```\n{open(p).read().strip()}\n```\n")
    qb, qa = (open(os.path.join(out, f)).read() for f in ("qdisc-before.txt", "qdisc-after.txt"))
    print("Root qdisc restored:", "yes" if qb == qa else "NO — differs:\n" + qa)


if __name__ == "__main__":
    main()
