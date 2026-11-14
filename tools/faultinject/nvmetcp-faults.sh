#!/bin/bash
# nvmetea fault-injection validation against ONE NVMe/TCP controller.
#
# DISRUPTIVE. Run only on a host where disturbing I/O is acceptable:
#   phase loss   netem packet loss on egress to the controller's target address
#   phase delay  netem delay on egress to the controller's target address
#   phase cpuhog a busy loop at nice -20 pinned to the io_cpu of one of the
#                controller's queues (competes with that queue's io_work)
#   phase rthog  a SCHED_FIFO busy loop with a duty cycle (RTBUSY_MS out of every
#                RTPERIOD_MS) on that io_cpu: delays the queue's io_work by up to
#                RTBUSY_MS when it wakes inside a busy window
#   phase rst    destroys one I/O-queue TCP connection (ss -K) -> RST, socket
#                error, controller error recovery and reconnect
# Impairments are confined to the controller's target IP: a clsact egress u32
# filter redirects only packets to that address through a temporary ifb device
# whose root qdisc is netem. The NIC's own qdiscs are never replaced (replacing
# a root qdisc drops whatever is queued on every tx queue, and re-created
# default children take the current MTU's quantum, not the boot-time one).
# Phases change netem in place (`tc qdisc change`), so switching is lossless.
# Everything is removed on exit (including Ctrl-C); modules the script loaded
# are unloaded. nvmetea observes throughout.
#
# Usage: sudo tools/faultinject/nvmetcp-faults.sh --yes [CTRL] [OUTDIR]
# Env:   PHASES="loss delay rst" (any of loss delay cpuhog rthog rst, in order)
#        RTBUSY_MS=2 RTPERIOD_MS=10
#        LOSS=1% DELAY=2ms BASE=15 PH=25 REC=15 RSTWAIT=35 RSTQID=3 HOGQID=1
#        PROFILE=N  also run `nvmetea profile --sample N` per phase (0 = off)
#        NVMETEA=path
set -u

if [ "${1:-}" != "--yes" ]; then
    echo "refusing: pass --yes (this disrupts I/O on one NVMe/TCP controller)" >&2
    exit 2
fi
CTRL=${2:-nvme4}
OUT=${3:-./faultinject-$(date +%Y%m%d-%H%M%S)}
HERE=$(cd "$(dirname "$0")" && pwd)
NVMETEA=${NVMETEA:-$HERE/../../target/release/nvmetea}
LOSS=${LOSS:-1%}
DELAY=${DELAY:-2ms}
BASE=${BASE:-15}
PH=${PH:-25}
REC=${REC:-15}
RSTWAIT=${RSTWAIT:-35}
RSTQID=${RSTQID:-3}
HOGQID=${HOGQID:-1}
RTBUSY_MS=${RTBUSY_MS:-2}
RTPERIOD_MS=${RTPERIOD_MS:-10}
PHASES=${PHASES:-"loss delay rst"}
PROFILE=${PROFILE:-0}

die() { echo "error: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "run as root"
[ -x "$NVMETEA" ] || die "nvmetea binary not found at $NVMETEA (cargo build --release)"
case "$CTRL" in nvme[0-9]*) ;; *) die "bad controller name $CTRL" ;; esac
S=/sys/class/nvme/$CTRL
[ -d "$S" ] || die "$CTRL not found"
[ "$(cat $S/transport)" = tcp ] || die "$CTRL is not NVMe/TCP"
[ "$(cat $S/state)" = live ] || die "$CTRL is not live"
ADDR=$(cat $S/address)
TRADDR=$(echo "$ADDR" | tr ',' '\n' | sed -n 's/^traddr=//p')
TRSVCID=$(echo "$ADDR" | tr ',' '\n' | sed -n 's/^trsvcid=//p')
[[ "$TRADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "only IPv4 targets supported by this script (got $TRADDR)"
SUBSYS=$(cat $S/subsysnqn)
OTHERS=0
for c in /sys/class/nvme/nvme*; do
    [ "$c" = "$S" ] && continue
    [ "$(cat $c/subsysnqn 2>/dev/null)" = "$SUBSYS" ] && [ "$(cat $c/state 2>/dev/null)" = live ] && OTHERS=$((OTHERS + 1))
done
[ "$OTHERS" -ge 1 ] || die "$CTRL is the only live path of its subsystem; refusing"
DEV=$(ip route get "$TRADDR" | grep -oP 'dev \K\S+')
[ -n "$DEV" ] || die "no route to $TRADDR"
# the target must not share an address with any other controller (scoping)
SHARED=$(grep -l "traddr=$TRADDR," /sys/class/nvme/nvme*/address 2>/dev/null | wc -l)
[ "$SHARED" -eq 1 ] || die "$TRADDR is used by $SHARED controllers; impairment would not be scoped to $CTRL"

IFB=nvt-ifb0
ip link show "$IFB" >/dev/null 2>&1 && die "$IFB already exists (stale run?); remove it first"
tc qdisc show dev "$DEV" | grep -q clsact && die "$DEV already has a clsact qdisc; refusing to touch it"

mkdir -p "$OUT"
echo "controller=$CTRL target=$TRADDR:$TRSVCID dev=$DEV other_live_paths=$OTHERS loss=$LOSS delay=$DELAY" | tee "$OUT/setup.txt"
tc qdisc show dev "$DEV" > "$OUT/qdisc-before.txt"
LOADED=""
for m in ifb sch_ingress act_mirred cls_u32 sch_netem; do
    if ! grep -q "^$m " /proc/modules; then
        if [ "$m" = ifb ]; then modprobe ifb numifbs=0; else modprobe "$m"; fi || die "modprobe $m"
        LOADED="$m $LOADED"
    fi
done

TOP_PID=""
OBS_PID=""
PROF_PID=""
HOG_PID=""
SETUP=0
impair_setup() { # pass-through netem on the ifb, redirect only the target's packets to it
    ip link add "$IFB" type ifb || die "ip link add $IFB"
    SETUP=1
    ip link set "$IFB" mtu "$(cat /sys/class/net/$DEV/mtu)" up || die "ifb up"
    tc qdisc add dev "$IFB" root handle 1: netem limit 100000 || die "tc netem"
    tc qdisc add dev "$DEV" clsact || die "tc clsact"
    tc filter add dev "$DEV" egress protocol ip prio 1 u32 match ip dst "$TRADDR"/32 \
        action mirred egress redirect dev "$IFB" || die "tc filter"
}
impair() { # netem parameters for the next phase; none = pass-through
    tc qdisc change dev "$IFB" root handle 1: netem limit 100000 "$@" || die "tc netem change $*"
    echo "$(date +%s.%N) netem ${*:-pass-through}" >> "$OUT/netem.log"
}
netem_stats() { tc -s qdisc show dev "$IFB" > "$OUT/netem-$1.txt"; }
cleanup() {
    if [ "$SETUP" = 1 ]; then
        tc qdisc del dev "$DEV" clsact 2>/dev/null
        ip link del "$IFB" 2>/dev/null
    fi
    [ -n "$HOG_PID" ] && kill "$HOG_PID" 2>/dev/null
    [ -n "$OBS_PID" ] && kill "$OBS_PID" 2>/dev/null
    [ -n "$PROF_PID" ] && kill "$PROF_PID" 2>/dev/null
    [ -n "$TOP_PID" ] && kill "$TOP_PID" 2>/dev/null
    wait 2>/dev/null
    for m in $LOADED; do modprobe -r "$m" 2>/dev/null; done
    tc qdisc show dev "$DEV" > "$OUT/qdisc-after.txt"
    cmp -s "$OUT/qdisc-before.txt" "$OUT/qdisc-after.txt" && q=unchanged || q=CHANGED
    echo "[$(date +%T)] cleaned up: $IFB and clsact removed, qdiscs on $DEV $q; controller $CTRL state $(cat $S/state 2>/dev/null)"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mark() { echo "$1 $(date +%s.%N)" >> "$OUT/phases.log"; echo "[$(date +%T)] $1"; }
observe() { # phase seconds: a queues run whose two samples bracket the phase
    "$NVMETEA" queues -i $(($2 - 3)) --json > "$OUT/queues-$1.json" 2> "$OUT/queues-$1.err" &
    OBS_PID=$!
    if [ "$PROFILE" != 0 ]; then
        "$NVMETEA" profile -i $(($2 - 5)) --sample "$PROFILE" --slowest 10 --json \
            > "$OUT/profile-$1.json" 2> "$OUT/profile-$1.err" &
        PROF_PID=$!
    fi
}
finish_observe() {
    [ -n "$OBS_PID" ] && wait "$OBS_PID"
    [ -n "$PROF_PID" ] && wait "$PROF_PID"
    OBS_PID=""
    PROF_PID=""
}
queue_field() { # tcp.json qid field -> value of the controller's queue
    python3 -I -c '
import json,sys
d=json.load(open(sys.argv[1]))
for s in d["sockets"]:
    if s.get("controller")==sys.argv[2] and s["qid"]["value"]==int(sys.argv[3]):
        v=s[sys.argv[4]]
        print(v["value"] if isinstance(v,dict) else v.rsplit(":",1)[1]); break
' "$OUT/tcp-before.json" "$CTRL" "$1" "$2"
}
recover() { mark "recover_$1_start"; sleep "$REC"; mark "recover_$1_end"; }

"$NVMETEA" top -i 1 --json > "$OUT/top.ndjson" 2> "$OUT/top.err" &
TOP_PID=$!
sleep 3

# the redirect + pass-through netem stay in place for the whole run, so the only
# difference between the baseline and the loss/delay phases is the impairment
impair_setup
impair
sleep 2
mark baseline_start; observe baseline "$BASE"; sleep "$BASE"; finish_observe; mark baseline_end
netem_stats baseline

"$NVMETEA" tcp -i 0 --json > "$OUT/tcp-before.json" 2>/dev/null
for ph in $PHASES; do
    case "$ph" in
    loss | delay)
        if [ "$ph" = loss ]; then impair loss "$LOSS"; else impair delay "$DELAY"; fi
        mark "${ph}_start"; observe "$ph" "$PH"; sleep "$PH"; finish_observe; mark "${ph}_end"
        netem_stats "$ph"
        impair
        recover "$ph"
        ;;
    cpuhog)
        HOGCPU=$(queue_field "$HOGQID" io_cpu)
        [ -n "$HOGCPU" ] && [ "$HOGCPU" != None ] || die "no io_cpu for $CTRL qid $HOGQID"
        echo "cpuhog: $CTRL qid $HOGQID io_cpu $HOGCPU" | tee -a "$OUT/setup.txt"
        mark cpuhog_start
        observe cpuhog "$PH"
        nice -n -20 taskset -c "$HOGCPU" bash -c 'while :; do :; done' &
        HOG_PID=$!
        sleep "$PH"
        kill "$HOG_PID" 2>/dev/null; wait "$HOG_PID" 2>/dev/null; HOG_PID=""
        finish_observe; mark cpuhog_end
        recover cpuhog
        ;;
    rthog)
        HOGCPU=$(queue_field "$HOGQID" io_cpu)
        [ -n "$HOGCPU" ] && [ "$HOGCPU" != None ] || die "no io_cpu for $CTRL qid $HOGQID"
        echo "rthog: $CTRL qid $HOGQID io_cpu $HOGCPU SCHED_FIFO busy ${RTBUSY_MS}ms every ${RTPERIOD_MS}ms" | tee -a "$OUT/setup.txt"
        mark rthog_start
        observe rthog "$PH"
        chrt -f 1 taskset -c "$HOGCPU" python3 -I -c "
import time
busy, period = $RTBUSY_MS / 1e3, $RTPERIOD_MS / 1e3
while True:
    end = time.perf_counter() + busy
    while time.perf_counter() < end:
        pass
    time.sleep(period - busy)
" &
        HOG_PID=$!
        sleep "$PH"
        kill "$HOG_PID" 2>/dev/null; wait "$HOG_PID" 2>/dev/null; HOG_PID=""
        finish_observe; mark rthog_end
        recover rthog
        ;;
    rst)
        PORT=$(queue_field "$RSTQID" local)
        [ -n "$PORT" ] || die "could not find $CTRL qid $RSTQID connection"
        echo "rst target: $CTRL qid $RSTQID local port $PORT" | tee -a "$OUT/setup.txt"
        mark rst_start
        observe rst "$RSTWAIT"
        sleep 1
        ss -K dst "$TRADDR" dport = ":$TRSVCID" sport = ":$PORT" > "$OUT/ss-kill.txt" 2>&1
        mark rst_done
        sleep $((RSTWAIT - 1))
        finish_observe
        mark rst_end
        for i in $(seq 1 20); do [ "$(cat $S/state)" = live ] && break; sleep 1; done
        ;;
    *) die "unknown phase $ph" ;;
    esac
done
"$NVMETEA" tcp -i 0 --json > "$OUT/tcp-after.json" 2>/dev/null
mark end
sleep 2
echo "outputs in $OUT; analyse with: python3 -I $HERE/analyze.py $OUT $CTRL"
