#!/bin/bash
# Offline capability inspection of a kernel build (no boot required).
# usage: inspect_kernel.sh <label> <vmlinux-ELF-with-.BTF> <config> <nvme-tcp.ko> <nvme-core.ko> <outdir>
# Prints a compact, machine-greppable report of the facts nvmetea's probe planner depends on.
set -u
L=$1; VM=$2; CFG=$3; TCP=$4; CORE=$5; OUT=$6
mkdir -p "$OUT"
echo "===== $L"
echo -n "config: "; grep -E '^CONFIG_(DEBUG_INFO_BTF|DEBUG_INFO_BTF_MODULES|NVME_TCP_TLS|NVME_MULTIPATH|FPROBE|DYNAMIC_FTRACE_WITH_DIRECT_CALLS|KPROBE_EVENTS|BPF_KPROBE_OVERRIDE|NET_SCH_NETEM|BLK_DEV_NULL_BLK|NVME_TARGET_TCP|INET_DIAG|INET_TCP_DIAG)=' "$CFG" | sed 's/CONFIG_//' | tr '\n' ' '; echo
for m in "$TCP" "$CORE"; do echo -n "$(basename $m) .BTF: "; readelf -S "$m" 2>/dev/null | grep -q '\.BTF ' && echo yes || echo NO; done
bpftool btf dump file "$VM" format c > "$OUT/vmlinux.h" 2>/dev/null
bpftool btf dump file "$TCP" -B "$VM" format c > "$OUT/nvme_tcp.h" 2>/dev/null
bpftool btf dump file "$CORE" -B "$VM" format c > "$OUT/nvme_core.h" 2>/dev/null
bpftool btf dump file "$TCP" -B "$VM" 2>/dev/null | grep -E "^\[[0-9]+\] FUNC '" | sed -E "s/.*FUNC '([^']+)'.*/\1/" | sort -u > "$OUT/tcp_btf_funcs"
readelf -sW "$TCP" | awk '$4=="FUNC" {print $8}' | grep -v '^__pfx_' | sort -u > "$OUT/tcp_syms"
echo -n "nvme_tcp key fns (Y=sym+BTF, s=sym-only, b=BTF-only, -=inlined/absent): "
for f in nvme_tcp_queue_rq nvme_tcp_io_work nvme_tcp_try_send nvme_tcp_try_send_cmd_pdu nvme_tcp_try_send_data nvme_tcp_try_send_data_pdu nvme_tcp_try_send_ddgst nvme_tcp_try_recv nvme_tcp_recv_skb nvme_tcp_recv_pdu nvme_tcp_recv_data nvme_tcp_handle_c2h_data nvme_tcp_handle_r2t nvme_tcp_handle_comp nvme_tcp_process_nvme_cqe nvme_tcp_setup_h2c_data_pdu nvme_tcp_setup_cmd_pdu nvme_tcp_data_ready nvme_tcp_state_change nvme_tcp_write_space nvme_tcp_poll nvme_tcp_timeout nvme_tcp_error_recovery_work nvme_tcp_reconnect_ctrl_work nvme_tcp_set_queue_io_cpu; do
  s=$(grep -qx "$f" "$OUT/tcp_syms" && echo 1 || echo 0); b=$(grep -qx "$f" "$OUT/tcp_btf_funcs" && echo 1 || echo 0)
  c=$(grep -E "^$f\.(constprop|isra|part|cold)" "$OUT/tcp_syms" | head -1)
  if [ $s = 1 ] && [ $b = 1 ]; then t=Y; elif [ $s = 1 ]; then t=s; elif [ $b = 1 ]; then t="b${c:+($c)}"; else t="-${c:+($c)}"; fi
  echo -n "${f#nvme_tcp_}=$t "
done; echo
echo -n "suffixed clones: "; grep -E '\.(constprop|isra|part|cold)' "$OUT/tcp_syms" | tr '\n' ' '; echo
echo -n "block tp: "; for t in block_rq_issue block_rq_complete block_io_start block_io_done block_rq_insert block_rq_requeue block_bio_queue block_bio_remap block_rq_error; do grep -q "btf_trace_$t)" "$OUT/vmlinux.h" && echo -n "$t " ; done; echo
echo -n "net tp: "; for t in tcp_retransmit_skb tcp_probe tcp_cong_state_set inet_sock_set_state tcp_send_reset tcp_receive_reset sock_exceed_buf_limit tcp_rcv_space_adjust tcp_destroy_sock sk_data_ready sock_rcvqueue_full; do grep -q "btf_trace_$t)" "$OUT/vmlinux.h" && echo -n "$t " ; done; echo
echo -n "nvme tp: "; grep -oE 'btf_trace_nvme_[a-z_]+\)\([^;]*' "$OUT/nvme_core.h" | tr '\n' ' '; echo
echo -n "nvme_request: "; awk '/^struct nvme_request \{/,/^\};/' "$OUT/nvme_core.h" | tr -s '\t\n' ' '; echo
echo -n "request: "; awk '/^struct request \{/,/^\};/' "$OUT/vmlinux.h" | grep -oE '(start_time_ns|io_start_time_ns|alloc_time_ns|mq_hctx|__data_len|internal_tag|tag);' | tr '\n' ' '; echo
echo -n "nvme_tcp_queue: "; awk '/^struct nvme_tcp_queue \{/,/^\};/' "$OUT/nvme_tcp.h" | grep -oE '[a-z_]+;' | tr '\n' ' '; echo
echo -n "nvme_tcp_request: "; awk '/^struct nvme_tcp_request \{/,/^\};/' "$OUT/nvme_tcp.h" | grep -oE '[a-z_]+;' | tr '\n' ' '; echo
echo -n "sock_common cookie: "; awk '/^struct sock_common \{/,/^\};/' "$OUT/vmlinux.h" | grep -oE 'skc_cookie;' ; echo
bpftool btf dump file "$VM" 2>/dev/null | grep -E "^\[[0-9]+\] FUNC '" | sed -E "s/.*FUNC '([^']+)'.*/\1/" | sort -u > "$OUT/vmlinux_btf_funcs"
echo -n "vmlinux BTF FUNCs: "; for f in kernel_sendpage sock_no_sendpage sock_sendmsg tcp_sendmsg tcp_sendmsg_locked skb_copy_datagram_iter skb_copy_and_hash_datagram_iter tcp_read_sock blk_mq_complete_request_remote bpf_fentry_test1 blk_mq_start_request; do grep -qx "$f" "$OUT/vmlinux_btf_funcs" && echo -n "$f " ; done; echo
