// SPDX-License-Identifier: (MIT OR GPL-2.0)
/*
 * nvmetea Level 3: NVMe/TCP queue sockets (probe ids T1, T3-T7 in
 * docs/kernel-compatibility.md).
 *
 *   iter/tcp                    T1  queue <-> socket table (on demand, no per-packet cost)
 *   raw_tp/tcp_retransmit_skb   T3  retransmissions
 *   raw_tp/inet_sock_set_state  T4  socket state changes
 *   raw_tp/tcp_cong_state_set   T5  congestion-state entries (absent on 5.15)
 *   raw_tp/tcp_receive_reset    T6  RST received
 *   raw_tp/tcp_send_reset       T6  RST sent
 *   raw_tp/inet_sk_error_report T7  socket errors
 *
 * A socket belongs to NVMe/TCP when sk->sk_user_data points to an
 * nvme_tcp_queue whose sock->sk points back to the socket, and the queue's
 * controller has ops->name "tcp". The queue index is
 * (queue - ctrl->queues) / sizeof(struct nvme_tcp_queue), the driver's own qid.
 * These tracepoints fire for every TCP socket on the host; non-NVMe sockets
 * return after a few reads.
 */
#include "kernel_types.h"

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "nvmetea.h"
#include "nvme_tcp.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

volatile bool armed;
volatile __u32 events_per_cpu_per_s;

/* layout anchors for the generated Rust types */
struct nvt_qsock nvt_layout_qsock;
struct nvt_ev_tcp nvt_layout_ev_tcp;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096); /* resized from topology; LRU drops closed sockets */
	__type(key, __u64);        /* socket cookie */
	__type(value, struct nvt_sstats);
} sstats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} tevents SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} ev_budget SEC(".maps");

/* [0] NVMe queue-socket events, [1] dropped (budget/ringbuf), [2] no cookie yet, [3] all TCP events seen */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} tcounters SEC(".maps");

static __always_inline void tcount(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&tcounters, &i);
	if (v)
		*v += 1;
}

static __always_inline __u64 cookie_of(const struct sock *sk)
{
	__u64 c = 0;

	bpf_core_read(&c, sizeof(c), &sk->__sk_common.skc_cookie);
	return c;
}

/* ------------------------------------------------------------ T1: iter/tcp */

SEC("iter/tcp")
int nvt_iter_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	struct nvt_qsock r = {};
	struct nvme_tcp_queue *q;
	unsigned char st;

	if (!skc)
		return 0;
	st = BPF_CORE_READ(skc, skc_state);
	if (st == 6 /* TIME_WAIT */ || st == 12 /* NEW_SYN_RECV */ || st == 10 /* LISTEN */)
		return 0;
	q = nvme_queue_of((const struct sock *)skc);
	if (!q || !queue_ident(q, &r.inst, &r.qid))
		return 0;
	/* generates the cookie if nothing has asked for it yet */
	r.cookie = bpf_get_socket_cookie(skc);
	r.family = BPF_CORE_READ(skc, skc_family);
	r.lport = BPF_CORE_READ(skc, skc_num);
	r.rport = __builtin_bswap16(BPF_CORE_READ(skc, skc_dport));
	r.state = st;
	if (r.family == 10 /* AF_INET6 */) {
		bpf_core_read(r.laddr, 16, &skc->skc_v6_rcv_saddr);
		bpf_core_read(r.raddr, 16, &skc->skc_v6_daddr);
	} else {
		bpf_core_read(r.laddr, 4, &skc->skc_rcv_saddr);
		bpf_core_read(r.raddr, 4, &skc->skc_daddr);
	}
	r.io_cpu = BPF_CORE_READ(q, io_cpu);
	if (BPF_CORE_READ(q, hdr_digest))
		r.flags |= NVT_QS_HDR_DIGEST;
	if (BPF_CORE_READ(q, data_digest))
		r.flags |= NVT_QS_DATA_DIGEST;
	if (bpf_core_field_exists(q->tls_enabled)) {
		if (BPF_CORE_READ(q, tls_enabled))
			r.flags |= NVT_QS_TLS;
	} else {
		r.flags |= NVT_QS_TLS_UNKNOWN;
	}
	bpf_seq_write(seq, &r, sizeof(r));
	return 0;
}

/* --------------------------------------------------------- T3-T7: events */

static __always_inline bool budget_ok(__u64 now)
{
	__u32 k0 = 0, k1 = 1;
	__u64 *win = bpf_map_lookup_elem(&ev_budget, &k0);
	__u64 *n = bpf_map_lookup_elem(&ev_budget, &k1);
	__u64 sec = now / 1000000000ULL;

	if (!win || !n)
		return false;
	if (*win != sec) {
		*win = sec;
		*n = 0;
	}
	if (*n >= events_per_cpu_per_s)
		return false;
	*n += 1;
	return true;
}

/* Count an event on an NVMe/TCP queue socket and emit it (rate-limited). */
static __always_inline void on_event(const struct sock *sk, __u32 tkind, __s32 a, __s32 b)
{
	struct nvme_tcp_queue *q;
	struct nvt_sstats *s, zero = {};
	struct nvt_ev_tcp *ev;
	__u64 cookie, now;
	__u32 inst = 0;
	__u16 qid = 0;

	if (!armed)
		return;
	tcount(3); /* every TCP event on the host, before the NVMe filter */
	q = nvme_queue_of(sk);
	if (!q || !queue_ident(q, &inst, &qid))
		return;
	tcount(0);
	now = bpf_ktime_get_ns();
	cookie = cookie_of(sk);
	if (!cookie)
		tcount(2); /* counted below under cookie 0 until sock_diag/iter generates one */
	s = bpf_map_lookup_elem(&sstats, &cookie);
	if (!s) {
		zero.inst = inst;
		zero.qid = qid;
		bpf_map_update_elem(&sstats, &cookie, &zero, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&sstats, &cookie);
	}
	if (s) {
		switch (tkind) {
		case NVT_TEV_RETRANS: __sync_fetch_and_add(&s->retrans, 1); break;
		case NVT_TEV_STATE: __sync_fetch_and_add(&s->state_changes, 1); break;
		case NVT_TEV_RST_RX: __sync_fetch_and_add(&s->rst_rx, 1); break;
		case NVT_TEV_RST_TX: __sync_fetch_and_add(&s->rst_tx, 1); break;
		case NVT_TEV_ERROR: __sync_fetch_and_add(&s->errors, 1); break;
		case NVT_TEV_CONG:
			if (a == 4) /* TCP_CA_Loss */
				__sync_fetch_and_add(&s->loss_entries, 1);
			else if (a == 3) /* TCP_CA_Recovery */
				__sync_fetch_and_add(&s->recovery_entries, 1);
			else if (a == 2) /* TCP_CA_CWR */
				__sync_fetch_and_add(&s->cwr_entries, 1);
			break;
		}
		s->last_event_ns = now;
	}
	if (!budget_ok(now)) {
		tcount(1);
		return;
	}
	ev = bpf_ringbuf_reserve(&tevents, sizeof(*ev), 0);
	if (!ev) {
		tcount(1);
		return;
	}
	ev->kind = NVT_EV_TCP;
	ev->tkind = tkind;
	ev->t = now;
	ev->cookie = cookie;
	ev->inst = inst;
	ev->qid = qid;
	ev->pad = 0;
	ev->a = a;
	ev->b = b;
	bpf_ringbuf_submit(ev, 0);
}

SEC("raw_tp/tcp_retransmit_skb")
int BPF_PROG(nvt_tcp_retransmit, const struct sock *sk, const void *skb)
{
	on_event(sk, NVT_TEV_RETRANS, 0, 0);
	return 0;
}

SEC("raw_tp/inet_sock_set_state")
int BPF_PROG(nvt_sock_state, const struct sock *sk, int oldstate, int newstate)
{
	on_event(sk, NVT_TEV_STATE, oldstate, newstate);
	return 0;
}

SEC("raw_tp/tcp_cong_state_set")
int BPF_PROG(nvt_cong_state, const struct sock *sk, __u8 ca_state)
{
	/* entering Open (0) / Disorder (1) is routine; count the costly states */
	if (ca_state >= 2)
		on_event(sk, NVT_TEV_CONG, ca_state, 0);
	return 0;
}

SEC("raw_tp/tcp_receive_reset")
int BPF_PROG(nvt_rst_rx, const struct sock *sk)
{
	on_event(sk, NVT_TEV_RST_RX, 0, 0);
	return 0;
}

SEC("raw_tp/tcp_send_reset")
int BPF_PROG(nvt_rst_tx, const struct sock *sk)
{
	if (sk)
		on_event(sk, NVT_TEV_RST_TX, 0, 0);
	return 0;
}

SEC("raw_tp/inet_sk_error_report")
int BPF_PROG(nvt_sk_error, const struct sock *sk)
{
	on_event(sk, NVT_TEV_ERROR, BPF_CORE_READ(sk, sk_err), 0);
	return 0;
}
