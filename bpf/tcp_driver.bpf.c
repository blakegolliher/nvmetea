// SPDX-License-Identifier: (MIT OR GPL-2.0)
/*
 * nvmetea Level 2: NVMe/TCP driver stage boundaries for sampled commands
 * (probe ids D1-D12 in docs/kernel-compatibility.md; boundaries and stages in
 * docs/latency-model.md §3 and §5).
 *
 *   raw_tp/nvme_setup_cmd            E_SETUP, sampling decision, record created
 *   D6  nvme_tcp_io_work             per-queue worker stats
 *   D1  nvme_tcp_try_send_cmd_pdu    entry: E_TX_START, send context; exit: E_CMD_SENT
 *   D2  nvme_tcp_try_send_data       in-capsule data done (E_CMD_SENT) or E_H2C_SENT; busy_h2c
 *       nvme_tcp_try_send_ddgst      same, when a data digest ends the PDU
 *   D3  nvme_tcp_try_send_data_pdu   E_H2C_START
 *   D4  nvme_tcp_setup_h2c_data_pdu  E_R2T_PROC (only inside a receive call: R2T parsed)
 *   D7  nvme_tcp_recv_skb            receive context: call start, skb end_seq
 *   D8  skb_copy_datagram_iter       READ data copies (inside a receive call only)
 *   D9  blk_mq_complete_request_remote  E_RSP_PARSED
 *   D10 nvme_tcp_data_ready          per-queue ring of (time, rcv_nxt): sequence-mapped
 *                                    notification boundaries (latency model §5.4)
 *   D12 nvme_tcp_timeout             timeout events
 *   raw_tp/nvme_complete_rq          E_NVME_DONE
 *   raw_tp/block_rq_complete         E_BLK_DONE, record emitted
 *
 * Every function hook exists in two flavours, kprobe/kretprobe and
 * fentry/fexit; userspace loads one (fentry only after the attach preflight).
 * Both read arguments as scalars, so every dereference goes through CO-RE
 * reads (finding F14).
 *
 * Only sampled commands get a record (1 in sample_every, bpf_get_prandom_u32).
 * Per-packet hooks return after one check while no sampled command is in
 * flight, and do no further work on queues without one (per-queue count in
 * the notification ring entry). Per-thread contexts live in per-CPU slots tagged with the thread id:
 * a context lost to preemption is dropped, never misattributed.
 */
#include "kernel_types.h"

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "nvmetea.h"
#include "nvme_tcp.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Set by userspace. */
volatile bool armed;
volatile __u32 sample_every;  /* 1 = every command */
volatile __s32 only_inst;     /* -1 = every NVMe/TCP controller */
/* Sampled commands in flight; per-packet hooks do nothing while it is 0. */
volatile __s64 sampled_inflight;

/* layout anchors for the generated Rust types */
struct nvt_ev_prof nvt_layout_ev_prof;
struct nvt_ev_timeout nvt_layout_ev_timeout;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096); /* resized from topology */
	__type(key, __u64);        /* driver PDU address (never leaves the kernel) */
	__type(value, struct nvt_prof);
} prof SEC(".maps");

/* (queue, command id) -> PDU address, for sampled READs (data copy attribution). */
struct cid_key {
	__u64 queue;
	__u16 cid;
	__u16 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct cid_key);
	__type(value, __u64);
} bycid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024); /* resized from topology */
	__type(key, __u64);        /* queue address */
	__type(value, struct nvt_nring);
} nring SEC(".maps");

/* queue address -> (instance, qid), computed once per queue object */
struct qid_val {
	__u32 inst;
	__u16 qid;
	__u16 valid;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct qid_val);
} qcache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct nvt_qkey);
	__type(value, struct nvt_wstats);
} wstats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nvt_dcounters);
} dcounters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nvt_nring);
} zero_ring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} devents SEC(".maps");

/* per-thread contexts (per-CPU slot tagged with the thread id) */
struct rx_ctx {
	__u64 tid;
	__u64 t_enter;
	__u64 queue;
	__u64 cur_key;    /* READ whose data this call is processing (busy accounting) */
	__u64 busy_from;
	__u32 end_seq;    /* TCP_SKB_CB(skb)->end_seq of the skb being processed */
	__u32 pad;
};

struct tx_ctx {
	__u64 tid;
	__u64 req;
	__u64 t_enter;
};

struct iow_ctx {
	__u64 tid;
	__u64 t_enter;
	__u64 queue;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rx_ctx);
} rxctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tx_ctx);
} txctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct iow_ctx);
} iowctx SEC(".maps");

/* ------------------------------------------------------------------ helpers */

static __always_inline void dcount(__u32 i)
{
	__u32 z = 0;
	struct nvt_dcounters *c = bpf_map_lookup_elem(&dcounters, &z);

	if (c && i < NVT_D_NR)
		c->c[i] += 1;
}

static __always_inline void *slot(void *map)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(map, &z);
}

static __always_inline bool hot(void)
{
	return armed && sampled_inflight > 0;
}

static __always_inline struct nvt_prof *prof_of(__u64 key)
{
	return bpf_map_lookup_elem(&prof, &key);
}

static __always_inline __u64 pdu_of_rq(__u64 rq)
{
	return rq + bpf_core_type_size(struct request);
}

/* The receive context of the current thread, if this thread is inside
 * nvme_tcp_recv_skb. */
static __always_inline struct rx_ctx *cur_rx(__u64 tid)
{
	struct rx_ctx *rx = slot(&rxctx);

	if (!rx || rx->tid != tid)
		return NULL;
	return rx;
}

/*
 * Sequence-mapped notification (latency model §5.4): the earliest recorded
 * sk_data_ready whose rcv_nxt covers @end_seq, i.e. the first moment the whole
 * skb holding the PDU had been delivered to the socket. Valid only within
 * [not_before, now]. Returns 0 when the ring cannot resolve it (including when
 * the oldest kept entry already covers it: an earlier one may be overwritten).
 */
static __always_inline __u64 seq_notify(__u64 queue, __u32 end_seq, __u64 not_before, __u64 now)
{
	struct nvt_nring *r = bpf_map_lookup_elem(&nring, &queue);
	__u64 best = 0;
	__u32 i, oldest;

	if (!r)
		return 0;
	for (i = 0; i < NVT_NRING; i++) {
		__u64 t = r->t[i];
		__s32 d = (__s32)(r->seq[i] - end_seq);

		if (t && d >= 0 && (!best || t < best))
			best = t;
	}
	if (!best)
		return 0;
	if (r->head >= NVT_NRING) {
		oldest = r->head % NVT_NRING;
		if (oldest < NVT_NRING && r->t[oldest] == best)
			return 0;
	}
	if (best < not_before || best > now)
		return 0;
	return best;
}

static __always_inline bool qident_cached(__u64 queue, __u32 *inst, __u16 *qid)
{
	struct qid_val *v = bpf_map_lookup_elem(&qcache, &queue);
	struct qid_val nv = {};

	if (v) {
		*inst = v->inst;
		*qid = v->qid;
		return v->valid;
	}
	nv.valid = queue_ident((struct nvme_tcp_queue *)queue, &nv.inst, &nv.qid);
	bpf_map_update_elem(&qcache, &queue, &nv, BPF_ANY);
	*inst = nv.inst;
	*qid = nv.qid;
	return nv.valid;
}

static __always_inline bool is_tcp_ctrl(struct nvme_ctrl *ctrl)
{
	const struct nvme_ctrl_ops *ops = BPF_CORE_READ(ctrl, ops);
	const char *name;
	char b[4] = {};

	if (!ops)
		return false;
	name = BPF_CORE_READ(ops, name);
	if (bpf_probe_read_kernel_str(b, sizeof(b), name) < 0)
		return false;
	return b[0] == 't' && b[1] == 'c' && b[2] == 'p' && b[3] == 0;
}

static __always_inline void finish(__u64 key, struct nvt_prof *p)
{
	__u64 q = (__u64)BPF_CORE_READ((struct nvme_tcp_request *)key, queue);
	struct nvt_nring *r = bpf_map_lookup_elem(&nring, &q);

	if (p->opcode == 0x02) {
		struct cid_key ck = {};

		ck.queue = q;
		ck.cid = p->cid;
		bpf_map_delete_elem(&bycid, &ck);
	}
	bpf_map_delete_elem(&prof, &key);
	if (r)
		__sync_fetch_and_add(&r->hot, -1);
	__sync_fetch_and_add(&sampled_inflight, -1);
}

/* The notification ring of a queue, created on first use. */
static __always_inline struct nvt_nring *ring_of(__u64 q)
{
	struct nvt_nring *r = bpf_map_lookup_elem(&nring, &q);
	struct nvt_nring *z;

	if (r)
		return r;
	z = slot(&zero_ring);
	if (!z)
		return NULL;
	bpf_map_update_elem(&nring, &q, z, BPF_NOEXIST);
	return bpf_map_lookup_elem(&nring, &q);
}

/* A queue has sampled commands in flight: only then do per-packet hooks work. */
static __always_inline struct nvt_nring *hot_ring(__u64 q)
{
	struct nvt_nring *r = bpf_map_lookup_elem(&nring, &q);

	return r && r->hot > 0 ? r : NULL;
}

/* ------------------------------------------------- E_SETUP: sampling (P1) */

SEC("raw_tp/nvme_setup_cmd")
int BPF_PROG(nvt_d_setup, struct request *rq, void *cmd)
{
	struct nvme_request *nr;
	struct nvme_ctrl *ctrl;
	struct nvt_wire_cmd wc;
	struct nvt_prof *p, np = {};
	struct nvme_tcp_queue *q;
	__u64 key, now;
	__u8 retries;
	__u16 qid;

	if (!armed)
		return 0;
	key = pdu_of_rq((__u64)rq);
	nr = (struct nvme_request *)key;
	now = bpf_ktime_get_ns();
	p = prof_of(key);
	if (p) {
		retries = BPF_CORE_READ(nr, retries);
		if (retries > p->retries) {
			/* the same sampled request dispatched again */
			p->retries = retries;
			p->flags |= NVT_PF_RETRIED;
			p->t_setup = now;
			p->t_tx_start = 0;
			p->t_cmd_sent = 0;
			dcount(NVT_D_RETRIED);
			return 0;
		}
		/* a completion was missed: replace */
		dcount(NVT_D_STALE);
		finish(key, p);
	}
	if (sample_every > 1 && bpf_get_prandom_u32() % sample_every)
		return 0;
	qid = BPF_CORE_READ(rq, q, queuedata) ? (__u16)(BPF_CORE_READ(rq, mq_hctx, queue_num) + 1) : 0;
	if (qid == 0)
		return 0; /* admin queue: not staged */
	ctrl = BPF_CORE_READ(nr, ctrl);
	if (!ctrl || !is_tcp_ctrl(ctrl))
		return 0;
	np.inst = (__u16)BPF_CORE_READ(ctrl, instance);
	if (only_inst >= 0 && np.inst != (__u16)only_inst)
		return 0;
	if (bpf_probe_read_kernel(&wc, sizeof(wc), cmd))
		return 0;
	q = BPF_CORE_READ((struct nvme_tcp_request *)key, queue);
	np.t_setup = now;
	np.t_start = BPF_CORE_READ(rq, start_time_ns);
	if (!np.t_start)
		np.flags |= NVT_PF_NO_START;
	np.qid = qid;
	np.cid = wc.command_id;
	np.nsid = wc.nsid;
	np.opcode = wc.opcode;
	np.bytes = BPF_CORE_READ(rq, __data_len);
	np.cpu_submit = (__u16)bpf_get_smp_processor_id();
	np.io_cpu = q ? BPF_CORE_READ(q, io_cpu) : -1;
	np.retries = BPF_CORE_READ(nr, retries);
	np.seq = ((__u64)np.cpu_submit << 48) | (now & 0xffffffffffffULL);
	if (bpf_map_update_elem(&prof, &key, &np, BPF_NOEXIST)) {
		dcount(NVT_D_MAP_FULL);
		return 0;
	}
	if (wc.opcode == 0x02 && q) {
		struct cid_key ck = { .queue = (__u64)q, .cid = wc.command_id };

		bpf_map_update_elem(&bycid, &ck, &key, BPF_ANY);
	}
	if (q) {
		struct nvt_nring *r = ring_of((__u64)q);

		if (r)
			__sync_fetch_and_add(&r->hot, 1);
	}
	__sync_fetch_and_add(&sampled_inflight, 1);
	dcount(NVT_D_SAMPLED);
	return 0;
}

/* --------------------------------------------------------- D6: io_work */

static __always_inline void on_io_work_enter(__u64 w)
{
	struct iow_ctx *c = slot(&iowctx);

	if (!armed || !c)
		return;
	c->tid = bpf_get_current_pid_tgid();
	c->t_enter = bpf_ktime_get_ns();
	c->queue = w - bpf_core_field_offset(struct nvme_tcp_queue, io_work);
}

static __always_inline void on_io_work_exit(void)
{
	struct iow_ctx *c = slot(&iowctx);
	struct nvt_qkey k = {};
	struct nvt_wstats *ws, zero = {};
	__u64 now, el;
	__u32 inst;
	__u16 qid;

	if (!c)
		return;
	if (c->tid != bpf_get_current_pid_tgid()) {
		if (armed)
			dcount(NVT_D_IOW_CTX_LOST);
		return;
	}
	c->tid = 0;
	now = bpf_ktime_get_ns();
	el = now - c->t_enter;
	if (!qident_cached(c->queue, &inst, &qid))
		return;
	k.inst = (__u16)inst;
	k.qid = qid;
	ws = bpf_map_lookup_elem(&wstats, &k);
	if (!ws) {
		bpf_map_update_elem(&wstats, &k, &zero, BPF_NOEXIST);
		ws = bpf_map_lookup_elem(&wstats, &k);
		if (!ws)
			return;
	}
	__sync_fetch_and_add(&ws->runs, 1);
	__sync_fetch_and_add(&ws->busy_ns, el);
	if (el >= 1000000)
		__sync_fetch_and_add(&ws->quota_runs, 1);
	if (el > ws->max_ns)
		ws->max_ns = el; /* racy max: may miss a concurrent maximum, never invents one */
}

/* ------------------------------------------------------ D1-D3: send path */

/* Entry of a send attempt of the command PDU: the first one is E_TX_START.
 * The sender is a workqueue worker (io_work) or the submitting context
 * (direct send: nvme_tcp_queue_request() on io_cpu sends every pending request
 * of the queue, not only its own). */
static __always_inline void on_cmd_pdu_enter(__u64 req)
{
	struct nvt_prof *p = prof_of(req);
	struct task_struct *task;

	if (!p || p->t_tx_start)
		return;
	p->t_tx_start = bpf_ktime_get_ns();
	task = (struct task_struct *)bpf_get_current_task();
	if (!(BPF_CORE_READ(task, flags) & PF_WQ_WORKER))
		p->flags |= NVT_PF_DIRECT;
}

static __always_inline bool send_done(__u64 req)
{
	struct nvme_tcp_queue *q = BPF_CORE_READ((struct nvme_tcp_request *)req, queue);

	/* nvme_tcp_done_send_req() clears queue->request when the request is fully sent */
	return q && BPF_CORE_READ(q, request) == NULL;
}

static __always_inline void on_cmd_pdu_exit(__u64 req, int ret)
{
	struct nvt_prof *p = prof_of(req);
	__u64 now;

	if (!p || ret != 1 || p->t_cmd_sent)
		return;
	now = bpf_ktime_get_ns();
	if (send_done(req))
		p->t_cmd_sent = now; /* no in-capsule data */
	else if (p->opcode == 0x01)
		p->flags |= NVT_PF_INLINE; /* in-capsule data follows: E_CMD_SENT at its end */
}

static __always_inline void on_data_enter(__u64 req)
{
	struct tx_ctx *c;

	if (!hot())
		return;
	c = slot(&txctx);
	if (!c)
		return;
	c->tid = bpf_get_current_pid_tgid();
	c->req = req;
	c->t_enter = bpf_ktime_get_ns();
}

/* try_send_data / try_send_ddgst returned: data (or its digest) handed to TCP. */
static __always_inline void on_data_exit(__u64 req, int ret, bool account_busy)
{
	struct nvt_prof *p = prof_of(req);
	struct tx_ctx *c;
	__u64 now;

	if (!p)
		return;
	now = bpf_ktime_get_ns();
	if (account_busy) {
		c = slot(&txctx);
		if (c && c->tid == bpf_get_current_pid_tgid() && c->req == req) {
			if (p->t_r2t_proc) {
				p->busy_h2c += now - c->t_enter;
				p->h2c_calls += 1;
			}
			c->tid = 0;
		} else {
			dcount(NVT_D_TX_CTX_LOST);
		}
	}
	if (ret != 1 || !send_done(req))
		return;
	if (p->t_r2t_proc) {
		p->t_h2c_sent = now; /* latest: the last solicited data */
	} else if (!p->t_cmd_sent) {
		p->t_cmd_sent = now; /* in-capsule data done */
		p->flags |= NVT_PF_INLINE;
	}
}

static __always_inline void on_data_pdu_enter(__u64 req)
{
	struct nvt_prof *p = prof_of(req);

	if (p && p->t_r2t_proc && !p->t_h2c_start)
		p->t_h2c_start = bpf_ktime_get_ns();
}

/* ------------------------------------------------- D4: R2T parsed (receive) */

static __always_inline void on_h2c_setup(__u64 req)
{
	struct nvt_prof *p = prof_of(req);
	struct rx_ctx *rx;
	__u64 tid, now, n;

	if (!p)
		return;
	tid = bpf_get_current_pid_tgid();
	rx = cur_rx(tid);
	if (!rx) {
		/* next H2C PDU of the same R2T, set up from the send path */
		dcount(NVT_D_H2C_CONT);
		return;
	}
	now = bpf_ktime_get_ns();
	if (p->r2ts < 255)
		p->r2ts += 1;
	p->flags |= NVT_PF_R2T;
	if (p->r2ts > 1) {
		p->flags |= NVT_PF_MULTI_R2T;
		return;
	}
	p->t_r2t_proc = now;
	p->t_r2t_start = rx->t_enter;
	n = seq_notify(rx->queue, rx->end_seq, p->t_cmd_sent, now);
	if (n) {
		p->t_r2t_notify = n;
	} else {
		p->flags |= NVT_PF_R2T_UNMAPPED;
		dcount(NVT_D_SEQ_UNRESOLVED);
	}
}

/* ------------------------------------------------ D7: receive context */

static __always_inline void on_recv_enter(__u64 skb)
{
	struct rx_ctx *rx;
	struct sock *sk;
	__u64 ud;
	__u32 end_seq = 0;

	if (!hot())
		return;
	rx = slot(&rxctx);
	if (!rx)
		return;
	sk = BPF_CORE_READ((struct sk_buff *)skb, sk);
	if (!sk)
		return;
	ud = (__u64)BPF_CORE_READ(sk, sk_user_data) & ~7ULL;
	if (!ud || !hot_ring(ud))
		return; /* no sampled command on this queue: nothing to attribute */
	/* TCP_SKB_CB(skb)->end_seq: second u32 of skb->cb */
	bpf_probe_read_kernel(&end_seq, sizeof(end_seq),
			      (void *)skb + bpf_core_field_offset(struct sk_buff, cb) + 4);
	rx->tid = bpf_get_current_pid_tgid();
	rx->t_enter = bpf_ktime_get_ns();
	rx->queue = ud;
	rx->end_seq = end_seq;
	rx->cur_key = 0;
	rx->busy_from = 0;
}

static __always_inline void close_busy(struct rx_ctx *rx, __u64 now)
{
	struct nvt_prof *p;

	if (!rx->cur_key)
		return;
	p = prof_of(rx->cur_key);
	if (p && now >= rx->busy_from) {
		p->busy_c2h += now - rx->busy_from;
		p->t_c2h_last = now; /* end of this READ's data processing so far */
	}
	rx->cur_key = 0;
}

static __always_inline void on_recv_exit(void)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct rx_ctx *rx = cur_rx(tid);

	if (!rx)
		return;
	close_busy(rx, bpf_ktime_get_ns());
	rx->tid = 0;
}

/* --------------------------------------------- D8: READ data copies */

struct c2h_hdr {
	__u8 type;     /* nvme_tcp_c2h_data = 7 */
	__u8 flags;    /* NVME_TCP_F_DATA_SUCCESS = 1 << 3 */
	__u8 hlen;
	__u8 pdo;
	__u32 plen;
	__u16 command_id;
	__u16 ttag;
};

static __always_inline void on_copy(void)
{
	struct rx_ctx *rx;
	struct c2h_hdr h;
	struct cid_key ck = {};
	struct nvt_prof *p;
	void *hdr;
	__u64 *kp, k, tid, now, n, qa;

	if (!hot())
		return;
	tid = bpf_get_current_pid_tgid();
	rx = cur_rx(tid);
	if (!rx)
		return;
	qa = rx->queue; /* a local struct: must not be inside the CO-RE read */
	hdr = BPF_CORE_READ((struct nvme_tcp_queue *)qa, pdu);
	if (!hdr || bpf_probe_read_kernel(&h, sizeof(h), hdr) || h.type != 7)
		return;
	ck.queue = qa;
	ck.cid = h.command_id;
	kp = bpf_map_lookup_elem(&bycid, &ck);
	if (!kp)
		return; /* not a sampled READ */
	k = *kp;
	p = prof_of(k);
	if (!p) {
		dcount(NVT_D_C2H_UNMATCHED);
		return;
	}
	now = bpf_ktime_get_ns();
	if (!p->t_c2h_first) {
		p->t_c2h_first = now;
		p->t_rx_start = rx->t_enter;
		p->flags |= NVT_PF_C2H_SEEN;
		n = seq_notify(rx->queue, rx->end_seq, p->t_cmd_sent, now);
		if (n) {
			p->t_rx_notify = n;
		} else {
			p->flags |= NVT_PF_RX_UNMAPPED;
			dcount(NVT_D_SEQ_UNRESOLVED);
		}
	}
	if (p->c2h_copies < 65535)
		p->c2h_copies += 1;
	if (h.flags & (1 << 3))
		p->flags |= NVT_PF_DATA_SUCCESS;
	if (rx->cur_key != k) {
		close_busy(rx, now);
		rx->cur_key = k;
		rx->busy_from = now;
	}
}

/* ------------------------------------------- D9: response parsed */

static __always_inline void on_complete_remote(__u64 rq)
{
	__u64 key = pdu_of_rq(rq), tid, now, ref, n;
	struct nvt_prof *p = prof_of(key);
	struct rx_ctx *rx;

	if (!p || p->t_rsp_parsed)
		return;
	now = bpf_ktime_get_ns();
	p->t_rsp_parsed = now;
	tid = bpf_get_current_pid_tgid();
	rx = cur_rx(tid);
	if (!rx) {
		p->flags |= NVT_PF_RX_NOCTX;
		dcount(NVT_D_RX_NOCTX);
		return;
	}
	p->t_rsp_start = rx->t_enter;
	ref = p->t_h2c_sent ? p->t_h2c_sent : p->t_cmd_sent;
	n = seq_notify(rx->queue, rx->end_seq, ref, now);
	if (n) {
		p->t_rsp_notify = n;
	} else {
		p->flags |= NVT_PF_RSP_UNMAPPED;
		dcount(NVT_D_SEQ_UNRESOLVED);
	}
	if (rx->cur_key == key)
		close_busy(rx, now); /* a READ completed inside the call that carried its data */
}

/* ------------------------------------------- D10: receive notifications */

static __always_inline void on_data_ready(__u64 skp)
{
	struct sock *sk = (struct sock *)skp;
	struct nvt_nring *r;
	__u64 q, now;
	__u32 i;

	if (!hot() || !sk)
		return;
	q = (__u64)BPF_CORE_READ(sk, sk_user_data) & ~7ULL;
	if (!q)
		return;
	r = hot_ring(q);
	if (!r)
		return; /* the ring is created, and made hot, when a command is sampled */
	now = bpf_ktime_get_ns();
	/* sk_data_ready of one socket is serialized by the socket lock */
	i = r->head % NVT_NRING;
	if (i < NVT_NRING) {
		r->seq[i] = BPF_CORE_READ((struct tcp_sock *)sk, rcv_nxt);
		r->t[i] = now;
	}
	r->head += 1;
}

/* ------------------------------------------------- D12: timeouts */

static __always_inline void on_timeout(__u64 rq)
{
	__u64 key = pdu_of_rq(rq), now;
	struct nvme_request *nr = (struct nvme_request *)key;
	struct nvt_prof *p;
	struct nvt_ev_timeout *ev;
	struct nvme_ctrl *ctrl;
	struct nvt_wire_cmd wc = {};
	void *cmd;
	__u64 start;

	if (!armed)
		return;
	ctrl = BPF_CORE_READ(nr, ctrl);
	if (!ctrl || !is_tcp_ctrl(ctrl))
		return;
	dcount(NVT_D_TIMEOUTS);
	now = bpf_ktime_get_ns();
	p = prof_of(key);
	if (p)
		p->flags |= NVT_PF_TIMED_OUT;
	ev = bpf_ringbuf_reserve(&devents, sizeof(*ev), 0);
	if (!ev) {
		dcount(NVT_D_EVENTS_LOST);
		return;
	}
	cmd = BPF_CORE_READ(nr, cmd);
	if (cmd)
		bpf_probe_read_kernel(&wc, sizeof(wc), cmd);
	start = BPF_CORE_READ((struct request *)rq, start_time_ns);
	ev->kind = NVT_EV_TIMEOUT;
	ev->inst = BPF_CORE_READ(ctrl, instance);
	ev->t = now;
	ev->age_ns = start && now > start ? now - start : 0;
	ev->qid = BPF_CORE_READ((struct request *)rq, q, queuedata)
			  ? (__u16)(BPF_CORE_READ((struct request *)rq, mq_hctx, queue_num) + 1)
			  : 0;
	ev->cid = wc.command_id;
	ev->opcode = wc.opcode;
	ev->sampled = p != NULL;
	ev->pad[0] = 0;
	ev->pad[1] = 0;
	bpf_ringbuf_submit(ev, 0);
}

/* --------------------------------------------- completion (P2, P3) */

SEC("raw_tp/nvme_complete_rq")
int BPF_PROG(nvt_d_complete_rq, struct request *rq)
{
	__u64 key = pdu_of_rq((__u64)rq);
	struct nvt_prof *p = prof_of(key);

	if (!p)
		return 0;
	p->t_nvme = bpf_ktime_get_ns();
	p->status = BPF_CORE_READ((struct nvme_request *)key, status);
	p->cpu_complete = (__u16)bpf_get_smp_processor_id();
	return 0;
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(nvt_d_blk_complete, struct request *rq, int error, unsigned int nr_bytes)
{
	__u64 key = pdu_of_rq((__u64)rq);
	struct nvt_prof *p = prof_of(key);
	struct nvt_ev_prof *ev;

	if (!p)
		return 0;
	p->t_blk = bpf_ktime_get_ns();
	if (error && !p->status)
		p->status = 0xffff; /* block-layer error without an NVMe status */
	ev = bpf_ringbuf_reserve(&devents, sizeof(*ev), 0);
	if (ev) {
		ev->kind = NVT_EV_PROF;
		ev->pad = 0;
		__builtin_memcpy(&ev->rec, p, sizeof(ev->rec));
		bpf_ringbuf_submit(ev, 0);
		dcount(NVT_D_EMITTED);
	} else {
		dcount(NVT_D_EVENTS_LOST);
	}
	finish(key, p);
	return 0;
}

/* ===================================================== flavour: kprobe */

static __always_inline void tx_stash(__u64 req)
{
	struct tx_ctx *c = slot(&txctx);

	if (!c)
		return;
	c->tid = bpf_get_current_pid_tgid();
	c->req = req;
	c->t_enter = bpf_ktime_get_ns();
}

static __always_inline bool tx_take(__u64 *req)
{
	struct tx_ctx *c = slot(&txctx);

	if (!c || c->tid != bpf_get_current_pid_tgid())
		return false;
	*req = c->req;
	c->tid = 0;
	return true;
}

SEC("kprobe/nvme_tcp_io_work")
int BPF_KPROBE(kp_io_work, void *w)
{
	on_io_work_enter((__u64)w);
	return 0;
}

SEC("kretprobe/nvme_tcp_io_work")
int BPF_KRETPROBE(kr_io_work)
{
	on_io_work_exit();
	return 0;
}

SEC("kprobe/nvme_tcp_try_send_cmd_pdu")
int BPF_KPROBE(kp_cmd_pdu, void *req)
{
	if (hot()) {
		on_cmd_pdu_enter((__u64)req);
		tx_stash((__u64)req);
	}
	return 0;
}

SEC("kretprobe/nvme_tcp_try_send_cmd_pdu")
int BPF_KRETPROBE(kr_cmd_pdu, int ret)
{
	__u64 req;

	if (tx_take(&req))
		on_cmd_pdu_exit(req, ret);
	return 0;
}

SEC("kprobe/nvme_tcp_try_send_data")
int BPF_KPROBE(kp_send_data, void *req)
{
	on_data_enter((__u64)req);
	return 0;
}

SEC("kretprobe/nvme_tcp_try_send_data")
int BPF_KRETPROBE(kr_send_data, int ret)
{
	struct tx_ctx *c = slot(&txctx);

	/* on_data_exit() consumes the context itself */
	if (c && c->tid == bpf_get_current_pid_tgid())
		on_data_exit(c->req, ret, true);
	return 0;
}

SEC("kprobe/nvme_tcp_try_send_ddgst")
int BPF_KPROBE(kp_ddgst, void *req)
{
	if (hot())
		tx_stash((__u64)req);
	return 0;
}

SEC("kretprobe/nvme_tcp_try_send_ddgst")
int BPF_KRETPROBE(kr_ddgst, int ret)
{
	__u64 req;

	if (tx_take(&req))
		on_data_exit(req, ret, false);
	return 0;
}

SEC("kprobe/nvme_tcp_try_send_data_pdu")
int BPF_KPROBE(kp_data_pdu, void *req)
{
	if (hot())
		on_data_pdu_enter((__u64)req);
	return 0;
}

SEC("kprobe/nvme_tcp_setup_h2c_data_pdu")
int BPF_KPROBE(kp_h2c_setup, void *req)
{
	if (hot())
		on_h2c_setup((__u64)req);
	return 0;
}

SEC("kprobe/nvme_tcp_recv_skb")
int BPF_KPROBE(kp_recv_skb, void *desc, void *skb)
{
	on_recv_enter((__u64)skb);
	return 0;
}

SEC("kretprobe/nvme_tcp_recv_skb")
int BPF_KRETPROBE(kr_recv_skb)
{
	on_recv_exit();
	return 0;
}

SEC("kprobe/skb_copy_datagram_iter")
int BPF_KPROBE(kp_copy)
{
	on_copy();
	return 0;
}

SEC("kprobe/skb_copy_and_hash_datagram_iter")
int BPF_KPROBE(kp_copy_hash)
{
	on_copy();
	return 0;
}

SEC("kprobe/blk_mq_complete_request_remote")
int BPF_KPROBE(kp_complete_remote, void *rq)
{
	if (hot())
		on_complete_remote((__u64)rq);
	return 0;
}

SEC("kprobe/nvme_tcp_data_ready")
int BPF_KPROBE(kp_data_ready, void *sk)
{
	on_data_ready((__u64)sk);
	return 0;
}

SEC("kprobe/nvme_tcp_timeout")
int BPF_KPROBE(kp_timeout, void *rq)
{
	on_timeout((__u64)rq);
	return 0;
}

/* ===================================================== flavour: fentry */

static __always_inline __u64 arg(void *ctx, __u32 n)
{
	__u64 v = 0;

	bpf_get_func_arg(ctx, n, &v);
	return v;
}

static __always_inline int retval(void *ctx)
{
	__u64 v = 0;

	bpf_get_func_ret(ctx, &v);
	return (int)v;
}

SEC("fentry/nvme_tcp_io_work")
int fe_io_work(void *ctx)
{
	on_io_work_enter(arg(ctx, 0));
	return 0;
}

SEC("fexit/nvme_tcp_io_work")
int fx_io_work(void *ctx)
{
	on_io_work_exit();
	return 0;
}

SEC("fentry/nvme_tcp_try_send_cmd_pdu")
int fe_cmd_pdu(void *ctx)
{
	if (hot())
		on_cmd_pdu_enter(arg(ctx, 0));
	return 0;
}

SEC("fexit/nvme_tcp_try_send_cmd_pdu")
int fx_cmd_pdu(void *ctx)
{
	if (hot())
		on_cmd_pdu_exit(arg(ctx, 0), retval(ctx));
	return 0;
}

SEC("fentry/nvme_tcp_try_send_data")
int fe_send_data(void *ctx)
{
	on_data_enter(arg(ctx, 0));
	return 0;
}

SEC("fexit/nvme_tcp_try_send_data")
int fx_send_data(void *ctx)
{
	struct tx_ctx *c = slot(&txctx);
	__u64 req = arg(ctx, 0);

	if (c && c->tid == bpf_get_current_pid_tgid() && c->req == req)
		on_data_exit(req, retval(ctx), true);
	return 0;
}

SEC("fexit/nvme_tcp_try_send_ddgst")
int fx_ddgst(void *ctx)
{
	if (hot())
		on_data_exit(arg(ctx, 0), retval(ctx), false);
	return 0;
}

SEC("fentry/nvme_tcp_try_send_data_pdu")
int fe_data_pdu(void *ctx)
{
	if (hot())
		on_data_pdu_enter(arg(ctx, 0));
	return 0;
}

SEC("fentry/nvme_tcp_setup_h2c_data_pdu")
int fe_h2c_setup(void *ctx)
{
	if (hot())
		on_h2c_setup(arg(ctx, 0));
	return 0;
}

SEC("fentry/nvme_tcp_recv_skb")
int fe_recv_skb(void *ctx)
{
	on_recv_enter(arg(ctx, 1));
	return 0;
}

SEC("fexit/nvme_tcp_recv_skb")
int fx_recv_skb(void *ctx)
{
	on_recv_exit();
	return 0;
}

SEC("fentry/skb_copy_datagram_iter")
int fe_copy(void *ctx)
{
	on_copy();
	return 0;
}

SEC("fentry/skb_copy_and_hash_datagram_iter")
int fe_copy_hash(void *ctx)
{
	on_copy();
	return 0;
}

SEC("fentry/blk_mq_complete_request_remote")
int fe_complete_remote(void *ctx)
{
	if (hot())
		on_complete_remote(arg(ctx, 0));
	return 0;
}

SEC("fentry/nvme_tcp_data_ready")
int fe_data_ready(void *ctx)
{
	on_data_ready(arg(ctx, 0));
	return 0;
}

SEC("fentry/nvme_tcp_timeout")
int fe_timeout(void *ctx)
{
	on_timeout(arg(ctx, 0));
	return 0;
}
