// SPDX-License-Identifier: (MIT OR GPL-2.0)
/*
 * nvmetea Level 1: NVMe/TCP command lifecycle from nvme-core and block-layer
 * raw tracepoints (probe ids P1-P4, L3 in docs/kernel-compatibility.md).
 *
 *   raw_tp/nvme_setup_cmd      dispatch: identity, counters, in-flight slot
 *   raw_tp/nvme_complete_rq    NVMe completion: status, command latency
 *   raw_tp/block_rq_complete   final completion: request latency, stages, slow events
 *   raw_tp/block_rq_requeue    requeue marker
 *   kprobe+kretprobe nvme_change_ctrl_state   controller state transitions
 *
 * Raw tracepoint arguments are plain scalars here (not BTF-typed), so the
 * driver PDU address rq + sizeof(struct request) can be computed (finding
 * F14); every dereference goes through BPF_CORE_READ.
 *
 * Nothing is counted until userspace sets `armed` after attaching all programs.
 * Userspace never resets maps; it reads cumulative values and differences them.
 *
 * In-flight commands live in a fixed slot array, not a hash: each hardware
 * queue's tag space (struct blk_mq_tags, shared by the queue's hctx of every
 * namespace) gets a region of nr_tags slots on first sight, and a command sits
 * at region base + its blk-mq tag. Tags are unique per hardware queue while a
 * request is in flight, and a tag is reused only after block_rq_complete has
 * run, so the I/O path needs no hashing, locks, allocation or freeing (a
 * shared hash cost ~1 µs per command on a 128-CPU host: free-list stealing
 * and cross-die cache lines). Requeued and retried requests release their tag;
 * their entry waits in a small hash until the next dispatch.
 */
#include "kernel_types.h"

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "nvmetea.h"
#include "hist.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Set by userspace. */
volatile bool armed;
volatile __u64 slow_ns;            /* 0 = no slow-command events */
volatile __u64 epoch;              /* high-watermark epoch, advanced by userspace */
volatile __u32 slow_per_cpu_per_s; /* slow-event budget per CPU per second */
/* ctrl->ops of NVMe/TCP controllers once seen (the string compare runs only
 * for ops pointers not seen before), and the last non-TCP ops seen. */
volatile __u64 tcp_ops;
volatile __u64 other_ops;
/* Slot allocation: regions are carved from [0, nslots) by an atomic cursor. */
volatile __u32 nslots;
volatile __u32 next_slot;
/* Queue indexes: [0, max_queues), handed out by an atomic cursor. */
volatile __u32 max_queues;
volatile __u32 next_queue;
/* Advanced by userspace when a controller or namespace appears or goes away:
 * per-hctx facts (qid, device) cached under an older epoch are recomputed
 * (a recreated queue may reuse the old one's addresses). */
volatile __u64 cache_epoch;
/* Entries in `requeued` (so dispatch checks it only when non-zero). */
volatile __s64 requeued_n;

/* Layout anchors: ring-buffer record types are otherwise not referenced by any
 * map or global, so the generated Rust skeleton would not contain them. */
struct nvt_ev_slow nvt_layout_ev_slow;
struct nvt_ev_state nvt_layout_ev_state;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8192); /* resized by userspace from topology */
	__type(key, __u32);
	__type(value, struct nvt_slot);
} slots SEC(".maps");

#define NO_REGION 0xffffffffu

/* NVMe queue (ctrl instance << 32 | qid) -> its slot region and queue index.
 * One entry per tag set: the hctx of every namespace on a hardware queue (and
 * the connect queue's) share the queue's tags. Keyed by queue, not by tag-set
 * address, so a deleted and recreated controller (instances are reused) gets
 * its old region back instead of leaking one, and a recycled address cannot
 * inherit another controller's queue index. */
struct tag_reg {
	__u32 base;
	__u32 depth;
	__u32 qidx;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, __u64);
	__type(value, struct tag_reg);
} tag_regs SEC(".maps");

/* hctx -> region and the queue's facts; read-mostly (written on first sight) */
struct hctx_reg {
	__u64 q;
	__u64 epoch;
	__u32 base;
	__u32 depth;
	__u32 dev;
	__u32 qidx;
	__u16 qid;
	__u16 inst;
	__u16 pad[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct hctx_reg);
} hctx_regs SEC(".maps");

/* entries of requeued/retried requests between their requeue and next dispatch */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);        /* driver PDU address */
	__type(value, struct nvt_inflight);
} requeued SEC(".maps");

/* Per-queue counters and histograms: arrays indexed by the queue index
 * assigned at registration (array lookups compile to pointer arithmetic). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256); /* resized by userspace */
	__type(key, __u32);
	__type(value, struct nvt_qstats);
} qstats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256 * NVT_HPQ);
	__type(key, __u32);
	__type(value, struct nvt_hist);
} qhist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct nvt_qinfo);
} qinfo SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct nvt_pkey);
	__type(value, struct nvt_hist);
} phist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nvt_counters);
} counters SEC(".maps");

/* All-zero templates used to create entries (values exceed the BPF stack). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nvt_hist);
} zero_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Slow-event budget per CPU: [0] window start (s), [1] events in window. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} slow_budget SEC(".maps");

/* nvme_change_ctrl_state entry -> return (per thread). */
struct state_ctx {
	__u64 ctrl;
	__u32 old_state;
	__u32 new_state;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, __u64); /* pid_tgid */
	__type(value, struct state_ctx);
} state_ctx SEC(".maps");

/* Bulk copies of the leading bytes of struct request and struct nvme_request:
 * one helper call each instead of one per field (fields are then taken at
 * their CO-RE-relocated offsets). */
#define RQ_BULK 256
#define NR_BULK 64

#define RQ_SMALL 64 /* q, mq_ctx, mq_hctx, flags, tag: enough on the completion paths */

struct scratch {
	__u8 rq[RQ_BULK];
	__u8 nr[NR_BULK];
	__u8 rqs[RQ_SMALL];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch SEC(".maps");

/* A field of a bulk copy at its relocated offset; a direct read if the
 * running kernel places it beyond the copied bytes. */
#define BULK_FIELD(buf, size, type, ptr, field)                                                        \
	({                                                                                             \
		__u32 __off = bpf_core_field_offset(ptr->field);                                       \
		__u64 __v;                                                                             \
		if (__off + bpf_core_field_size(ptr->field) <= (size) && bpf_core_field_size(ptr->field) == 8) \
			__v = *(__u64 *)((buf) + __off);                                               \
		else if (__off + bpf_core_field_size(ptr->field) <= (size) && bpf_core_field_size(ptr->field) == 4) \
			__v = *(__u32 *)((buf) + __off);                                               \
		else if (__off + bpf_core_field_size(ptr->field) <= (size) && bpf_core_field_size(ptr->field) == 2) \
			__v = *(__u16 *)((buf) + __off);                                               \
		else if (__off + bpf_core_field_size(ptr->field) <= (size) && bpf_core_field_size(ptr->field) == 1) \
			__v = *(__u8 *)((buf) + __off);                                                \
		else                                                                                   \
			__v = (__u64)BPF_CORE_READ(ptr, field);                                        \
		(type)__v;                                                                             \
	})

static __always_inline struct nvt_counters *cnt(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&counters, &z);
}

static __always_inline void count(__u32 i)
{
	struct nvt_counters *c = cnt();
	if (c && i < NVT_C_NR)
		c->c[i] += 1;
}

static __always_inline struct nvme_request *nreq_of(struct request *rq)
{
	return (struct nvme_request *)((void *)rq + bpf_core_type_size(struct request));
}

/* NVMe/TCP controllers have ctrl->ops->name == "tcp". The ops structure is
 * static in the nvme_tcp module, so once one TCP controller's ops pointer is
 * known, the test is a pointer compare; the name is read only for ops
 * pointers not seen before. */
static __always_inline bool is_tcp(struct nvme_ctrl *ctrl)
{
	const struct nvme_ctrl_ops *ops = BPF_CORE_READ(ctrl, ops);
	const char *name;
	char b[4] = {};
	bool tcp;

	if (!ops)
		return false;
	if ((__u64)ops == tcp_ops)
		return true;
	if ((__u64)ops == other_ops)
		return false;
	name = BPF_CORE_READ(ops, name);
	if (bpf_probe_read_kernel_str(b, sizeof(b), name) < 0)
		return false;
	tcp = b[0] == 't' && b[1] == 'c' && b[2] == 'p' && b[3] == 0;
	if (tcp)
		tcp_ops = (__u64)ops;
	else
		other_ops = (__u64)ops;
	return tcp;
}

static __always_inline __u8 op_of(__u16 qid, __u8 opcode)
{
	if (qid == 0)
		return NVT_OP_ADMIN;
	switch (opcode) {
	case 0x02: return NVT_OP_READ;
	case 0x01: return NVT_OP_WRITE;
	case 0x00: return NVT_OP_FLUSH;
	default: return NVT_OP_OTHER;
	}
}

static __always_inline struct nvt_qstats *qstats_at(__u32 qidx)
{
	return bpf_map_lookup_elem(&qstats, &qidx);
}

static __always_inline void hist_add(void *map, void *key, __u64 v)
{
	struct nvt_hist *h = bpf_map_lookup_elem(map, key);
	__u32 z = 0, b;

	if (!h) {
		struct nvt_hist *zero = bpf_map_lookup_elem(&zero_hist, &z);
		if (!zero)
			return;
		bpf_map_update_elem(map, key, zero, BPF_NOEXIST);
		h = bpf_map_lookup_elem(map, key);
		if (!h) {
			count(NVT_C_MAP_FULL_HIST);
			return;
		}
	}
	b = nvt_bucket(v);
	if (b < NVT_NBUCKETS)
		__sync_fetch_and_add(&h->b[b], 1);
}

static __always_inline void qhist_add(__u32 qidx, __u8 op, __u8 metric, __u64 v)
{
	__u32 i = qidx * NVT_HPQ + (__u32)op * NVT_M_NR + metric, b;
	struct nvt_hist *h;

	if (op >= NVT_OP_NR || metric >= NVT_M_NR || qidx == NO_REGION)
		return;
	h = bpf_map_lookup_elem(&qhist, &i);
	if (!h) {
		/* queue index beyond the histogram array's memory budget */
		count(NVT_C_MAP_FULL_HIST);
		return;
	}
	b = nvt_bucket(v);
	if (b < NVT_NBUCKETS)
		__sync_fetch_and_add(&h->b[b], 1);
}

/* NVMe qid (0 = admin queue) and path device of a request's hardware queue.
 * The qid comes from the tag set, not from the request queue: the fabrics
 * connect queue has no queuedata but sends its Connect commands on the I/O
 * queues (hardware queue k is NVMe queue k + 1). Only namespace queues have a
 * path device. */
static __always_inline __u16 queue_facts(__u64 hctx, __u64 q, struct nvme_ctrl *ctrl, __u32 *dev)
{
	struct request_queue *rqq = (struct request_queue *)q;
	bool admin;

	*dev = 0;
	if (bpf_core_field_exists(rqq->tag_set) && bpf_core_field_exists(ctrl->admin_tagset))
		admin = BPF_CORE_READ(rqq, tag_set) == BPF_CORE_READ(ctrl, admin_tagset);
	else
		admin = !BPF_CORE_READ(rqq, queuedata);
	if (BPF_CORE_READ(rqq, queuedata) && bpf_core_field_exists(rqq->disk))
		*dev = BPF_CORE_READ(rqq, disk, part0, bd_dev);
	return admin ? 0 : (__u16)(BPF_CORE_READ((struct blk_mq_hw_ctx *)hctx, queue_num) + 1);
}

/* The region of a request's hardware queue (registered on first sight). */
static __always_inline struct hctx_reg *region_of(__u64 hctx, __u64 q, struct nvme_ctrl *ctrl, __u16 inst,
						  bool create)
{
	struct hctx_reg *v = bpf_map_lookup_elem(&hctx_regs, &hctx);
	struct hctx_reg nv = {};
	struct tag_reg *t, nt = {};
	__u64 tags, qkey;

	if (v && v->q == q && (!create || (v->epoch == cache_epoch && v->inst == inst)))
		return v;
	if (!create)
		return NULL;
	nv.q = q;
	nv.epoch = cache_epoch;
	nv.inst = inst;
	nv.qid = queue_facts(hctx, q, ctrl, &nv.dev);
	nv.base = NO_REGION;
	nv.qidx = NO_REGION;
	tags = (__u64)BPF_CORE_READ((struct blk_mq_hw_ctx *)hctx, tags);
	nv.depth = tags ? BPF_CORE_READ((struct blk_mq_tags *)tags, nr_tags) : 0;
	qkey = ((__u64)inst << 32) | nv.qid;
	if (nv.depth && nv.depth <= 65536) {
		t = bpf_map_lookup_elem(&tag_regs, &qkey);
		if (t && t->depth == nv.depth) {
			nv.base = t->base;
			nv.qidx = t->qidx;
		} else {
			/* first sight of this queue, or its depth changed (a new region;
			 * the queue index and its cumulative statistics are kept) */
			__u32 base = __sync_fetch_and_add(&next_slot, nv.depth);

			if (t) {
				nt.qidx = t->qidx;
			} else {
				__u32 qidx = __sync_fetch_and_add(&next_queue, 1);

				nt.qidx = NO_REGION;
				if (qidx < max_queues) {
					struct nvt_qinfo qi = { .inst = inst, .qid = nv.qid, .valid = 1 };

					bpf_map_update_elem(&qinfo, &qidx, &qi, BPF_ANY);
					nt.qidx = qidx;
				} else {
					count(NVT_C_MAP_FULL_QSTATS);
				}
			}
			if (base + nv.depth <= nslots) {
				nt.base = base;
			} else {
				nt.base = NO_REGION;
				count(NVT_C_MAP_FULL_INFLIGHT);
			}
			nt.depth = nv.depth;
			bpf_map_update_elem(&tag_regs, &qkey, &nt, BPF_ANY);
			nv.base = nt.base;
			nv.qidx = nt.qidx;
		}
	}
	bpf_map_update_elem(&hctx_regs, &hctx, &nv, BPF_ANY);
	return bpf_map_lookup_elem(&hctx_regs, &hctx);
}

static __always_inline struct nvt_slot *slot_at(struct hctx_reg *r, __s32 tag)
{
	__u32 idx;

	if (!r || r->base == NO_REGION || tag < 0 || (__u32)tag >= r->depth)
		return NULL;
	idx = r->base + (__u32)tag;
	return bpf_map_lookup_elem(&slots, &idx);
}

/* The slot of an in-flight request on a completion path (no registration),
 * or NULL if the request is not tracked. */
static __always_inline struct nvt_slot *tracked(struct request *rq, __u64 key, struct scratch *sc, __u32 *qidx)
{
	struct hctx_reg *r;
	struct nvt_slot *sl;
	__u64 q, hctx;

	if (bpf_probe_read_kernel(sc->rqs, sizeof(sc->rqs), rq))
		return NULL;
	q = BULK_FIELD(sc->rqs, RQ_SMALL, __u64, rq, q);
	hctx = BULK_FIELD(sc->rqs, RQ_SMALL, __u64, rq, mq_hctx);
	r = region_of(hctx, q, NULL, 0, false);
	sl = slot_at(r, BULK_FIELD(sc->rqs, RQ_SMALL, __s32, rq, tag));
	if (!sl || sl->key != key)
		return NULL;
	*qidx = r ? r->qidx : NO_REGION;
	return sl;
}

/* Free a slot: the key goes last, with a full barrier (atomic exchange). */
static __always_inline void slot_free(struct nvt_slot *sl)
{
	__sync_lock_test_and_set(&sl->key, 0);
}

/* ---------------------------------------------------------------- dispatch */

SEC("raw_tp/nvme_setup_cmd")
int BPF_PROG(nvt_setup_cmd, struct request *rq, void *cmd)
{
	struct nvme_request *nr;
	struct nvme_ctrl *ctrl;
	struct nvt_wire_cmd wc;
	struct nvt_inflight *e, ne = {};
	struct nvt_qstats *qs;
	struct nvt_counters *c;
	struct scratch *sc;
	struct hctx_reg *reg;
	struct nvt_slot *sl;
	__u64 key, now, q, hctx;
	__u32 dev = 0, z = 0;
	__u16 qid, inst;
	__u8 retries;

	if (!armed)
		return 0;
	sc = bpf_map_lookup_elem(&scratch, &z);
	if (!sc)
		return 0;
	nr = nreq_of(rq);
	if (bpf_probe_read_kernel(sc->nr, sizeof(sc->nr), nr))
		return 0;
	ctrl = BULK_FIELD(sc->nr, NR_BULK, struct nvme_ctrl *, nr, ctrl);
	if (!ctrl || !is_tcp(ctrl))
		return 0;
	if (bpf_probe_read_kernel(&wc, sizeof(wc), cmd) || bpf_probe_read_kernel(sc->rq, sizeof(sc->rq), rq))
		return 0;
	now = bpf_ktime_get_ns();
	key = (__u64)nr;
	q = BULK_FIELD(sc->rq, RQ_BULK, __u64, rq, q);
	hctx = BULK_FIELD(sc->rq, RQ_BULK, __u64, rq, mq_hctx);
	inst = (__u16)BPF_CORE_READ(ctrl, instance);
	reg = q && hctx ? region_of(hctx, q, ctrl, inst, true) : NULL;
	qid = reg ? reg->qid : 0;
	dev = reg ? reg->dev : 0;
	retries = BULK_FIELD(sc->nr, NR_BULK, __u8, nr, retries);
	sl = slot_at(reg, BULK_FIELD(sc->rq, RQ_BULK, __s32, rq, tag));

	e = NULL;
	if (sl && sl->key == key) {
		e = &sl->e;
	} else if (sl && requeued_n > 0) {
		/* re-dispatch of a requeued/retried request: its entry waited aside */
		struct nvt_inflight *r = bpf_map_lookup_elem(&requeued, &key);

		if (r) {
			if (sl->key) {
				count(NVT_C_STALE_REPLACED);
				qs = qstats_at(reg->qidx);
				if (qs && !(sl->e.flags & NVT_F_AER))
					__sync_fetch_and_add(&qs->inflight, -1);
			}
			__builtin_memcpy(&sl->e, r, sizeof(sl->e));
			__sync_lock_test_and_set(&sl->key, key);
			bpf_map_delete_elem(&requeued, &key);
			__sync_fetch_and_add(&requeued_n, -1);
			e = &sl->e;
		}
	}
	if (e) {
		bool retry = retries > e->retries;

		if (retry || (e->flags & NVT_F_REQUEUED)) {
			/* the same request dispatched again: keep its start */
			e->retries = retries;
			if (retry)
				e->flags |= NVT_F_RETRIED;
			else
				e->flags |= NVT_F_WAS_REQUEUED;
			e->flags &= ~(NVT_F_REQUEUED | NVT_F_NVME_ERR);
			e->t_setup = now;
			e->cid = wc.command_id;
			e->t_nvme = 0;
			e->status = 0;
			qs = qstats_at(reg->qidx);
			if (qs) {
				__u8 op = e->op < NVT_OP_NR ? e->op : NVT_OP_OTHER;
				__sync_fetch_and_add(&qs->dispatched[op], 1);
				if (retry)
					__sync_fetch_and_add(&qs->retries, 1);
			}
			return 0;
		}
		/* a previous completion of this request was missed: count and replace */
		count(NVT_C_STALE_REPLACED);
		qs = qstats_at(reg->qidx);
		if (qs && !(e->flags & NVT_F_AER))
			__sync_fetch_and_add(&qs->inflight, -1);
		slot_free(sl);
	} else if (sl && sl->key) {
		/* another request's entry on this tag: its completion was missed */
		count(NVT_C_STALE_REPLACED);
		qs = qstats_at(reg->qidx);
		if (qs && !(sl->e.flags & NVT_F_AER))
			__sync_fetch_and_add(&qs->inflight, -1);
		slot_free(sl);
	}

	ne.t_setup = now;
	ne.t_first_setup = now;
	ne.t_start = BULK_FIELD(sc->rq, RQ_BULK, __u64, rq, start_time_ns);
	ne.inst = inst;
	ne.qid = qid;
	ne.cid = wc.command_id;
	ne.nsid = wc.nsid;
	ne.opcode = wc.opcode;
	ne.op = op_of(qid, wc.opcode);
	ne.bytes = BULK_FIELD(sc->rq, RQ_BULK, __u32, rq, __data_len);
	ne.dev = qid ? dev : 0;
	ne.cpu = (__u16)bpf_get_smp_processor_id();
	ne.retries = retries;
	if (!ne.t_start)
		ne.flags |= NVT_F_NO_START;
	if (qid == 0 && wc.opcode == 0x0c)
		ne.flags |= NVT_F_AER; /* outstanding by design: excluded from latency */

	c = cnt();
	if (c) {
		c->c[NVT_C_SETUP_TCP] += 1;
		c->c[NVT_C_SEQ] += 1;
		ne.seq = ((__u64)ne.cpu << 48) | (c->c[NVT_C_SEQ] & 0xffffffffffffULL);
		if (ne.flags & NVT_F_AER)
			c->c[NVT_C_AER] += 1;
	}

	qs = reg ? qstats_at(reg->qidx) : NULL;
	if (qs) {
		__u8 op = ne.op < NVT_OP_NR ? ne.op : NVT_OP_OTHER;
		__s64 inf;

		__sync_fetch_and_add(&qs->dispatched[op], 1);
		__sync_fetch_and_add(&qs->bytes[op], ne.bytes);
		if (!sl)
			return 0; /* no region (counted at registration): untracked */
		__builtin_memcpy(&sl->e, &ne, sizeof(sl->e));
		__sync_lock_test_and_set(&sl->key, key);
		if (ne.flags & NVT_F_AER)
			return 0; /* outstanding by design: not in inflight */
		inf = __sync_fetch_and_add(&qs->inflight, 1) + 1;
		/* high watermark since the current epoch (racy max: may miss a
		 * concurrent maximum by one update, never invents one) */
		if (qs->inflight_epoch != epoch) {
			qs->inflight_epoch = epoch;
			qs->inflight_max = inf > 0 ? inf : 0;
		} else if (inf > 0 && (__u64)inf > qs->inflight_max) {
			qs->inflight_max = inf;
		}
	} else if (sl) {
		__builtin_memcpy(&sl->e, &ne, sizeof(sl->e));
		__sync_lock_test_and_set(&sl->key, key);
	}
	return 0;
}

SEC("raw_tp/block_rq_requeue")
int BPF_PROG(nvt_requeue, struct request *rq)
{
	__u64 key = (__u64)nreq_of(rq);
	struct nvt_qstats *qs;
	struct nvt_slot *sl;
	struct scratch *sc;
	__u32 z = 0, qidx = NO_REGION;

	sc = bpf_map_lookup_elem(&scratch, &z);
	if (!sc)
		return 0;
	sl = tracked(rq, key, sc, &qidx);
	if (!sl)
		return 0;
	sl->e.flags |= NVT_F_REQUEUED;
	qs = qstats_at(qidx);
	if (qs)
		__sync_fetch_and_add(&qs->requeues, 1);
	/* the request releases its driver tag; the entry waits for the next dispatch */
	if (bpf_map_update_elem(&requeued, &key, &sl->e, BPF_ANY) == 0)
		__sync_fetch_and_add(&requeued_n, 1);
	else if (qs && !(sl->e.flags & NVT_F_AER))
		__sync_fetch_and_add(&qs->inflight, -1);
	slot_free(sl);
	return 0;
}

/* -------------------------------------------------------------- completion */

SEC("raw_tp/nvme_complete_rq")
int BPF_PROG(nvt_complete_rq, struct request *rq)
{
	struct nvme_request *nr = nreq_of(rq);
	__u64 key = (__u64)nr, now;
	struct nvt_inflight *e;
	struct nvt_qstats *qs;
	struct nvt_wire_cmd wc;
	struct scratch *sc;
	struct nvt_slot *sl;
	void *cmd;
	__u16 status;
	__u32 z = 0, qidx = NO_REGION;
	__u8 op;

	sc = bpf_map_lookup_elem(&scratch, &z);
	if (!sc)
		return 0;
	sl = tracked(rq, key, sc, &qidx);
	if (!sl) {
		if (armed) {
			struct nvme_ctrl *ctrl = BPF_CORE_READ(nr, ctrl);
			if (ctrl && is_tcp(ctrl))
				count(NVT_C_UNTRACKED_COMPLETION);
		}
		return 0;
	}
	e = &sl->e;
	now = bpf_ktime_get_ns();
	if (bpf_probe_read_kernel(sc->nr, sizeof(sc->nr), nr))
		return 0;
	cmd = BULK_FIELD(sc->nr, NR_BULK, void *, nr, cmd);
	if (!cmd || bpf_probe_read_kernel(&wc, sizeof(wc), cmd) || wc.command_id != e->cid) {
		count(NVT_C_CID_MISMATCH);
		qs = qstats_at(qidx);
		if (qs && !(e->flags & NVT_F_AER))
			__sync_fetch_and_add(&qs->inflight, -1);
		slot_free(sl);
		return 0;
	}
	status = BULK_FIELD(sc->nr, NR_BULK, __u16, nr, status);
	e->status = status;
	e->t_nvme = now;
	op = e->op < NVT_OP_NR ? e->op : NVT_OP_OTHER;
	qs = qstats_at(qidx);
	if (status) {
		e->flags |= NVT_F_NVME_ERR;
		if (qs) {
			__sync_fetch_and_add(&qs->nvme_errors[op], 1);
			__sync_fetch_and_add(&qs->status_type[(status >> 8) & 7], 1);
		}
	}
	if (!(e->flags & NVT_F_AER) && now >= e->t_setup) {
		__u64 lat = now - e->t_setup;

		qhist_add(qidx, op, NVT_M_CMD, lat);
		if (qs) {
			__sync_fetch_and_add(&qs->cmd_lat_sum_ns[op], lat);
			__sync_fetch_and_add(&qs->cmd_lat_cnt[op], 1);
		}
	}
	return 0;
}

static __always_inline void emit_slow(struct nvt_inflight *e, __u64 now, __s32 err)
{
	__u32 k0 = 0, k1 = 1;
	__u64 *win = bpf_map_lookup_elem(&slow_budget, &k0);
	__u64 *n = bpf_map_lookup_elem(&slow_budget, &k1);
	__u64 sec = now / 1000000000ULL;
	struct nvt_ev_slow *ev;

	if (!win || !n)
		return;
	if (*win != sec) {
		*win = sec;
		*n = 0;
	}
	if (*n >= slow_per_cpu_per_s) {
		count(NVT_C_SLOW_SUPPRESSED);
		return;
	}
	*n += 1;
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		count(NVT_C_EVENTS_LOST);
		return;
	}
	ev->kind = NVT_EV_SLOW;
	ev->cpu = bpf_get_smp_processor_id();
	ev->t_blk = now;
	ev->blk_error = err;
	ev->pad = 0;
	__builtin_memcpy(&ev->rec, e, sizeof(ev->rec));
	bpf_ringbuf_submit(ev, 0);
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(nvt_blk_complete, struct request *rq, int error, unsigned int nr_bytes)
{
	__u64 key = (__u64)nreq_of(rq), now;
	struct nvt_inflight *e;
	struct nvt_qstats *qs;
	struct nvt_slot *sl;
	struct scratch *sc;
	__u32 z = 0, qidx = NO_REGION;
	__u8 op;

	sc = bpf_map_lookup_elem(&scratch, &z);
	if (!sc)
		return 0;
	sl = tracked(rq, key, sc, &qidx);
	if (!sl)
		return 0;
	e = &sl->e;
	now = bpf_ktime_get_ns();
	op = e->op < NVT_OP_NR ? e->op : NVT_OP_OTHER;
	qs = qstats_at(qidx);
	if (qs) {
		__sync_fetch_and_add(&qs->completed[op], 1);
		if (!(e->flags & NVT_F_AER))
			__sync_fetch_and_add(&qs->inflight, -1);
	}
	if (e->flags & NVT_F_AER)
		goto out;
	if (error) {
		/* failed at the block layer: counted, kept out of latency histograms */
		if (qs)
			__sync_fetch_and_add(&qs->error_completed, 1);
		goto out;
	}
	if ((e->flags & NVT_F_NVME_ERR) && e->status) {
		/* NVMe error but success at the block layer: the bios were failed
		 * over to another path. Its duration is not what the caller saw. */
		if (qs)
			__sync_fetch_and_add(&qs->failovers, 1);
		goto out;
	}
	if (e->flags & (NVT_F_RETRIED | NVT_F_WAS_REQUEUED)) {
		/* spans several dispatches: its own class, not mixed into latency */
		if (qs)
			__sync_fetch_and_add(&qs->retried_completed, 1);
		goto out;
	}
	if (e->t_start && now >= e->t_start) {
		__u64 lat = now - e->t_start;

		qhist_add(qidx, op, NVT_M_REQ, lat);
		if (qs) {
			__sync_fetch_and_add(&qs->req_lat_sum_ns[op], lat);
			__sync_fetch_and_add(&qs->req_lat_cnt[op], 1);
		}
		if (e->dev) {
			struct nvt_pkey pk = { .dev = e->dev, .op = op };
			hist_add(&phist, &pk, lat);
		}
		if (e->t_first_setup >= e->t_start)
			qhist_add(qidx, op, NVT_M_STAGE_A, e->t_first_setup - e->t_start);
		else
			count(NVT_C_ORDER_VIOLATION);
		if (slow_ns && lat >= slow_ns)
			emit_slow(e, now, error);
	} else if (!e->t_start && e->qid) {
		/* admin requests never carry a start time; I/O requests do when
		 * iostats/stats are enabled on the path queue */
		count(NVT_C_START_MISSING);
	}
	if (e->t_nvme && now >= e->t_nvme)
		qhist_add(qidx, op, NVT_M_STAGE_E2, now - e->t_nvme);
out:
	slot_free(sl);
	return 0;
}

/* ------------------------------------------------- controller state (L3) */

SEC("kprobe/nvme_change_ctrl_state")
int BPF_KPROBE(nvt_state_enter, struct nvme_ctrl *ctrl, int new_state)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct state_ctx s = {};

	s.ctrl = (__u64)ctrl;
	s.old_state = BPF_CORE_READ(ctrl, state);
	s.new_state = new_state;
	bpf_map_update_elem(&state_ctx, &id, &s, BPF_ANY);
	return 0;
}

SEC("kretprobe/nvme_change_ctrl_state")
int BPF_KRETPROBE(nvt_state_exit, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct state_ctx *s = bpf_map_lookup_elem(&state_ctx, &id);
	struct nvt_ev_state *ev;
	struct nvme_ctrl *ctrl;

	if (!s)
		return 0;
	ctrl = (struct nvme_ctrl *)s->ctrl;
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (ev) {
		ev->kind = NVT_EV_STATE;
		ev->inst = BPF_CORE_READ(ctrl, instance);
		ev->t = bpf_ktime_get_ns();
		ev->old_state = s->old_state;
		ev->new_state = s->new_state;
		ev->accepted = (ret & 0xff) != 0; /* bool return */
		ev->pad = 0;
		bpf_ringbuf_submit(ev, 0);
	} else {
		count(NVT_C_EVENTS_LOST);
	}
	bpf_map_delete_elem(&state_ctx, &id);
	return 0;
}
