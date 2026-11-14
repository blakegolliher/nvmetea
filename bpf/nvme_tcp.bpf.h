/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * NVMe/TCP queue identification shared by the Level 2 and Level 3 objects.
 * Include after kernel_types.h and the libbpf headers.
 */
#ifndef NVMETEA_NVME_TCP_BPF_H
#define NVMETEA_NVME_TCP_BPF_H

/* The NVMe/TCP queue owning @sk, or NULL: sk->sk_user_data (low bits are
 * flags) must be a queue whose sock->sk points back to @sk. */
static __always_inline struct nvme_tcp_queue *nvme_queue_of(const struct sock *sk)
{
	unsigned long ud = (unsigned long)BPF_CORE_READ(sk, sk_user_data);
	struct nvme_tcp_queue *q = (struct nvme_tcp_queue *)(ud & ~7UL);
	struct socket *so;

	if (!q)
		return NULL;
	so = BPF_CORE_READ(q, sock);
	if (!so || (unsigned long)BPF_CORE_READ(so, sk) != (unsigned long)sk)
		return NULL;
	return q;
}

/* Controller instance and the driver's own qid of queue @q:
 * (q - ctrl->queues) / sizeof(struct nvme_tcp_queue), bounds-checked against
 * queue_count, and only for controllers whose ops->name is "tcp". */
static __always_inline bool queue_ident(struct nvme_tcp_queue *q, __u32 *inst, __u16 *qid)
{
	struct nvme_tcp_ctrl *tc = BPF_CORE_READ(q, ctrl);
	struct nvme_tcp_queue *base;
	const struct nvme_ctrl_ops *ops;
	const char *name;
	char b[4] = {};
	__u64 off, sz;
	__u32 qc;

	if (!tc)
		return false;
	ops = BPF_CORE_READ(tc, ctrl.ops);
	if (!ops)
		return false;
	name = BPF_CORE_READ(ops, name);
	if (bpf_probe_read_kernel_str(b, sizeof(b), name) < 0 || b[0] != 't' || b[1] != 'c' || b[2] != 'p' || b[3])
		return false;
	base = BPF_CORE_READ(tc, queues);
	sz = bpf_core_type_size(struct nvme_tcp_queue);
	if (!base || !sz || (unsigned long)q < (unsigned long)base)
		return false;
	off = (unsigned long)q - (unsigned long)base;
	if (off % sz)
		return false;
	qc = BPF_CORE_READ(tc, ctrl.queue_count);
	if (off / sz >= qc)
		return false;
	*qid = (__u16)(off / sz);
	*inst = (__u32)BPF_CORE_READ(tc, ctrl.instance);
	return true;
}

#endif /* NVMETEA_NVME_TCP_BPF_H */
