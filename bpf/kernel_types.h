/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * The few kernel types nvmetea reads, declared for BPF CO-RE.
 *
 * Only members that are read are declared; preserve_access_index makes clang
 * emit a relocation per access and libbpf resolves the real offsets against
 * the running kernel's BTF (vmlinux and module BTF) at load time, so these
 * declarations do not have to match any kernel's layout.
 */
#ifndef NVMETEA_KERNEL_TYPES_H
#define NVMETEA_KERNEL_TYPES_H

#include <linux/types.h>

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef _Bool bool;
#define true 1
#define false 0

/* Register layouts for BPF_KPROBE argument access (bpf_tracing.h). */
#define __VMLINUX_H__
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
	unsigned long ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			__u64 regs[31];
			__u64 sp;
			__u64 pc;
			__u64 pstate;
		};
	};
	__u64 orig_x0;
};
#else
#error "unsupported __TARGET_ARCH"
#endif

#define __core __attribute__((preserve_access_index))

/* ---- sockets ---- */

typedef struct {
	s64 counter;
} atomic64_t;

struct in6_addr {
	u8 s6_addr[16];
};

struct sock_common {
	u32 skc_daddr;        /* __be32 */
	u32 skc_rcv_saddr;    /* __be32 */
	u16 skc_dport;        /* __be16 */
	u16 skc_num;          /* host order */
	unsigned short skc_family;
	volatile unsigned char skc_state;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
	atomic64_t skc_cookie;
} __core;

struct sock {
	struct sock_common __sk_common;
	int sk_err;
	void *sk_user_data;
} __core;

struct socket {
	struct sock *sk;
} __core;

struct tcp_sock {
	u32 rcv_nxt;          /* next sequence number expected (delivered up to here) */
} __core;

struct sk_buff {
	struct sock *sk;      /* inside an anonymous union in the kernel; CO-RE resolves it */
	char cb[48];          /* struct tcp_skb_cb: u32 seq, u32 end_seq, ... */
} __core;

/* Declared only so that the offset of nvme_tcp_queue.io_work can be relocated. */
struct work_struct {
	long data;
} __core;

struct seq_file;

struct bpf_iter_meta {
	struct seq_file *seq;
	u64 session_id;
	u64 seq_num;
} __core;

struct bpf_iter__tcp {
	struct bpf_iter_meta *meta;
	struct sock_common *sk_common;
	u32 uid;
} __core;

/* ---- tasks ---- */

#define PF_WQ_WORKER 0x00000020 /* the task is a workqueue worker (kworker) */

struct task_struct {
	unsigned int flags;
} __core;

/* ---- block layer ---- */

struct block_device {
	u32 bd_dev; /* dev_t */
} __core;

struct gendisk {
	struct block_device *part0;
} __core;

struct blk_mq_tag_set;

struct request_queue {
	void *queuedata;      /* NULL for the admin queue and the fabrics connect queue */
	struct gendisk *disk;
	struct blk_mq_tag_set *tag_set;
} __core;

struct blk_mq_tags {
	unsigned int nr_tags;     /* tags of one hardware queue (incl. reserved) */
} __core;

struct blk_mq_hw_ctx {
	struct blk_mq_tags *tags; /* shared by the hctx of every namespace on this hardware queue */
	unsigned int queue_num;
} __core;

struct request {
	struct request_queue *q;
	struct blk_mq_hw_ctx *mq_hctx;
	unsigned int __data_len;
	int tag;
	u64 start_time_ns;
} __core;

/* ---- NVMe host core (drivers/nvme/host/nvme.h; nvme_core module BTF) ---- */

struct nvme_ctrl_ops {
	const char *name;     /* "tcp", "rdma", "pcie", "fc", "loop" */
} __core;

/* CO-RE requires the same kind as the kernel's field (enum, not int). */
enum nvme_ctrl_state {
	NVME_CTRL_NEW = 0,
	NVME_CTRL_LIVE = 1,
};

struct nvme_ctrl {
	enum nvme_ctrl_state state;
	const struct nvme_ctrl_ops *ops;
	int instance;
	u16 cntlid;
	u32 queue_count;
	struct blk_mq_tag_set *admin_tagset;
} __core;

/* ---- NVMe/TCP host (drivers/nvme/host/tcp.c; nvme_tcp module BTF) ---- */

struct nvme_tcp_ctrl;

struct nvme_tcp_request;

struct nvme_tcp_queue {
	struct socket *sock;
	struct work_struct io_work;
	int io_cpu;
	void *pdu;            /* receive PDU header buffer (current PDU) */
	struct nvme_tcp_request *request; /* request being sent; NULL between requests */
	struct nvme_tcp_ctrl *ctrl;
	bool hdr_digest;
	bool data_digest;
	bool tls_enabled;     /* absent on 5.15: read only under bpf_core_field_exists */
} __core;

struct nvme_tcp_ctrl {
	struct nvme_tcp_queue *queues;
	struct nvme_ctrl ctrl;
} __core;

/* The driver PDU of an NVMe/TCP request: starts with struct nvme_request, so its
 * address is the same correlation key Level 1 uses (rq + sizeof(struct request)). */
struct nvme_tcp_request {
	struct nvme_tcp_queue *queue;
} __core;

/* The driver PDU of every NVMe request starts with struct nvme_request. */
struct nvme_request {
	void *cmd;            /* struct nvme_command * (wire format) */
	u8 retries;
	u16 status;
	struct nvme_ctrl *ctrl;
} __core;

/* NVMe submission queue entry, wire format (no relocation). */
struct nvt_wire_cmd {
	u8 opcode;
	u8 flags;
	u16 command_id;
	u32 nsid;
};

#endif /* NVMETEA_KERNEL_TYPES_H */
