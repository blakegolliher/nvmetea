/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * nvmetea: layouts shared by the BPF programs and userspace (Rust mirrors in
 * crates/nvmetea-bpf/src/abi.rs; sizes are asserted on both sides).
 *
 * Timestamps are CLOCK_MONOTONIC ns (bpf_ktime_get_ns, ktime_get_ns).
 */
#ifndef NVMETEA_H
#define NVMETEA_H

#ifndef __bpf__
#include <linux/types.h>
#endif

/*
 * Log-linear latency histogram (docs/architecture.md §4.4):
 *   bucket 0          v < 256 ns
 *   bucket 1..224     2^k .. 2^(k+1), k = 8..35, 8 linear sub-buckets each
 *   bucket 225        v >= 2^36 ns (~68.7 s)
 */
#define NVT_HIST_USED 226
#define NVT_NBUCKETS 232

enum nvt_op {
	NVT_OP_READ = 0,
	NVT_OP_WRITE = 1,
	NVT_OP_FLUSH = 2,
	NVT_OP_OTHER = 3,   /* other I/O-queue commands (incl. fabrics) */
	NVT_OP_ADMIN = 4,   /* admin queue (keep-alive, identify, ...) */
	NVT_OP_NR = 5,
};

enum nvt_metric {
	NVT_M_CMD = 0,      /* nvme_setup_cmd -> nvme_complete_rq (last dispatch) */
	NVT_M_REQ = 1,      /* rq->start_time_ns -> block_rq_complete */
	NVT_M_STAGE_A = 2,  /* rq->start_time_ns -> first nvme_setup_cmd */
	NVT_M_STAGE_E2 = 3, /* nvme_complete_rq -> block_rq_complete */
	NVT_M_NR = 4,
};

/* per-command flags */
#define NVT_F_RETRIED (1u << 0)
#define NVT_F_REQUEUED (1u << 1)
#define NVT_F_AER (1u << 2)
#define NVT_F_NO_START (1u << 3)
#define NVT_F_NVME_ERR (1u << 4)
#define NVT_F_WAS_REQUEUED (1u << 5)

/* Per hardware queue: NVT_OP_NR x NVT_M_NR histograms, index qidx * NVT_HPQ + op * NVT_M_NR + metric. */
#define NVT_HPQ (NVT_OP_NR * NVT_M_NR)

/* Dense index of a hardware queue (assigned at registration) -> identity. */
struct nvt_qinfo {
	__u16 inst;
	__u16 qid;
	__u32 valid;
};

struct nvt_qkey {
	__u16 inst;  /* controller instance (N of nvmeN) */
	__u16 qid;   /* 0 = admin */
};

struct nvt_hkey {
	__u16 inst;
	__u16 qid;
	__u8 op;     /* enum nvt_op */
	__u8 metric; /* enum nvt_metric */
	__u16 pad;
};

struct nvt_pkey {
	__u32 dev;   /* kernel dev_t of the path / namespace block device */
	__u8 op;
	__u8 pad[3];
};

struct nvt_hist {
	__u64 b[NVT_NBUCKETS];
};

struct nvt_qstats {
	__u64 dispatched[NVT_OP_NR];     /* nvme_setup_cmd, retries included */
	__u64 bytes[NVT_OP_NR];          /* bytes of first dispatches */
	__u64 completed[NVT_OP_NR];      /* final block_rq_complete */
	__u64 nvme_errors[NVT_OP_NR];    /* nvme_complete_rq with status != 0 */
	__u64 cmd_lat_sum_ns[NVT_OP_NR];
	__u64 cmd_lat_cnt[NVT_OP_NR];
	__u64 req_lat_sum_ns[NVT_OP_NR];
	__u64 req_lat_cnt[NVT_OP_NR];
	__u64 status_type[8];            /* NVMe status code type (SCT) of errors */
	__u64 retries;
	__u64 requeues;
	__u64 failovers;                 /* nvme error masked at block completion */
	__u64 retried_completed;         /* completions of retried/requeued requests (not in latency hists) */
	__u64 error_completed;           /* block-layer errors (not in latency hists) */
	__s64 inflight;                  /* tracked, dispatched, not completed */
	__u64 inflight_max;              /* max since inflight_epoch */
	__u64 inflight_epoch;
};

struct nvt_inflight {
	__u64 t_setup;       /* last dispatch */
	__u64 t_first_setup;
	__u64 t_start;       /* rq->start_time_ns, 0 if not set */
	__u64 t_nvme;        /* nvme_complete_rq of the last dispatch */
	__u64 seq;           /* correlation id (never a kernel pointer) */
	__u32 dev;
	__u32 nsid;
	__u32 bytes;
	__u16 inst;
	__u16 qid;
	__u16 cid;
	__u16 status;
	__u16 cpu;
	__u8 op;
	__u8 opcode;
	__u8 retries;
	__u8 flags;
	__u8 pad[6];
};

/* One in-flight command: slot `region base + blk-mq tag` of the slot array
 * (key = driver PDU address, 0 = free). */
struct nvt_slot {
	__u64 key;
	struct nvt_inflight e;
};

enum nvt_counter {
	NVT_C_SETUP_TCP = 0,
	NVT_C_UNTRACKED_COMPLETION,  /* completed but its dispatch was not seen */
	NVT_C_CID_MISMATCH,          /* entry exists but command id differs */
	NVT_C_STALE_REPLACED,        /* dispatch found an unfinished entry (missed completion) */
	NVT_C_MAP_FULL_INFLIGHT,     /* no slot region left for a new hardware queue */
	NVT_C_MAP_FULL_QSTATS,
	NVT_C_MAP_FULL_HIST,
	NVT_C_EVENTS_LOST,
	NVT_C_SLOW_SUPPRESSED,
	NVT_C_START_MISSING,
	NVT_C_ORDER_VIOLATION,
	NVT_C_AER,
	NVT_C_SEQ,                   /* per-CPU correlation sequence */
	NVT_C_NR = 16,
};

struct nvt_counters {
	__u64 c[NVT_C_NR];
};

enum nvt_event_kind {
	NVT_EV_SLOW = 1,
	NVT_EV_STATE = 2,
	NVT_EV_TCP = 3,
	NVT_EV_PROF = 4,
	NVT_EV_TIMEOUT = 5,
};

/* ---- Level 3: NVMe/TCP queue sockets (bpf/tcp_sock.bpf.c) ---- */

#define NVT_QS_HDR_DIGEST (1u << 0)
#define NVT_QS_DATA_DIGEST (1u << 1)
#define NVT_QS_TLS (1u << 2)
#define NVT_QS_TLS_UNKNOWN (1u << 3) /* kernel has no tls_enabled field */

/* One iter/tcp record per NVMe/TCP queue socket. */
struct nvt_qsock {
	__u64 cookie;
	__u32 inst;      /* controller instance */
	__u16 qid;       /* 0 = admin */
	__u16 family;    /* AF_INET / AF_INET6 */
	__s32 io_cpu;    /* queue->io_cpu (WORK_CPU_UNBOUND when unbound) */
	__u16 lport;     /* host byte order */
	__u16 rport;     /* host byte order */
	__u8 laddr[16];  /* IPv4 in the first 4 bytes */
	__u8 raddr[16];
	__u8 state;      /* TCP state */
	__u8 flags;      /* NVT_QS_* */
	__u8 pad[6];
};

/* Cumulative transport events per queue socket (keyed by socket cookie). */
struct nvt_sstats {
	__u64 retrans;          /* tcp_retransmit_skb events (skbs, not segments) */
	__u64 rst_rx;
	__u64 rst_tx;
	__u64 state_changes;
	__u64 loss_entries;     /* entries into TCP_CA_Loss */
	__u64 recovery_entries; /* entries into TCP_CA_Recovery */
	__u64 cwr_entries;      /* entries into TCP_CA_CWR */
	__u64 errors;           /* inet_sk_error_report */
	__u64 last_event_ns;
	__u32 inst;
	__u16 qid;
	__u16 pad;
};

enum nvt_tcp_event {
	NVT_TEV_RETRANS = 1,
	NVT_TEV_STATE = 2,   /* a = old state, b = new state */
	NVT_TEV_RST_RX = 3,
	NVT_TEV_RST_TX = 4,
	NVT_TEV_CONG = 5,    /* a = new ca_state */
	NVT_TEV_ERROR = 6,   /* a = sk_err */
};

struct nvt_ev_tcp {
	__u32 kind;          /* NVT_EV_TCP */
	__u32 tkind;         /* enum nvt_tcp_event */
	__u64 t;
	__u64 cookie;
	__u32 inst;
	__u16 qid;
	__u16 pad;
	__s32 a;
	__s32 b;
};

struct nvt_ev_slow {
	__u32 kind;
	__u32 cpu;          /* completion CPU */
	__u64 t_blk;        /* block_rq_complete */
	__s32 blk_error;
	__u32 pad;
	struct nvt_inflight rec;
};

struct nvt_ev_state {
	__u32 kind;
	__u32 inst;
	__u64 t;
	__u32 old_state;
	__u32 new_state;
	__u32 accepted;     /* nvme_change_ctrl_state() return value */
	__u32 pad;
};

/* ---- Level 2: NVMe/TCP driver stage records (bpf/tcp_driver.bpf.c) ----
 *
 * One record per sampled command, filled in by the driver hooks and emitted at
 * block completion. Boundary names follow docs/latency-model.md §3; 0 means the
 * boundary was not observed. Stages are computed in userspace (nvmetea-profile).
 */

#define NVT_PF_DIRECT (1u << 0)        /* first send attempt not in a workqueue worker (direct send) */
#define NVT_PF_INLINE (1u << 1)        /* write data sent in-capsule */
#define NVT_PF_R2T (1u << 2)           /* write data solicited by R2T */
#define NVT_PF_MULTI_R2T (1u << 3)     /* more than one R2T */
#define NVT_PF_DATA_SUCCESS (1u << 4)  /* READ completed by a C2H data PDU with SUCCESS */
#define NVT_PF_RETRIED (1u << 5)       /* dispatched more than once */
#define NVT_PF_TIMED_OUT (1u << 6)
#define NVT_PF_NO_START (1u << 7)      /* rq->start_time_ns was 0 */
#define NVT_PF_RX_NOCTX (1u << 8)      /* response parsed outside a receive call (e.g. cancel) */
#define NVT_PF_R2T_UNMAPPED (1u << 9)  /* R2T notification not resolved by sequence */
#define NVT_PF_RSP_UNMAPPED (1u << 10) /* response notification not resolved */
#define NVT_PF_RX_UNMAPPED (1u << 11)  /* READ first-data notification not resolved */
#define NVT_PF_C2H_SEEN (1u << 12)     /* at least one READ data copy attributed */

struct nvt_prof {
	__u64 t_start;      /* E_START: rq->start_time_ns (0 if not set) */
	__u64 t_setup;      /* E_SETUP: nvme_setup_cmd (last dispatch) */
	__u64 t_tx_start;   /* E_TX_START: entry of the command's first send attempt (nvme_tcp_try_send_cmd_pdu) */
	__u64 t_cmd_sent;   /* E_CMD_SENT: command (and in-capsule data) handed to TCP */
	__u64 t_r2t_notify; /* E_R2T_NOTIFY: first notification covering the R2T (sequence-mapped) */
	__u64 t_r2t_start;  /* E_R2T_START: start of the receive call that parsed the R2T */
	__u64 t_r2t_proc;   /* E_R2T_PROC: first R2T parsed */
	__u64 t_h2c_start;  /* E_H2C_START: first solicited data PDU starts sending */
	__u64 t_h2c_sent;   /* E_H2C_SENT: last solicited data handed to TCP */
	__u64 t_rx_notify;  /* READ: notification covering the first data (sequence-mapped) */
	__u64 t_rx_start;   /* READ: start of the receive call that copied the first data */
	__u64 t_c2h_first;  /* READ: first data copy */
	__u64 t_c2h_last;   /* READ: end of the last receive call's work on its data (or its completion) */
	__u64 t_rsp_notify; /* notification covering the skb that completed the command (sequence-mapped) */
	__u64 t_rsp_start;  /* start of the receive call that completed the command */
	__u64 t_rsp_parsed; /* E_RSP_PARSED: blk_mq_complete_request_remote */
	__u64 t_nvme;       /* E_NVME_DONE */
	__u64 t_blk;        /* E_BLK_DONE */
	__u64 busy_h2c;     /* time inside nvme_tcp_try_send_data for this command's solicited data */
	__u64 busy_c2h;     /* time of receive calls spent on this READ's data */
	__u64 seq;          /* correlation id (never a kernel pointer) */
	__u32 bytes;
	__u32 nsid;
	__u32 flags;        /* NVT_PF_* */
	__s32 io_cpu;
	__u16 inst;
	__u16 qid;
	__u16 cid;
	__u16 status;
	__u16 cpu_submit;
	__u16 cpu_complete;
	__u16 h2c_calls;    /* try_send_data calls for solicited data */
	__u16 c2h_copies;   /* READ data copies */
	__u8 opcode;
	__u8 retries;
	__u8 r2ts;
	__u8 pad[5];
};

struct nvt_ev_prof {
	__u32 kind;         /* NVT_EV_PROF */
	__u32 pad;
	struct nvt_prof rec;
};

struct nvt_ev_timeout {
	__u32 kind;         /* NVT_EV_TIMEOUT */
	__u32 inst;
	__u64 t;
	__u64 age_ns;       /* since rq->start_time_ns (0 if not set) */
	__u16 qid;
	__u16 cid;
	__u8 opcode;
	__u8 sampled;
	__u8 pad[2];
};

/* Per-queue worker (io_work) accounting, cumulative. */
struct nvt_wstats {
	__u64 runs;
	__u64 busy_ns;      /* elapsed time inside io_work (includes preemption and interrupts) */
	__u64 quota_runs;   /* runs that used the whole 1 ms quota and requeued themselves */
	__u64 max_ns;
};

enum nvt_dcounter {
	NVT_D_SAMPLED = 0,       /* commands selected for a record */
	NVT_D_EMITTED,
	NVT_D_EVENTS_LOST,       /* ring buffer full */
	NVT_D_MAP_FULL,          /* no record slot: sample skipped */
	NVT_D_STALE,             /* a record found unfinished at a new dispatch */
	NVT_D_RETRIED,
	NVT_D_TX_CTX_LOST,       /* send exit without its entry context (preempted/migrated) */
	NVT_D_SEQ_UNRESOLVED,    /* notification ring did not resolve a boundary */
	NVT_D_C2H_UNMATCHED,     /* READ data copy whose command was not found */
	NVT_D_H2C_CONT,          /* H2C data PDUs set up from the send path (same R2T) */
	NVT_D_TIMEOUTS,
	NVT_D_RX_NOCTX,          /* response parsed outside a receive call */
	NVT_D_IOW_CTX_LOST,      /* io_work exit without its entry context (another run interleaved) */
	NVT_D_NR = 16,
};

struct nvt_dcounters {
	__u64 c[NVT_D_NR];
};

#define NVT_NRING 32         /* receive notifications kept per queue */

/* Receive notifications of one queue: (time, tcp rcv_nxt) at each sk_data_ready. */
struct nvt_nring {
	__u64 t[NVT_NRING];
	__u32 seq[NVT_NRING];
	__u32 head;              /* next slot; total notifications recorded */
	__s32 hot;               /* sampled commands in flight on this queue */
};

_Static_assert(sizeof(struct nvt_prof) == 208, "nvt_prof layout");
_Static_assert(sizeof(struct nvt_ev_prof) == 216, "nvt_ev_prof layout");
_Static_assert(sizeof(struct nvt_ev_timeout) == 32, "nvt_ev_timeout layout");
_Static_assert(sizeof(struct nvt_wstats) == 32, "nvt_wstats layout");
_Static_assert(sizeof(struct nvt_nring) == 392, "nvt_nring layout");

_Static_assert(sizeof(struct nvt_inflight) == 72, "nvt_inflight layout");
_Static_assert(sizeof(struct nvt_slot) == 80, "nvt_slot layout");
_Static_assert(sizeof(struct nvt_qinfo) == 8, "nvt_qinfo layout");
_Static_assert(sizeof(struct nvt_ev_slow) == 96, "nvt_ev_slow layout");
_Static_assert(sizeof(struct nvt_ev_state) == 32, "nvt_ev_state layout");
_Static_assert(sizeof(struct nvt_hist) == 8 * NVT_NBUCKETS, "nvt_hist layout");
_Static_assert(sizeof(struct nvt_qsock) == 64, "nvt_qsock layout");
_Static_assert(sizeof(struct nvt_sstats) == 80, "nvt_sstats layout");
_Static_assert(sizeof(struct nvt_ev_tcp) == 40, "nvt_ev_tcp layout");

#endif /* NVMETEA_H */
