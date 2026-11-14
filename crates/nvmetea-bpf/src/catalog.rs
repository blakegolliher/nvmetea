//! The probe catalog of `docs/kernel-compatibility.md` §5, as data.

/// Where a hook lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Tracepoint `system:name`, declared in the BTF of `btf_module` ("" = vmlinux).
    Tracepoint { system: &'static str, name: &'static str, btf_module: &'static str },
    /// Kernel function in `module` ("" = vmlinux).
    Function { module: &'static str, name: &'static str },
    /// BPF iterator target, present when vmlinux BTF has `struct bpf_iter__<name>`.
    Iterator { name: &'static str },
}

#[derive(Debug, Clone, Copy)]
pub struct ProbeSpec {
    pub id: &'static str,
    pub level: u8,
    pub target: Target,
    pub provides: &'static str,
    pub fallback: &'static str,
}

const fn tp(system: &'static str, name: &'static str, btf_module: &'static str) -> Target {
    Target::Tracepoint { system, name, btf_module }
}
const fn func(module: &'static str, name: &'static str) -> Target {
    Target::Function { module, name }
}

pub const CATALOG: &[ProbeSpec] = &[
    ProbeSpec {
        id: "P1",
        level: 1,
        target: tp("nvme", "nvme_setup_cmd", "nvme_core"),
        provides: "dispatch boundary, cid/qid/opcode, request identity",
        fallback: "text tracepoint (P1b)",
    },
    ProbeSpec {
        id: "P2",
        level: 1,
        target: tp("nvme", "nvme_complete_rq", "nvme_core"),
        provides: "NVMe completion, status, retries",
        fallback: "text tracepoint (P2b)",
    },
    ProbeSpec {
        id: "P3",
        level: 1,
        target: tp("block", "block_rq_complete", ""),
        provides: "block completion (request latency end)",
        fallback: "none",
    },
    ProbeSpec {
        id: "P4",
        level: 1,
        target: tp("block", "block_rq_requeue", ""),
        provides: "requeue marker",
        fallback: "retry count from P2",
    },
    ProbeSpec {
        id: "P5",
        level: 1,
        target: func("nvme_core", "nvme_failover_req"),
        provides: "multipath failover",
        fallback: "status inference at P2",
    },
    ProbeSpec {
        id: "P6",
        level: 1,
        target: func("nvme_core", "nvme_retry_req"),
        provides: "retry decision",
        fallback: "re-dispatch at P1",
    },
    ProbeSpec {
        id: "P7",
        level: 1,
        target: func("nvme_core", "nvme_cancel_request"),
        provides: "host cancellation",
        fallback: "status at P2",
    },
    ProbeSpec {
        id: "P8",
        level: 1,
        target: func("nvme_core", "nvme_keep_alive_end_io"),
        provides: "keep-alive completion",
        fallback: "admin opcode 0x18 at P1/P2",
    },
    ProbeSpec {
        id: "P9a",
        level: 1,
        target: func("nvme_core", "nvme_init_ctrl"),
        provides: "controller object creation (generation)",
        fallback: "userspace generations",
    },
    ProbeSpec {
        id: "P9b",
        level: 1,
        target: func("nvme_core", "nvme_uninit_ctrl"),
        provides: "controller object destruction",
        fallback: "userspace generations",
    },
    ProbeSpec {
        id: "L3",
        level: 1,
        target: func("nvme_core", "nvme_change_ctrl_state"),
        provides: "every state transition (ns timestamps)",
        fallback: "uevents + sysfs polling",
    },
    ProbeSpec {
        id: "L4",
        level: 1,
        target: tp("nvme", "nvme_async_event", "nvme_core"),
        provides: "asynchronous event notifications",
        fallback: "uevent NVME_AEN",
    },
    ProbeSpec {
        id: "D1",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_try_send_cmd_pdu"),
        provides: "command PDU handed to TCP",
        fallback: "D5",
    },
    ProbeSpec {
        id: "D2a",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_try_send_data"),
        provides: "write data handed to TCP",
        fallback: "D5",
    },
    ProbeSpec {
        id: "D2b",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_try_send_ddgst"),
        provides: "data digest sent",
        fallback: "D5",
    },
    ProbeSpec {
        id: "D3",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_try_send_data_pdu"),
        provides: "solicited H2C data starts",
        fallback: "D5",
    },
    ProbeSpec {
        id: "D4",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_setup_h2c_data_pdu"),
        provides: "R2T parsed",
        fallback: "none",
    },
    ProbeSpec {
        id: "D5",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_try_send"),
        provides: "send fallback where try_send_* are inlined",
        fallback: "stage B unavailable",
    },
    ProbeSpec {
        id: "D6",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_io_work"),
        provides: "queue worker runs, elapsed, CPU",
        fallback: "worker metrics unavailable",
    },
    ProbeSpec {
        id: "D7",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_recv_skb"),
        provides: "receive context per skb",
        fallback: "receive staging unavailable",
    },
    ProbeSpec {
        id: "D8a",
        level: 2,
        target: func("", "skb_copy_datagram_iter"),
        provides: "READ data copies",
        fallback: "READ data phase merged",
    },
    ProbeSpec {
        id: "D8b",
        level: 2,
        target: func("", "skb_copy_and_hash_datagram_iter"),
        provides: "READ data copies with data digest",
        fallback: "digest queues: data phase merged",
    },
    ProbeSpec {
        id: "D9",
        level: 2,
        target: func("", "blk_mq_complete_request_remote"),
        provides: "response parsed (before IPI)",
        fallback: "P2 only",
    },
    ProbeSpec {
        id: "D10",
        level: 2,
        target: tp("sock", "sk_data_ready", ""),
        provides: "receive notification (sequence-mapped)",
        fallback: "nvme_tcp_data_ready function hook",
    },
    ProbeSpec {
        id: "D10f",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_data_ready"),
        provides: "receive notification (function hook)",
        fallback: "C1+D1 merged",
    },
    ProbeSpec {
        id: "D11",
        level: 2,
        target: tp("sched", "sched_switch", ""),
        provides: "off-CPU time inside the worker",
        fallback: "worker time as elapsed only",
    },
    ProbeSpec {
        id: "D12",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_timeout"),
        provides: "command timeout events",
        fallback: "error status only",
    },
    ProbeSpec {
        id: "D13",
        level: 2,
        target: func("nvme_tcp", "nvme_tcp_poll"),
        provides: "receive context on polled queues",
        fallback: "polled queues unstaged",
    },
    ProbeSpec {
        id: "T1",
        level: 3,
        target: Target::Iterator { name: "tcp" },
        provides: "queue ↔ socket table",
        fallback: "endpoint match (controller level)",
    },
    ProbeSpec {
        id: "T3",
        level: 3,
        target: tp("tcp", "tcp_retransmit_skb", ""),
        provides: "timestamped retransmissions",
        fallback: "tcp_info counter deltas",
    },
    ProbeSpec {
        id: "T4",
        level: 3,
        target: tp("sock", "inet_sock_set_state", ""),
        provides: "socket state changes",
        fallback: "sock_diag polling",
    },
    ProbeSpec {
        id: "T5",
        level: 3,
        target: tp("tcp", "tcp_cong_state_set", ""),
        provides: "congestion state changes",
        fallback: "tcpi_ca_state sampling",
    },
    ProbeSpec {
        id: "T6",
        level: 3,
        target: tp("tcp", "tcp_receive_reset", ""),
        provides: "RST received",
        fallback: "sock_diag polling",
    },
    ProbeSpec {
        id: "F",
        level: 0,
        target: func("", "bpf_fentry_test1"),
        provides: "fentry attach preflight target",
        fallback: "kprobes",
    },
];

/// vmlinux functions the catalog needs to look up in kallsyms/ftrace.
pub fn vmlinux_functions() -> Vec<&'static str> {
    let mut v: Vec<&str> = CATALOG
        .iter()
        .filter_map(|p| match p.target {
            Target::Function { module: "", name } => Some(name),
            _ => None,
        })
        .collect();
    v.extend(["sock_sendmsg", "kernel_sendpage"]);
    v
}

/// (struct, member, owning BTF module or "" for vmlinux) that the planned CO-RE
/// programs read. Optional members are marked; see finding F9.
pub const FIELDS: &[(&str, &str, &str, bool)] = &[
    ("request", "q", "", false),
    ("request", "mq_hctx", "", false),
    ("request", "tag", "", false),
    ("request", "__data_len", "", false),
    ("request", "start_time_ns", "", false),
    ("sock_common", "skc_cookie", "", false),
    ("sock", "sk_user_data", "", false),
    ("tcp_sock", "rcv_nxt", "", false),
    ("tcp_skb_cb", "end_seq", "", false),
    ("sk_buff", "tstamp", "", false),
    ("nvme_request", "cmd", "nvme_core", false),
    ("nvme_request", "genctr", "nvme_core", false),
    ("nvme_request", "retries", "nvme_core", false),
    ("nvme_request", "status", "nvme_core", false),
    ("nvme_request", "ctrl", "nvme_core", false),
    ("nvme_request", "start_time", "nvme_core", true),
    ("nvme_ctrl", "instance", "nvme_core", false),
    ("nvme_ctrl", "cntlid", "nvme_core", false),
    ("nvme_ctrl", "state", "nvme_core", false),
    ("nvme_tcp_queue", "sock", "nvme_tcp", false),
    ("nvme_tcp_queue", "io_cpu", "nvme_tcp", false),
    ("nvme_tcp_queue", "pdu", "nvme_tcp", false),
    ("nvme_tcp_queue", "request", "nvme_tcp", false),
    ("nvme_tcp_queue", "ctrl", "nvme_tcp", false),
    ("nvme_tcp_queue", "tls_enabled", "nvme_tcp", true),
    ("nvme_tcp_queue", "data_digest", "nvme_tcp", false),
    ("nvme_tcp_request", "queue", "nvme_tcp", false),
    ("nvme_tcp_request", "state", "nvme_tcp", false),
    ("nvme_tcp_ctrl", "queues", "nvme_tcp", false),
];
