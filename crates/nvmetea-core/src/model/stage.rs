//! Per-command driver boundaries of a sampled NVMe/TCP command (Level 2,
//! profile mode). Boundary names follow `docs/latency-model.md` §3. All times
//! are CLOCK_MONOTONIC ns; `None` means the boundary was not observed.

use crate::model::Op;
use serde::Serialize;

/// Command flags (mirror of `NVT_PF_*` in `bpf/nvmetea.h`).
pub mod flag {
    pub const DIRECT: u32 = 1 << 0;
    pub const INLINE: u32 = 1 << 1;
    pub const R2T: u32 = 1 << 2;
    pub const MULTI_R2T: u32 = 1 << 3;
    pub const DATA_SUCCESS: u32 = 1 << 4;
    pub const RETRIED: u32 = 1 << 5;
    pub const TIMED_OUT: u32 = 1 << 6;
    pub const NO_START: u32 = 1 << 7;
    pub const RX_NOCTX: u32 = 1 << 8;
    pub const R2T_UNMAPPED: u32 = 1 << 9;
    pub const RSP_UNMAPPED: u32 = 1 << 10;
    pub const RX_UNMAPPED: u32 = 1 << 11;
    pub const C2H_SEEN: u32 = 1 << 12;

    pub const NAMES: &[(u32, &str)] = &[
        (DIRECT, "direct_send"),
        (INLINE, "inline_data"),
        (R2T, "r2t"),
        (MULTI_R2T, "multi_r2t"),
        (DATA_SUCCESS, "data_success"),
        (RETRIED, "retried"),
        (TIMED_OUT, "timed_out"),
        (NO_START, "start_ts_missing"),
        (RX_NOCTX, "parsed_outside_receive"),
        (R2T_UNMAPPED, "r2t_notify_unresolved"),
        (RSP_UNMAPPED, "rsp_notify_unresolved"),
        (RX_UNMAPPED, "data_notify_unresolved"),
        (C2H_SEEN, "c2h_data_seen"),
    ];

    pub fn names(f: u32) -> Vec<&'static str> {
        NAMES.iter().filter(|(b, _)| f & b != 0).map(|(_, n)| *n).collect()
    }
}

/// Boundary timestamps of one command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Boundaries {
    /// `E_START`: blk-mq request start (`rq->start_time_ns`).
    pub start: Option<u64>,
    /// `E_SETUP`: `nvme_setup_cmd` of the last dispatch.
    pub setup: Option<u64>,
    /// `E_TX_START`: entry of the command's first send attempt.
    pub tx_start: Option<u64>,
    /// `E_CMD_SENT`: command (with in-capsule data) handed to TCP.
    pub cmd_sent: Option<u64>,
    pub r2t_notify: Option<u64>,
    pub r2t_start: Option<u64>,
    pub r2t_proc: Option<u64>,
    pub h2c_start: Option<u64>,
    pub h2c_sent: Option<u64>,
    /// READ: notification covering the first data (sequence-mapped).
    pub rx_notify: Option<u64>,
    /// READ: start of the receive call that copied the first data.
    pub rx_start: Option<u64>,
    /// READ: first data copy.
    pub c2h_first: Option<u64>,
    /// READ: end of the last receive call's work on its data.
    pub c2h_last: Option<u64>,
    /// Notification covering the skb that completed the command.
    pub rsp_notify: Option<u64>,
    /// Start of the receive call that completed the command.
    pub rsp_start: Option<u64>,
    /// `E_RSP_PARSED`.
    pub rsp_parsed: Option<u64>,
    /// `E_NVME_DONE`.
    pub nvme: Option<u64>,
    /// `E_BLK_DONE`.
    pub blk: Option<u64>,
}

/// One sampled command.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StageRecord {
    /// Correlation id (not a kernel address).
    pub seq: u64,
    pub instance: u32,
    pub qid: u16,
    pub cid: u16,
    pub opcode: u8,
    pub nsid: u32,
    pub bytes: u32,
    /// NVMe status (0 = success; 0xffff = block-layer error without NVMe status).
    pub status: u16,
    pub retries: u8,
    pub r2ts: u8,
    pub io_cpu: Option<u32>,
    pub cpu_submit: u16,
    pub cpu_complete: u16,
    pub h2c_calls: u16,
    pub c2h_copies: u16,
    pub flags: u32,
    pub t: Boundaries,
    /// Time inside `nvme_tcp_try_send_data` for this command's solicited data.
    pub busy_h2c_ns: u64,
    /// Time of receive calls spent on this READ's data.
    pub busy_c2h_ns: u64,
}

impl StageRecord {
    pub fn op(&self) -> Op {
        match self.opcode {
            0x02 => Op::Read,
            0x01 => Op::Write,
            0x00 => Op::Flush,
            _ => Op::Other,
        }
    }
    pub fn has(&self, f: u32) -> bool {
        self.flags & f != 0
    }
    /// Request latency (E_START → E_BLK_DONE), when both are known.
    pub fn e2e_ns(&self) -> Option<u64> {
        let (a, b) = (self.t.start?, self.t.blk?);
        b.checked_sub(a)
    }
}
