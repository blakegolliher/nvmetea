//! BPF program run-time statistics for overhead measurement.
//!
//! `BPF_ENABLE_STATS(BPF_STATS_RUN_TIME)` turns on per-program run counters
//! for as long as the returned file descriptor is open: host-wide (every BPF
//! program), with the small cost of two clock reads per program run. It is
//! the scoped alternative to the `kernel.bpf_stats_enabled` sysctl: closing
//! the descriptor (also on crash) restores the previous state.

use libbpf_rs::libbpf_sys;
use serde::Serialize;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// Run-time statistics stay enabled while this is alive.
pub struct RunStats {
    _fd: OwnedFd,
}

pub fn enable_run_stats() -> std::io::Result<RunStats> {
    // SAFETY: a syscall wrapper with a plain integer argument.
    let fd = unsafe { libbpf_sys::bpf_enable_stats(libbpf_sys::BPF_STATS_RUN_TIME) };
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(-fd));
    }
    // SAFETY: libbpf returned a new descriptor that nothing else owns.
    Ok(RunStats { _fd: unsafe { OwnedFd::from_raw_fd(fd) } })
}

/// Cumulative run statistics of one program.
#[derive(Debug, Clone, Serialize)]
pub struct ProgRun {
    pub object: &'static str,
    pub program: String,
    pub run_cnt: u64,
    pub run_time_ns: u64,
    /// Runs skipped because a BPF program was already running on that CPU
    /// (recursion protection; kprobe programs share one per-CPU guard).
    pub recursion_misses: u64,
}

/// `(run_cnt, run_time_ns, recursion_misses)` of a loaded program.
pub fn prog_run(fd: BorrowedFd<'_>) -> Option<(u64, u64, u64)> {
    let mut info = libbpf_sys::bpf_prog_info::default();
    let mut len = std::mem::size_of::<libbpf_sys::bpf_prog_info>() as u32;
    // SAFETY: info and len are valid for writes; the kernel fills at most len bytes.
    let r = unsafe { libbpf_sys::bpf_prog_get_info_by_fd(fd.as_raw_fd(), &mut info, &mut len) };
    (r == 0).then_some((info.run_cnt, info.run_time_ns, info.recursion_misses))
}
