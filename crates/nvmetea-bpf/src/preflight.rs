//! fentry attach preflight (`docs/kernel-compatibility.md` §8, finding F15).
//!
//! fentry/fexit attach updates a BPF trampoline, which waits for RCU-tasks
//! grace periods; on busy hosts that has been seen to take seconds per
//! program. Before choosing the fentry flavour, nvmetea re-executes itself
//! (`nvmetea __preflight`) to attach one empty fentry program to
//! `bpf_fentry_test1` and waits for it with a deadline. A helper that misses
//! the deadline is killed and not waited for; the kprobe flavour is used.
//! A separate process (spawned with exec, not fork) keeps a stalled attach from
//! blocking the caller.

#[allow(
    clippy::all,
    clippy::unwrap_used,
    dead_code,
    unused_imports,
    unsafe_op_in_unsafe_fn,
    non_camel_case_types,
    non_snake_case
)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/preflight.skel.rs"));
}

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use serde::Serialize;
use std::io::Read;
use std::mem::MaybeUninit;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Per-program attach time above which fentry is not used: a full driver
/// object attaches about 20 fentry/fexit programs.
pub const MAX_ATTACH_MS: f64 = 100.0;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Preflight {
    /// The helper attached and detached one fentry program.
    Passed {
        attach_ms: f64,
        total_ms: f64,
    },
    /// Attached, but too slowly for a full object.
    Slow {
        attach_ms: f64,
    },
    /// No answer within the deadline; the helper was killed.
    TimedOut {
        after_ms: f64,
    },
    Failed {
        error: String,
    },
}

impl Preflight {
    pub fn fentry_ok(&self) -> bool {
        matches!(self, Preflight::Passed { .. })
    }
}

/// Run the helper and judge the result.
pub fn check(deadline: Duration) -> Preflight {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return Preflight::Failed { error: format!("current_exe: {e}") },
    };
    let t0 = Instant::now();
    let mut child = match Command::new(exe)
        .arg("__preflight")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Preflight::Failed { error: format!("spawn: {e}") },
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let total_ms = t0.elapsed().as_secs_f64() * 1e3;
                let mut out = String::new();
                if let Some(mut so) = child.stdout.take() {
                    let _ = so.read_to_string(&mut out);
                }
                if !status.success() {
                    return Preflight::Failed { error: out.trim().to_string() };
                }
                let attach_ms = out.trim().strip_prefix("ok ").and_then(|v| v.parse::<f64>().ok());
                return match attach_ms {
                    Some(a) if a <= MAX_ATTACH_MS => Preflight::Passed { attach_ms: a, total_ms },
                    Some(a) => Preflight::Slow { attach_ms: a },
                    None => Preflight::Failed { error: format!("unexpected helper output: {}", out.trim()) },
                };
            }
            Ok(None) if t0.elapsed() >= deadline => {
                let _ = child.kill();
                // not waited for: a stalled attach may keep it in the kernel
                std::mem::forget(child);
                return Preflight::TimedOut { after_ms: t0.elapsed().as_secs_f64() * 1e3 };
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Preflight::Failed { error: e.to_string() },
        }
    }
}

/// Body of `nvmetea __preflight`: attach, report "ok <attach ms>", detach.
pub fn run_helper() -> i32 {
    let storage: &'static mut MaybeUninit<libbpf_rs::OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));
    let open = match skel::PreflightSkelBuilder::default().open(storage) {
        Ok(o) => o,
        Err(e) => {
            println!("open: {e}");
            return 1;
        }
    };
    let skel = match open.load() {
        Ok(s) => s,
        Err(e) => {
            println!("load: {e}");
            return 1;
        }
    };
    let t = Instant::now();
    match skel.progs.nvt_preflight.attach() {
        Ok(link) => {
            let ms = t.elapsed().as_secs_f64() * 1e3;
            drop(link);
            println!("ok {ms:.3}");
            0
        }
        Err(e) => {
            println!("attach: {e}");
            1
        }
    }
}
