//! Graceful stop for the long-running commands (`record`, `profile`, `serve`,
//! the TUI). The first SIGINT or SIGTERM asks the command to finish: write the
//! capture or the report so far, restore the terminal. Another one more than
//! 0.5 s later terminates at once (default action); closer ones are the same
//! request delivered twice (`timeout` signals the child and its process group,
//! a terminal signals the whole foreground group). A SIGINT that was already
//! ignored when nvmetea started (a background job of a non-interactive shell,
//! `nohup`) stays ignored, as shells expect.

use std::sync::atomic::{AtomicU64, Ordering};

/// CLOCK_MONOTONIC time of the first stop signal, 0 = none yet.
static FIRST_NS: AtomicU64 = AtomicU64::new(0);

const DUPLICATE_WINDOW_NS: u64 = 500_000_000;

fn monotonic_ns() -> u64 {
    // SAFETY: clock_gettime(2) is async-signal-safe and writes only `ts`.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64).max(1)
}

extern "C" fn on_signal(sig: libc::c_int) {
    let now = monotonic_ns();
    if let Err(first) = FIRST_NS.compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst) {
        if now.saturating_sub(first) > DUPLICATE_WINDOW_NS {
            // A second request: terminate now. signal() and raise() are
            // async-signal-safe.
            // SAFETY: restoring the default disposition and re-raising is the
            // documented way to terminate "as if" no handler were installed.
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
            }
        }
    }
}

/// Install the handlers. Call once, before starting the command's loop.
pub fn install() {
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: plain sigaction(2) calls with zero-initialised structs; the
        // handler only touches an atomic and async-signal-safe functions.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if sig == libc::SIGINT
                && libc::sigaction(sig, std::ptr::null(), &mut old) == 0
                && old.sa_sigaction == libc::SIG_IGN
            {
                continue;
            }
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = libc::SA_RESTART;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// True once a stop was requested.
pub fn requested() -> bool {
    FIRST_NS.load(Ordering::Relaxed) != 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn first_signal_requests_stop_and_a_duplicate_is_ignored() {
        super::install();
        assert!(!super::requested());
        // SAFETY: raise(3) on our own process; the handler is installed.
        unsafe { libc::raise(libc::SIGTERM) };
        assert!(super::requested());
        // within the duplicate window: the same request, not a forced exit
        unsafe { libc::raise(libc::SIGTERM) };
        assert!(super::requested());
    }
}
