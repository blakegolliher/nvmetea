//! Interval arithmetic over cumulative counters.
//!
//! Cumulative kernel counters are never reset by nvmetea; rates are differences
//! between two snapshots. A decrease means the counter's owner was replaced
//! (reboot, socket reconnect, device re-creation) and yields `counter_reset`.

use crate::quality::{Obs, Reason};

/// `cur - prev`, or `None` if the counter went backwards.
pub fn delta(prev: u64, cur: u64) -> Option<u64> {
    cur.checked_sub(prev)
}

/// Per-second rate of a cumulative counter over `dt_s` seconds.
pub fn rate(prev: u64, cur: u64, dt_s: f64, sources: &'static [&'static str]) -> Obs<f64> {
    if dt_s.is_nan() || dt_s <= 0.0 {
        return Obs::unavailable(Reason::FirstInterval);
    }
    match delta(prev, cur) {
        Some(d) => Obs::derived(d as f64 / dt_s, sources),
        None => Obs::unavailable(Reason::CounterReset),
    }
}

/// Rate when either sample may be missing (e.g. a field absent on older kernels).
pub fn rate_opt(prev: Option<u64>, cur: Option<u64>, dt_s: f64, sources: &'static [&'static str]) -> Obs<f64> {
    match (prev, cur) {
        (Some(p), Some(c)) => rate(p, c, dt_s, sources),
        (None, Some(_)) => Obs::unavailable(Reason::FirstInterval),
        _ => Obs::unavailable(Reason::MissingInterface),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(rate(10, 30, 2.0, &[]).value, Some(10.0));
        assert_eq!(rate(30, 10, 2.0, &[]).reason, Some(Reason::CounterReset));
        assert_eq!(rate(1, 2, 0.0, &[]).reason, Some(Reason::FirstInterval));
        assert_eq!(rate_opt(None, Some(3), 1.0, &[]).reason, Some(Reason::FirstInterval));
        assert_eq!(rate_opt(Some(1), None, 1.0, &[]).reason, Some(Reason::MissingInterface));
    }
}
