//! Length-gated decoding of `struct tcp_info` (uapi `linux/tcp.h`).
//!
//! Offsets were verified against the BTF of the development kernel (6.12,
//! `sizeof(struct tcp_info)` = 248). Older kernels return a shorter structure;
//! every field after `tcpi_total_retrans` (offset 100) is decoded only if the
//! returned length covers it.

use nvmetea_core::model::TcpInfo;

/// Bytes up to and including `tcpi_total_retrans` (present since Linux 2.6).
pub const MIN_LEN: usize = 104;

fn u8_at(b: &[u8], o: usize) -> u8 {
    b[o]
}
fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_ne_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        u64::from_ne_bytes(a)
    })
}

pub fn decode(b: &[u8]) -> Option<TcpInfo> {
    if b.len() < MIN_LEN {
        return None;
    }
    let r = |o| u32_at(b, o).unwrap_or(0); // in range: len >= MIN_LEN
    Some(TcpInfo {
        state: u8_at(b, 0),
        ca_state: u8_at(b, 1),
        retransmits: u8_at(b, 2),
        probes: u8_at(b, 3),
        backoff: u8_at(b, 4),
        options: u8_at(b, 5),
        snd_wscale: u8_at(b, 6) & 0x0f,
        rcv_wscale: u8_at(b, 6) >> 4,
        rto_us: r(8),
        ato_us: r(12),
        snd_mss: r(16),
        rcv_mss: r(20),
        unacked: r(24),
        sacked: r(28),
        lost: r(32),
        retrans: r(36),
        last_data_sent_ms: r(44),
        last_data_recv_ms: r(52),
        last_ack_recv_ms: r(56),
        pmtu: r(60),
        rcv_ssthresh: r(64),
        rtt_us: r(68),
        rttvar_us: r(72),
        snd_ssthresh: r(76),
        snd_cwnd: r(80),
        advmss: r(84),
        reordering: r(88),
        rcv_rtt_us: r(92),
        rcv_space: r(96),
        total_retrans: r(100),
        pacing_rate: u64_at(b, 104),
        max_pacing_rate: u64_at(b, 112),
        bytes_acked: u64_at(b, 120),
        bytes_received: u64_at(b, 128),
        segs_out: u32_at(b, 136),
        segs_in: u32_at(b, 140),
        notsent_bytes: u32_at(b, 144),
        min_rtt_us: u32_at(b, 148),
        data_segs_in: u32_at(b, 152),
        data_segs_out: u32_at(b, 156),
        delivery_rate: u64_at(b, 160),
        busy_time_us: u64_at(b, 168),
        rwnd_limited_us: u64_at(b, 176),
        sndbuf_limited_us: u64_at(b, 184),
        delivered: u32_at(b, 192),
        delivered_ce: u32_at(b, 196),
        bytes_sent: u64_at(b, 200),
        bytes_retrans: u64_at(b, 208),
        dsack_dups: u32_at(b, 216),
        reord_seen: u32_at(b, 220),
        rcv_ooopack: u32_at(b, 224),
        snd_wnd: u32_at(b, 228),
        rcv_wnd: u32_at(b, 232),
        rehash: u32_at(b, 236),
        total_rto: u16_at(b, 240),
        total_rto_recoveries: u16_at(b, 242),
        total_rto_time_ms: u32_at(b, 244),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_ne_bytes());
    }
    fn put64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_ne_bytes());
    }

    #[test]
    fn full_struct() {
        let mut b = vec![0u8; 248];
        b[0] = 1;
        b[6] = 0x76; // rcv_wscale 7, snd_wscale 6
        put32(&mut b, 68, 153);
        put32(&mut b, 72, 137);
        put32(&mut b, 80, 10);
        put32(&mut b, 100, 3);
        put64(&mut b, 200, 12_331_136);
        put32(&mut b, 148, 21);
        put32(&mut b, 244, 77);
        let i = decode(&b).expect("decode");
        assert_eq!((i.state, i.snd_wscale, i.rcv_wscale), (1, 6, 7));
        assert_eq!((i.rtt_us, i.rttvar_us, i.snd_cwnd, i.total_retrans), (153, 137, 10, 3));
        assert_eq!(i.bytes_sent, Some(12_331_136));
        assert_eq!(i.min_rtt_us, Some(21));
        assert_eq!(i.total_rto_time_ms, Some(77));
    }

    #[test]
    fn short_struct_gates_fields() {
        // e.g. a kernel whose tcp_info ends after tcpi_delivery_rate (168 bytes)
        let mut b = vec![0u8; 168];
        put64(&mut b, 160, 999);
        let i = decode(&b).expect("decode");
        assert_eq!(i.delivery_rate, Some(999));
        assert_eq!(i.busy_time_us, None);
        assert_eq!(i.bytes_sent, None);
        assert_eq!(i.snd_wnd, None);
        assert!(decode(&b[..100]).is_none());
    }
}
