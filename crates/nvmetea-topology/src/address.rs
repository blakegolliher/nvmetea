//! Parsing of the controller `address` attribute and endpoint normalisation.

use nvmetea_core::model::FabricAddress;
use std::net::{IpAddr, Ipv6Addr};

/// `traddr=192.0.2.1,trsvcid=4420,src_addr=198.51.100.95` → fields.
/// PCIe controllers expose a PCI BDF (`0000:03:00.0`), kept as `raw` only.
pub fn parse_address(raw: &str) -> FabricAddress {
    let mut a = FabricAddress { raw: raw.to_string(), ..Default::default() };
    if !raw.contains('=') {
        return a;
    }
    for part in raw.split(',') {
        let Some((k, v)) = part.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim().to_string());
        match k {
            "traddr" => a.traddr = Some(v),
            "trsvcid" => a.trsvcid = Some(v),
            "host_traddr" => a.host_traddr = Some(v),
            "host_iface" => a.host_iface = Some(v),
            "src_addr" => a.src_addr = Some(v),
            _ => {
                a.extra.insert(k.to_string(), v);
            }
        }
    }
    a
}

/// Parse an IP address as sysfs prints it (IPv6 possibly bracketed or with a
/// `%scope`), normalising IPv4-mapped IPv6 to IPv4.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    let s = s.split('%').next().unwrap_or(s);
    let ip: IpAddr = s.parse().ok()?;
    Some(normalize_ip(ip))
}

pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match to_ipv4_mapped(&v6) {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn to_ipv4_mapped(v6: &Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let o = v6.octets();
    if o[..10].iter().all(|&b| b == 0) && o[10] == 0xff && o[11] == 0xff {
        Some(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_address() {
        let a = parse_address("traddr=192.0.2.1,trsvcid=4420,src_addr=198.51.100.95");
        assert_eq!(a.traddr.as_deref(), Some("192.0.2.1"));
        assert_eq!(a.trsvcid.as_deref(), Some("4420"));
        assert_eq!(a.src_addr.as_deref(), Some("198.51.100.95"));
        assert!(a.extra.is_empty());
    }

    #[test]
    fn host_fields_and_unknown_keys() {
        let a = parse_address("traddr=fe80::1%eth0,trsvcid=4421,host_traddr=fe80::2,host_iface=eth0,future=x");
        assert_eq!(a.host_iface.as_deref(), Some("eth0"));
        assert_eq!(a.extra.get("future").map(String::as_str), Some("x"));
        assert_eq!(parse_ip(a.traddr.as_deref().unwrap_or_default()), "fe80::1".parse().ok());
    }

    #[test]
    fn pcie_bdf_is_raw_only() {
        let a = parse_address("0000:03:00.0");
        assert_eq!(a.raw, "0000:03:00.0");
        assert!(a.traddr.is_none());
    }

    #[test]
    fn ip_normalisation() {
        assert_eq!(parse_ip("::ffff:10.0.0.1"), "10.0.0.1".parse().ok());
        assert_eq!(parse_ip("[2001:db8::1]"), "2001:db8::1".parse().ok());
        assert_eq!(parse_ip("not-an-ip"), None);
    }
}
