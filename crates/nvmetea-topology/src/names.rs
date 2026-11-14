//! Strict parsers for kernel device names. Names that do not match are ignored,
//! so unexpected sysfs entries (partitions, `ng*` char devices, `power`, …) are
//! never treated as NVMe objects and never used to build paths.

fn digits(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 9 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `nvme12` → 12
pub fn ctrl(name: &str) -> Option<u32> {
    digits(name.strip_prefix("nvme")?)
}

/// `nvme-subsys3` → 3
pub fn subsys(name: &str) -> Option<u32> {
    digits(name.strip_prefix("nvme-subsys")?)
}

/// `nvme2n1` → (2, 1): a multipath head or a direct namespace.
pub fn namespace(name: &str) -> Option<(u32, u32)> {
    let rest = name.strip_prefix("nvme")?;
    let (a, b) = rest.split_once('n')?;
    Some((digits(a)?, digits(b)?))
}

/// `nvme2c3n1` → (2, 3, 1): subsystem instance, controller instance, namespace index.
pub fn path(name: &str) -> Option<(u32, u32, u32)> {
    let rest = name.strip_prefix("nvme")?;
    let (s, rest) = rest.split_once('c')?;
    let (c, n) = rest.split_once('n')?;
    Some((digits(s)?, digits(c)?, digits(n)?))
}

/// Any whole NVMe block device name (head, direct namespace or path).
pub fn is_nvme_block(name: &str) -> bool {
    namespace(name).is_some() || path(name).is_some()
}

/// Sort key that orders `nvme2` before `nvme10`.
pub fn natural_key(name: &str) -> (String, Vec<u32>) {
    let mut prefix = String::new();
    let mut nums = Vec::new();
    let mut cur = String::new();
    for ch in name.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else {
            if !cur.is_empty() {
                nums.push(cur.parse().unwrap_or(u32::MAX));
                cur.clear();
            }
            if nums.is_empty() {
                prefix.push(ch);
            }
        }
    }
    if !cur.is_empty() {
        nums.push(cur.parse().unwrap_or(u32::MAX));
    }
    (prefix, nums)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers() {
        assert_eq!(ctrl("nvme0"), Some(0));
        assert_eq!(ctrl("nvme12"), Some(12));
        assert_eq!(ctrl("nvme"), None);
        assert_eq!(ctrl("nvme1n1"), None);
        assert_eq!(ctrl("nvme-subsys1"), None);
        assert_eq!(subsys("nvme-subsys7"), Some(7));
        assert_eq!(namespace("nvme2n10"), Some((2, 10)));
        assert_eq!(namespace("nvme0n1p1"), None);
        assert_eq!(namespace("ng2n1"), None);
        assert_eq!(namespace("nvme2c3n1"), None);
        assert_eq!(path("nvme2c3n1"), Some((2, 3, 1)));
        assert_eq!(path("nvme2c3n"), None);
        assert_eq!(path("nvme2n1"), None);
        assert_eq!(path("nvme2c3n1/../../etc"), None);
        assert!(is_nvme_block("nvme0n1"));
        assert!(!is_nvme_block("sda"));
    }

    #[test]
    fn natural_order() {
        let mut v = vec!["nvme10", "nvme2", "nvme2c10n1", "nvme2c2n1", "nvme1"];
        v.sort_by_key(|s| natural_key(s));
        assert_eq!(v, ["nvme1", "nvme2", "nvme2c2n1", "nvme2c10n1", "nvme10"]);
    }
}
