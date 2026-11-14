//! Minimal BTF reader: function names, typedef names and selected struct member
//! names, for vmlinux and split (module) BTF. Used for capability discovery
//! without libbpf. `/sys/kernel/btf/*` is world-readable, so this works
//! unprivileged.

use std::collections::{BTreeMap, BTreeSet};

const BTF_MAGIC: u16 = 0xeb9f;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfError {
    Truncated(&'static str),
    BadMagic(u16),
    UnknownKind(u32),
}

impl std::fmt::Display for BtfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BtfError::Truncated(w) => write!(f, "truncated BTF ({w})"),
            BtfError::BadMagic(m) => write!(f, "bad BTF magic {m:#x} (big-endian BTF is not supported)"),
            BtfError::UnknownKind(k) => write!(f, "unknown BTF kind {k}"),
        }
    }
}

impl std::error::Error for BtfError {}

/// String section of a BTF blob, plus the base's strings for split BTF, and
/// the number of types that precede this blob's first type id.
#[derive(Debug, Clone, Default)]
pub struct BtfStrings {
    base: Vec<u8>,
    own: Vec<u8>,
    base_types: u32,
    own_types: u32,
}

impl BtfStrings {
    fn get(&self, off: u32) -> Option<&str> {
        let off = off as usize;
        let (buf, o) = if off < self.base.len() { (&self.base, off) } else { (&self.own, off - self.base.len()) };
        let s = buf.get(o..)?;
        let end = s.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&s[..end]).ok()
    }
    /// The base to pass when parsing a split (module) BTF on top of this one.
    pub fn as_base(&self) -> BtfStrings {
        let mut b = self.base.clone();
        b.extend_from_slice(&self.own);
        BtfStrings { base: b, own: Vec::new(), base_types: self.base_types + self.own_types, own_types: 0 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BtfIndex {
    pub funcs: BTreeSet<String>,
    pub typedefs: BTreeSet<String>,
    /// Member names of the requested structs, including members reached through
    /// anonymous struct/union members (as CO-RE field access resolves them).
    pub structs: BTreeMap<String, BTreeSet<String>>,
    pub types: usize,
}

impl BtfIndex {
    pub fn has_func(&self, n: &str) -> bool {
        self.funcs.contains(n)
    }
    pub fn has_tracepoint(&self, tp: &str) -> bool {
        self.typedefs.contains(&format!("btf_trace_{tp}"))
    }
    /// `None` when the struct is not described in this BTF.
    pub fn struct_has(&self, s: &str, member: &str) -> Option<bool> {
        self.structs.get(s).map(|m| m.contains(member))
    }
}

struct Rd<'a> {
    b: &'a [u8],
}

impl Rd<'_> {
    fn u16(&self, o: usize) -> Result<u16, BtfError> {
        self.b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(BtfError::Truncated("u16"))
    }
    fn u32(&self, o: usize) -> Result<u32, BtfError> {
        self.b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(BtfError::Truncated("u32"))
    }
}

#[derive(Clone, Copy)]
struct Rec {
    kind: u32,
    name_off: u32,
    vlen: usize,
    /// Offset of the kind-specific data that follows the 12-byte header.
    data: usize,
}

/// Parse a BTF blob. `base` is the vmlinux table when `data` is module (split)
/// BTF. Member names are collected only for `want_structs`.
pub fn parse(
    data: &[u8],
    base: Option<&BtfStrings>,
    want_structs: &[&str],
) -> Result<(BtfIndex, BtfStrings), BtfError> {
    let r = Rd { b: data };
    let magic = r.u16(0)?;
    if magic != BTF_MAGIC {
        return Err(BtfError::BadMagic(magic));
    }
    let hdr_len = r.u32(4)? as usize;
    let type_off = r.u32(8)? as usize;
    let type_len = r.u32(12)? as usize;
    let str_off = r.u32(16)? as usize;
    let str_len = r.u32(20)? as usize;
    let ts = hdr_len.checked_add(type_off).ok_or(BtfError::Truncated("type_off"))?;
    let te = ts.checked_add(type_len).ok_or(BtfError::Truncated("type_len"))?;
    let ss = hdr_len.checked_add(str_off).ok_or(BtfError::Truncated("str_off"))?;
    let se = ss.checked_add(str_len).ok_or(BtfError::Truncated("str_len"))?;
    if te > data.len() || se > data.len() {
        return Err(BtfError::Truncated("sections"));
    }
    let base_types = base.map(|b| b.base_types).unwrap_or(0);
    let mut strings = BtfStrings {
        base: base.map(|b| b.base.clone()).unwrap_or_default(),
        own: data[ss..se].to_vec(),
        base_types,
        own_types: 0,
    };

    // Pass 1: type records (type id = base_types + 1 + index).
    let mut recs: Vec<Rec> = Vec::new();
    let mut o = ts;
    while o < te {
        let name_off = r.u32(o)?;
        let info = r.u32(o + 4)?;
        let vlen = (info & 0xffff) as usize;
        let kind = (info >> 24) & 0x1f;
        let data_off = o + 12;
        let extra = match kind {
            1 => 4, // INT
            2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
            3 => 12,            // ARRAY
            4 | 5 => 12 * vlen, // STRUCT / UNION
            6 => 8 * vlen,      // ENUM
            13 => 8 * vlen,     // FUNC_PROTO
            14 => 4,            // VAR
            15 => 12 * vlen,    // DATASEC
            17 => 4,            // DECL_TAG
            19 => 12 * vlen,    // ENUM64
            k => return Err(BtfError::UnknownKind(k)),
        };
        if data_off + extra > te {
            return Err(BtfError::Truncated("type record"));
        }
        recs.push(Rec { kind, name_off, vlen, data: data_off });
        o = data_off + extra;
    }
    strings.own_types = recs.len() as u32;

    // Pass 2: names.
    let mut idx = BtfIndex { types: recs.len(), ..Default::default() };
    let want: BTreeSet<&str> = want_structs.iter().copied().collect();
    for rec in &recs {
        match rec.kind {
            12 => {
                if let Some(n) = strings.get(rec.name_off) {
                    idx.funcs.insert(n.to_string());
                }
            }
            8 => {
                if let Some(n) = strings.get(rec.name_off) {
                    if n.starts_with("btf_trace_") {
                        idx.typedefs.insert(n.to_string());
                    }
                }
            }
            4 | 5 => {
                if let Some(n) = strings.get(rec.name_off) {
                    if want.contains(n) {
                        let mut set = idx.structs.remove(n).unwrap_or_default();
                        collect_members(&r, &recs, &strings, base_types, rec, &mut set, 0)?;
                        idx.structs.insert(n.to_string(), set);
                    }
                }
            }
            _ => {}
        }
    }
    Ok((idx, strings))
}

/// Member names of a struct/union, descending into anonymous struct/union
/// members defined in the same BTF blob.
fn collect_members(
    r: &Rd,
    recs: &[Rec],
    strings: &BtfStrings,
    base_types: u32,
    rec: &Rec,
    out: &mut BTreeSet<String>,
    depth: u32,
) -> Result<(), BtfError> {
    if depth > 8 {
        return Ok(());
    }
    for m in 0..rec.vlen {
        let mo = rec.data + 12 * m;
        let name_off = r.u32(mo)?;
        let ty = r.u32(mo + 4)?;
        match strings.get(name_off) {
            Some(n) if !n.is_empty() => {
                out.insert(n.to_string());
            }
            _ => {
                // anonymous member: resolve its type if it lives in this blob
                if ty > base_types {
                    if let Some(inner) = recs.get((ty - base_types - 1) as usize) {
                        if matches!(inner.kind, 4 | 5) {
                            collect_members(r, recs, strings, base_types, inner, out, depth + 1)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny BTF: INT, STRUCT foo {a,b}, FUNC_PROTO, FUNC bar, TYPEDEF btf_trace_baz.
    fn sample() -> Vec<u8> {
        let strs = b"\0int\0foo\0a\0b\0bar\0btf_trace_baz\0";
        let off = |s: &str| {
            let needle = format!("\0{s}\0");
            strs.windows(needle.len()).position(|w| w == needle.as_bytes()).map(|p| p as u32 + 1).expect("str")
        };
        let mut t = Vec::new();
        let ty = |t: &mut Vec<u8>, name: u32, kind: u32, vlen: u32, sz: u32| {
            t.extend_from_slice(&name.to_le_bytes());
            t.extend_from_slice(&((kind << 24) | vlen).to_le_bytes());
            t.extend_from_slice(&sz.to_le_bytes());
        };
        ty(&mut t, off("int"), 1, 0, 4);
        t.extend_from_slice(&0x20u32.to_le_bytes()); // INT encoding
        ty(&mut t, off("foo"), 4, 2, 8);
        for (m, bit) in [("a", 0u32), ("b", 32)] {
            t.extend_from_slice(&off(m).to_le_bytes());
            t.extend_from_slice(&1u32.to_le_bytes());
            t.extend_from_slice(&bit.to_le_bytes());
        }
        ty(&mut t, 0, 13, 0, 1); // FUNC_PROTO returning int, no params
        ty(&mut t, off("bar"), 12, 0, 3);
        ty(&mut t, off("btf_trace_baz"), 8, 0, 1);
        let mut b = Vec::new();
        b.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        b.push(1);
        b.push(0);
        b.extend_from_slice(&24u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(t.len() as u32).to_le_bytes());
        b.extend_from_slice(&(t.len() as u32).to_le_bytes());
        b.extend_from_slice(&(strs.len() as u32).to_le_bytes());
        b.extend_from_slice(&t);
        b.extend_from_slice(strs);
        b
    }

    #[test]
    fn parses_synthetic() {
        let (idx, _) = parse(&sample(), None, &["foo"]).expect("parse");
        assert_eq!(idx.types, 5);
        assert!(idx.has_func("bar"));
        assert!(idx.has_tracepoint("baz"));
        assert_eq!(idx.struct_has("foo", "b"), Some(true));
        assert_eq!(idx.struct_has("foo", "c"), Some(false));
        assert_eq!(idx.struct_has("nope", "a"), None);
    }

    #[test]
    fn anonymous_union_members_are_visible() {
        // [1] int; [2] union { int y; }; [3] struct outer { int x; union { ... }; }
        let strs = b"\0int\0y\0outer\0x\0";
        let ty = |t: &mut Vec<u8>, name: u32, kind: u32, vlen: u32, sz: u32| {
            t.extend_from_slice(&name.to_le_bytes());
            t.extend_from_slice(&((kind << 24) | vlen).to_le_bytes());
            t.extend_from_slice(&sz.to_le_bytes());
        };
        let mem = |t: &mut Vec<u8>, name: u32, typ: u32, off: u32| {
            t.extend_from_slice(&name.to_le_bytes());
            t.extend_from_slice(&typ.to_le_bytes());
            t.extend_from_slice(&off.to_le_bytes());
        };
        let mut t = Vec::new();
        ty(&mut t, 1, 1, 0, 4);
        t.extend_from_slice(&0x20u32.to_le_bytes());
        ty(&mut t, 0, 5, 1, 4); // anonymous union
        mem(&mut t, 5, 1, 0); // y
        ty(&mut t, 7, 4, 2, 8); // struct outer
        mem(&mut t, 13, 1, 0); // x
        mem(&mut t, 0, 2, 32); // anonymous member of type [2]
        let mut b = Vec::new();
        b.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        b.extend_from_slice(&[1, 0]);
        for v in [24u32, 0, t.len() as u32, t.len() as u32, strs.len() as u32] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&t);
        b.extend_from_slice(strs);
        let (idx, s) = parse(&b, None, &["outer"]).expect("parse");
        assert_eq!(idx.struct_has("outer", "x"), Some(true));
        assert_eq!(idx.struct_has("outer", "y"), Some(true));
        assert_eq!(s.as_base().base_types, 3);
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(parse(&[0x9f, 0xeb, 1, 0], None, &[]), Err(BtfError::Truncated(_))));
        assert!(matches!(parse(&[0u8; 4], None, &[]), Err(BtfError::BadMagic(0))));
        let mut b = sample();
        b[0] = 0;
        assert!(matches!(parse(&b, None, &[]), Err(BtfError::BadMagic(_))));
        let b = sample();
        assert!(parse(&b[..b.len() - 10], None, &[]).is_err());
    }

    #[test]
    fn running_kernel_btf_if_present() {
        let Ok(vm) = std::fs::read("/sys/kernel/btf/vmlinux") else { return };
        let (idx, strs) = parse(&vm, None, &["request", "sock_common", "sk_buff"]).expect("vmlinux BTF parses");
        assert_eq!(idx.struct_has("sk_buff", "tstamp"), Some(true));
        assert_eq!(idx.struct_has("sk_buff", "sk"), Some(true));
        assert!(idx.types > 10_000);
        assert!(idx.has_func("bpf_fentry_test1") || idx.has_func("schedule"));
        assert_eq!(idx.struct_has("request", "start_time_ns"), Some(true));
        assert_eq!(idx.struct_has("sock_common", "skc_cookie"), Some(true));
        if let Ok(m) = std::fs::read("/sys/kernel/btf/nvme_core") {
            let (midx, _) = parse(&m, Some(&strs.as_base()), &["nvme_request"]).expect("split BTF parses");
            assert!(midx.has_tracepoint("nvme_setup_cmd"));
            assert_eq!(midx.struct_has("nvme_request", "genctr"), Some(true));
        }
    }
}
