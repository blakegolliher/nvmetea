//! Passive capability discovery (`nvmetea probe`, steps 1–7 of
//! `docs/kernel-compatibility.md` §6.1). Nothing is loaded or attached: a probe
//! that passes every static check is reported `eligible`, not `supported`.

use crate::btf::{self, BtfIndex, BtfStrings};
use crate::catalog::{CATALOG, FIELDS, ProbeSpec, Target, vmlinux_functions};
use crate::symbols::{self, SymbolSet};
use nvmetea_core::quality::Reason;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const MODULES: &[&str] = &["nvme_core", "nvme_fabrics", "nvme_tcp"];

#[derive(Debug, Clone, Serialize)]
pub struct HostIdentity {
    pub hostname: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub os_id: Option<String>,
    pub kernel_release: Option<String>,
    pub kernel_version: Option<String>,
    pub arch: Option<String>,
    pub boot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Privileges {
    pub euid: u32,
    /// Relevant effective capabilities that are present.
    pub capabilities: Vec<&'static str>,
    pub missing_capabilities: Vec<&'static str>,
    pub unprivileged_bpf_disabled: Option<i64>,
    pub perf_event_paranoid: Option<i64>,
    pub kptr_restrict: Option<i64>,
    pub lockdown: Option<String>,
    pub selinux: Option<String>,
    pub bpf_jit_enable: Option<i64>,
    pub bpf_stats_enabled: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Avail {
    Present,
    Absent,
    Error(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleStatus {
    pub loaded: bool,
    pub btf: Avail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// All static prerequisites verified; not yet loaded/attached by this build.
    Eligible,
    Unavailable,
    /// Could not be checked (usually permissions).
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeCheck {
    pub id: &'static str,
    pub level: u8,
    pub target: String,
    pub provides: &'static str,
    pub fallback: &'static str,
    /// Tracepoints: raw_tp. Functions: fentry/fexit.
    pub btf_flavour: Status,
    /// Functions only: kprobe/kretprobe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kprobe_flavour: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldCheck {
    pub structure: &'static str,
    pub member: &'static str,
    pub btf: &'static str,
    pub optional: bool,
    /// `None`: the structure's BTF was not available.
    pub present: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Discovery {
    pub host: HostIdentity,
    pub privileges: Privileges,
    pub kernel_config: BTreeMap<String, String>,
    pub kernel_config_source: Option<String>,
    pub btf_vmlinux: Avail,
    pub modules: BTreeMap<String, ModuleStatus>,
    pub tracefs: Option<String>,
    pub tracefs_readable: bool,
    pub kallsyms: Avail,
    pub filter_functions: Avail,
    pub probes: Vec<ProbeCheck>,
    pub fields: Vec<FieldCheck>,
}

fn read_trim(p: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
fn read_i64(p: &str) -> Option<i64> {
    read_trim(p)?.parse().ok()
}

fn os_release() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(t) = read_trim("/etc/os-release") {
        for l in t.lines() {
            if let Some((k, v)) = l.split_once('=') {
                m.insert(k.to_string(), v.trim_matches('"').to_string());
            }
        }
    }
    m
}

pub fn host_identity() -> HostIdentity {
    let os = os_release();
    HostIdentity {
        hostname: read_trim("/proc/sys/kernel/hostname"),
        os_name: os.get("NAME").cloned(),
        os_version: os.get("VERSION").cloned(),
        os_id: os.get("ID").cloned(),
        kernel_release: read_trim("/proc/sys/kernel/osrelease"),
        kernel_version: read_trim("/proc/sys/kernel/version"),
        arch: Some(std::env::consts::ARCH.to_string()),
        boot_id: read_trim("/proc/sys/kernel/random/boot_id"),
    }
}

const CAPS: &[(u32, &str)] =
    &[(12, "CAP_NET_ADMIN"), (21, "CAP_SYS_ADMIN"), (34, "CAP_SYSLOG"), (38, "CAP_PERFMON"), (39, "CAP_BPF")];

pub fn privileges() -> Privileges {
    let status = read_trim("/proc/self/status").unwrap_or_default();
    let eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|h| u64::from_str_radix(h.trim(), 16).ok())
        .unwrap_or(0);
    let mut have: Vec<&'static str> = Vec::new();
    let mut miss: Vec<&'static str> = Vec::new();
    for &(bit, name) in CAPS {
        if eff & (1u64 << bit) != 0 { have.push(name) } else { miss.push(name) }
    }
    let lockdown = read_trim("/sys/kernel/security/lockdown").map(|s| {
        s.split_whitespace().find(|w| w.starts_with('[')).map(|w| w.trim_matches(['[', ']']).to_string()).unwrap_or(s)
    });
    let selinux = match read_trim("/sys/fs/selinux/enforce").as_deref() {
        Some("1") => Some("enforcing".into()),
        Some("0") => Some("permissive".into()),
        _ => Some("disabled or not mounted".into()),
    };
    Privileges {
        // SAFETY: geteuid has no preconditions.
        euid: unsafe { libc::geteuid() },
        capabilities: have,
        missing_capabilities: miss,
        unprivileged_bpf_disabled: read_i64("/proc/sys/kernel/unprivileged_bpf_disabled"),
        perf_event_paranoid: read_i64("/proc/sys/kernel/perf_event_paranoid"),
        kptr_restrict: read_i64("/proc/sys/kernel/kptr_restrict"),
        lockdown,
        selinux,
        bpf_jit_enable: read_i64("/proc/sys/net/core/bpf_jit_enable"),
        bpf_stats_enabled: read_i64("/proc/sys/kernel/bpf_stats_enabled"),
    }
}

const CONFIG_KEYS: &[&str] = &[
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_DEBUG_INFO_BTF_MODULES",
    "CONFIG_BPF_EVENTS",
    "CONFIG_KPROBES",
    "CONFIG_KPROBE_EVENTS",
    "CONFIG_FPROBE",
    "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS",
    "CONFIG_FUNCTION_TRACER",
    "CONFIG_NVME_TCP",
    "CONFIG_NVME_TCP_TLS",
    "CONFIG_NVME_MULTIPATH",
    "CONFIG_INET_DIAG",
    "CONFIG_INET_TCP_DIAG",
];

fn kernel_config(release: Option<&str>) -> (BTreeMap<String, String>, Option<String>) {
    let mut m = BTreeMap::new();
    let Some(rel) = release else { return (m, None) };
    for p in [format!("/boot/config-{rel}"), format!("/lib/modules/{rel}/config")] {
        if let Ok(t) = std::fs::read_to_string(&p) {
            for l in t.lines() {
                if let Some((k, v)) = l.split_once('=') {
                    if CONFIG_KEYS.contains(&k) {
                        m.insert(k.to_string(), v.to_string());
                    }
                } else if let Some(k) = l.strip_prefix("# ").and_then(|r| r.strip_suffix(" is not set")) {
                    if CONFIG_KEYS.contains(&k) {
                        m.insert(k.to_string(), "n".into());
                    }
                }
            }
            return (m, Some(p));
        }
    }
    (m, None)
}

fn tracefs_dir() -> Option<PathBuf> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.join("events").exists() || p.exists())
}

struct Ctx {
    vm: Option<BtfIndex>,
    mods: BTreeMap<&'static str, (bool, Option<BtfIndex>, Avail)>,
    kallsyms: Option<SymbolSet>,
    ftrace: Option<SymbolSet>,
    tracefs_events: Option<PathBuf>,
}

fn btf_of<'a>(ctx: &'a Ctx, module: &str) -> Option<&'a BtfIndex> {
    if module.is_empty() { ctx.vm.as_ref() } else { ctx.mods.get(module).and_then(|m| m.1.as_ref()) }
}

fn check_tracepoint(ctx: &Ctx, system: &str, name: &str, btf_module: &str) -> (Status, Option<Reason>, String) {
    if !btf_module.is_empty() && !ctx.mods.get(btf_module).is_some_and(|m| m.0) {
        return (Status::Unavailable, Some(Reason::ModuleNotLoaded), format!("module {btf_module} not loaded"));
    }
    let Some(b) = btf_of(ctx, btf_module) else {
        let r = if btf_module.is_empty() { Reason::BtfVmlinuxMissing } else { Reason::BtfModuleMissing };
        return (Status::Unknown, Some(r), "no BTF to check; text tracepoint may still exist".into());
    };
    if !b.has_tracepoint(name) {
        return (Status::Unavailable, Some(Reason::MissingInterface), format!("no btf_trace_{name} in BTF"));
    }
    let mut detail = format!("btf_trace_{name} present");
    if let Some(ev) = &ctx.tracefs_events {
        if ev.join(system).join(name).exists() {
            detail.push_str("; tracefs event present");
        } else if ev.join(system).exists() {
            detail.push_str("; tracefs event MISSING");
        }
    }
    (Status::Eligible, None, detail)
}

fn check_function(ctx: &Ctx, module: &str, name: &str) -> (Status, Option<Status>, Option<Reason>, String) {
    let mod_label = if module.is_empty() { "vmlinux" } else { module };
    if !module.is_empty() && !ctx.mods.get(module).is_some_and(|m| m.0) {
        return (
            Status::Unavailable,
            Some(Status::Unavailable),
            Some(Reason::ModuleNotLoaded),
            format!("module {module} not loaded"),
        );
    }
    let in_btf = btf_of(ctx, module).map(|b| b.has_func(name));
    let (in_sym, clones) = match &ctx.kallsyms {
        Some(s) => (Some(s.has(module, name)), s.clones(module, name)),
        None => (None, Vec::new()),
    };
    let in_ftrace = ctx.ftrace.as_ref().map(|s| s.has(module, name));
    let mut d = vec![
        format!("BTF FUNC: {}", in_btf.map_or("unknown", |b| if b { "yes" } else { "no" })),
        format!("kallsyms[{mod_label}]: {}", in_sym.map_or("unknown", |b| if b { "yes" } else { "no" })),
        format!("ftrace: {}", in_ftrace.map_or("unknown (needs root)", |b| if b { "yes" } else { "no" })),
    ];
    if !clones.is_empty() {
        d.push(format!("clones: {}", clones.join(",")));
    }
    let detail = d.join("; ");
    // Rule F4: exact text symbol required for both flavours.
    match in_sym {
        Some(false) => {
            let r = if clones.is_empty() {
                if in_btf == Some(true) { Reason::Inlined } else { Reason::MissingInterface }
            } else {
                Reason::UnsafeClone
            };
            return (Status::Unavailable, Some(Status::Unavailable), Some(r), detail);
        }
        None => return (Status::Unknown, Some(Status::Unknown), Some(Reason::PermissionDenied), detail),
        Some(true) => {}
    }
    let kprobe = Status::Eligible;
    let fentry = match (in_btf, in_ftrace) {
        (Some(false), _) | (None, _) => (
            Status::Unavailable,
            Some(if module.is_empty() { Reason::BtfVmlinuxMissing } else { Reason::BtfModuleMissing }),
        ),
        (Some(true), Some(true)) => (Status::Eligible, None),
        (Some(true), Some(false)) => (Status::Unavailable, Some(Reason::MissingInterface)),
        (Some(true), None) => (Status::Unknown, Some(Reason::PermissionDenied)),
    };
    let reason = fentry.1;
    (fentry.0, Some(kprobe), reason, detail)
}

pub fn discover(proc_root: &Path) -> Discovery {
    let host = host_identity();
    let privileges = privileges();
    let (kernel_config, kernel_config_source) = kernel_config(host.kernel_release.as_deref());

    let want_vm: Vec<&str> = FIELDS.iter().filter(|f| f.2.is_empty()).map(|f| f.0).chain(["bpf_iter__tcp"]).collect();
    let (vm, vm_strings, btf_vmlinux) = match std::fs::read("/sys/kernel/btf/vmlinux") {
        Ok(d) => match btf::parse(&d, None, &want_vm) {
            Ok((i, s)) => (Some(i), Some(s), Avail::Present),
            Err(e) => (None, None, Avail::Error(e.to_string())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None, Avail::Absent),
        Err(e) => (None, None, Avail::Error(e.to_string())),
    };
    let base: Option<BtfStrings> = vm_strings.map(|s| s.as_base());
    let mut mods = BTreeMap::new();
    for &m in MODULES {
        let loaded = Path::new("/sys/module").join(m).exists();
        let want: Vec<&str> = FIELDS.iter().filter(|f| f.2 == m).map(|f| f.0).collect();
        let (idx, avail) = match (std::fs::read(Path::new("/sys/kernel/btf").join(m)), &base) {
            (Ok(d), Some(b)) => match btf::parse(&d, Some(b), &want) {
                Ok((i, _)) => (Some(i), Avail::Present),
                Err(e) => (None, Avail::Error(e.to_string())),
            },
            (Ok(_), None) => (None, Avail::Error("vmlinux BTF unavailable as base".into())),
            (Err(e), _) if e.kind() == std::io::ErrorKind::NotFound => (None, Avail::Absent),
            (Err(e), _) => (None, Avail::Error(e.to_string())),
        };
        mods.insert(m, (loaded, idx, avail));
    }

    let vm_wanted: BTreeSet<String> = vmlinux_functions().into_iter().map(String::from).collect();
    let (kallsyms, kallsyms_avail) = match symbols::read_kallsyms(proc_root, MODULES, &vm_wanted) {
        Ok(s) => (Some(s), Avail::Present),
        Err(e) => (None, Avail::Error(e.to_string())),
    };
    let (ftrace, filter_functions) = match symbols::read_filter_functions(MODULES, &vm_wanted) {
        Ok(s) => (Some(s), Avail::Present),
        Err(e) => (None, Avail::Error(e.to_string())),
    };
    let tracefs = tracefs_dir();
    let events = tracefs.as_ref().map(|t| t.join("events")).filter(|e| std::fs::read_dir(e).is_ok());
    let tracefs_readable = events.is_some();
    let ctx = Ctx { vm, mods, kallsyms, ftrace, tracefs_events: events };

    let probes = CATALOG.iter().map(|p| evaluate(&ctx, p)).collect();
    let fields = FIELDS
        .iter()
        .map(|&(s, m, b, optional)| FieldCheck {
            structure: s,
            member: m,
            btf: if b.is_empty() { "vmlinux" } else { b },
            optional,
            present: btf_of(&ctx, b).and_then(|i| i.struct_has(s, m)),
        })
        .collect();
    let modules = ctx
        .mods
        .iter()
        .map(|(k, (loaded, _, avail))| (k.to_string(), ModuleStatus { loaded: *loaded, btf: avail.clone() }))
        .collect();
    Discovery {
        host,
        privileges,
        kernel_config,
        kernel_config_source,
        btf_vmlinux,
        modules,
        tracefs: tracefs.map(|p| p.display().to_string()),
        tracefs_readable,
        kallsyms: kallsyms_avail,
        filter_functions,
        probes,
        fields,
    }
}

fn evaluate(ctx: &Ctx, p: &ProbeSpec) -> ProbeCheck {
    let (target, btf_flavour, kprobe_flavour, reason, detail) = match p.target {
        Target::Tracepoint { system, name, btf_module } => {
            let (s, r, d) = check_tracepoint(ctx, system, name, btf_module);
            (format!("tracepoint {system}:{name}"), s, None, r, d)
        }
        Target::Function { module, name } => {
            let (f, k, r, d) = check_function(ctx, module, name);
            let m = if module.is_empty() { "vmlinux" } else { module };
            (format!("{m}:{name}"), f, k, r, d)
        }
        Target::Iterator { name } => match ctx.vm.as_ref() {
            Some(v) if v.structs.contains_key(&format!("bpf_iter__{name}")) => {
                (format!("iter/{name}"), Status::Eligible, None, None, format!("struct bpf_iter__{name} present"))
            }
            Some(_) => (
                format!("iter/{name}"),
                Status::Unavailable,
                None,
                Some(Reason::MissingInterface),
                "iterator target not in BTF".into(),
            ),
            None => (
                format!("iter/{name}"),
                Status::Unknown,
                None,
                Some(Reason::BtfVmlinuxMissing),
                "no vmlinux BTF".into(),
            ),
        },
    };
    ProbeCheck {
        id: p.id,
        level: p.level,
        target,
        provides: p.provides,
        fallback: p.fallback,
        btf_flavour,
        kprobe_flavour,
        reason,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(btf_funcs: &[&str], syms: &[&str], ftrace: Option<&[&str]>) -> Ctx {
        let b = BtfIndex { funcs: btf_funcs.iter().map(|s| s.to_string()).collect(), ..Default::default() };
        let mut mods = BTreeMap::new();
        mods.insert("nvme_tcp", (true, Some(b), Avail::Present));
        mods.insert("nvme_core", (false, None, Avail::Absent));
        let mut ks = SymbolSet::default();
        ks.by_module.insert("nvme_tcp".into(), syms.iter().map(|s| s.to_string()).collect());
        let ft = ftrace.map(|f| {
            let mut s = SymbolSet::default();
            s.by_module.insert("nvme_tcp".into(), f.iter().map(|x| x.to_string()).collect());
            s
        });
        Ctx { vm: None, mods, kallsyms: Some(ks), ftrace: ft, tracefs_events: None }
    }

    #[test]
    fn rule_f4_exact_symbol_btf_and_ftrace() {
        let c = ctx(&["nvme_tcp_io_work"], &["nvme_tcp_io_work"], Some(&["nvme_tcp_io_work"]));
        let (f, k, r, _) = check_function(&c, "nvme_tcp", "nvme_tcp_io_work");
        assert_eq!((f, k, r), (Status::Eligible, Some(Status::Eligible), None));
    }

    #[test]
    fn rule_f4_constprop_clone_is_unsafe() {
        // Rocky 9.8: BTF names nvme_tcp_handle_r2t but only the .constprop.0 symbol exists
        let c = ctx(&["nvme_tcp_handle_r2t"], &["nvme_tcp_handle_r2t.constprop.0"], Some(&[]));
        let (f, k, r, d) = check_function(&c, "nvme_tcp", "nvme_tcp_handle_r2t");
        assert_eq!((f, k, r), (Status::Unavailable, Some(Status::Unavailable), Some(Reason::UnsafeClone)));
        assert!(d.contains("constprop"));
    }

    #[test]
    fn rule_f4_inlined_and_missing() {
        // el9 6.12: nvme_tcp_recv_pdu is in BTF but has no symbol (inlined)
        let c = ctx(&["nvme_tcp_recv_pdu"], &[], Some(&[]));
        assert_eq!(check_function(&c, "nvme_tcp", "nvme_tcp_recv_pdu").2, Some(Reason::Inlined));
        assert_eq!(check_function(&c, "nvme_tcp", "nvme_tcp_nonexistent").2, Some(Reason::MissingInterface));
        assert_eq!(check_function(&c, "nvme_core", "nvme_failover_req").2, Some(Reason::ModuleNotLoaded));
    }

    #[test]
    fn rule_f4_without_root_fentry_is_unknown_kprobe_eligible() {
        let c = ctx(&["nvme_tcp_io_work"], &["nvme_tcp_io_work"], None);
        let (f, k, r, _) = check_function(&c, "nvme_tcp", "nvme_tcp_io_work");
        assert_eq!((f, k, r), (Status::Unknown, Some(Status::Eligible), Some(Reason::PermissionDenied)));
        // not traceable by ftrace (notrace) → fentry unavailable, kprobe still possible
        let c = ctx(&["nvme_tcp_io_work"], &["nvme_tcp_io_work"], Some(&[]));
        assert_eq!(check_function(&c, "nvme_tcp", "nvme_tcp_io_work").0, Status::Unavailable);
    }
}
