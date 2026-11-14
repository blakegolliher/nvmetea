//! Data-quality classification carried by every exported metric.
//!
//! See `docs/latency-model.md` §7. An unavailable value is `None` with a
//! [`Reason`]; it is never replaced by zero.

use serde::Serialize;

/// How a value was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    /// A counter or interval taken directly from an observed kernel event or counter.
    Measured,
    /// Arithmetic over measured values under a stated model (rates, sums, means).
    Derived,
    /// Uses heuristic or non-specific evidence.
    Estimated,
    /// Not observable here; see the accompanying reason.
    Unavailable,
}

/// Stable reason codes (`docs/kernel-compatibility.md` §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    MissingInterface,
    NotSupportedByController,
    PermissionDenied,
    KernelLockdown,
    BtfVmlinuxMissing,
    BtfModuleMissing,
    ModuleNotLoaded,
    Inlined,
    UnsafeClone,
    DependencyUnavailable,
    DisabledByUser,
    /// The feature exists in the design but is not implemented in this build.
    NotImplemented,
    /// First sample: no previous value to difference against.
    FirstInterval,
    /// A cumulative counter went backwards or its identity changed.
    CounterReset,
    /// No events in the interval, so a per-event mean is undefined.
    NoSamples,
    /// More than one entity matches; attribution would be a guess.
    Ambiguous,
    InetDiagUnavailable,
    ParseError,
    /// The BPF verifier rejected a program.
    VerifierRejected,
    /// A CO-RE relocation found no matching type/field in the kernel's BTF.
    BtfMismatch,
    /// Load succeeded but attaching failed.
    AttachFailed,
    /// Not a TCP controller, or otherwise outside nvmetea's scope.
    NotApplicable,
    /// The connection closed during the interval; its live state is gone.
    ConnectionClosed,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::MissingInterface => "missing_interface",
            Reason::NotSupportedByController => "not_supported_by_controller",
            Reason::PermissionDenied => "permission_denied",
            Reason::KernelLockdown => "kernel_lockdown",
            Reason::BtfVmlinuxMissing => "btf_vmlinux_missing",
            Reason::BtfModuleMissing => "btf_module_missing",
            Reason::ModuleNotLoaded => "module_not_loaded",
            Reason::Inlined => "inlined",
            Reason::UnsafeClone => "unsafe_clone",
            Reason::DependencyUnavailable => "dependency_unavailable",
            Reason::DisabledByUser => "disabled_by_user",
            Reason::NotImplemented => "not_implemented",
            Reason::FirstInterval => "first_interval",
            Reason::CounterReset => "counter_reset",
            Reason::NoSamples => "no_samples",
            Reason::Ambiguous => "ambiguous",
            Reason::InetDiagUnavailable => "inet_diag_unavailable",
            Reason::ParseError => "parse_error",
            Reason::VerifierRejected => "verifier_rejected",
            Reason::BtfMismatch => "btf_mismatch",
            Reason::AttachFailed => "attach_failed",
            Reason::NotApplicable => "not_applicable",
            Reason::ConnectionClosed => "connection_closed",
        }
    }

    /// One-line explanation and remediation for humans.
    pub fn remediation(self) -> &'static str {
        match self {
            Reason::MissingInterface => "the kernel or target does not expose this interface",
            Reason::NotSupportedByController => "the controller does not report this (e.g. no ANA support)",
            Reason::PermissionDenied => {
                "run as root, or grant CAP_BPF, CAP_PERFMON and CAP_SYS_ADMIN (module BTF), +CAP_SYSLOG for symbol checks"
            }
            Reason::KernelLockdown => {
                "kernel lockdown (confidentiality) blocks tracing; only passive monitoring is possible"
            }
            Reason::BtfVmlinuxMissing => "kernel built without CONFIG_DEBUG_INFO_BTF; BPF CO-RE collectors cannot run",
            Reason::BtfModuleMissing => {
                "the module carries no BTF (often an out-of-tree/DKMS build); driver-stage timing disabled"
            }
            Reason::ModuleNotLoaded => "the kernel module is not loaded (no controllers of this kind yet?)",
            Reason::Inlined => "the compiler inlined this function in this kernel build; a fallback is used",
            Reason::UnsafeClone => "only a compiler clone (.constprop/.isra) exists; it is never probed by argument",
            Reason::DependencyUnavailable => "a prerequisite collector or probe is unavailable",
            Reason::DisabledByUser => "disabled by option",
            Reason::NotImplemented => "not implemented in this build of nvmetea yet",
            Reason::FirstInterval => "needs two samples; available from the next interval",
            Reason::CounterReset => "counter reset or identity change in this interval",
            Reason::NoSamples => "no operations in this interval",
            Reason::Ambiguous => "several candidates match; attribution would be a guess",
            Reason::InetDiagUnavailable => {
                "socket diagnostics (inet_diag/tcp_diag) unavailable; RTT/congestion metrics disabled"
            }
            Reason::ParseError => "unexpected kernel data; see issues",
            Reason::VerifierRejected => {
                "the BPF verifier rejected a program on this kernel (log in `nvmetea probe --load`)"
            }
            Reason::BtfMismatch => "a kernel type or field nvmetea needs is missing from this kernel's BTF",
            Reason::AttachFailed => "a BPF program loaded but could not be attached",
            Reason::NotApplicable => "not applicable to this entity",
            Reason::ConnectionClosed => "the connection closed during the interval; see its events",
        }
    }
}

/// A value together with its classification and provenance.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Obs<T> {
    pub value: Option<T>,
    pub quality: Quality,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub sources: &'static [&'static str],
}

impl<T> Obs<T> {
    pub fn measured(value: T, sources: &'static [&'static str]) -> Self {
        Obs { value: Some(value), quality: Quality::Measured, reason: None, sources }
    }
    pub fn derived(value: T, sources: &'static [&'static str]) -> Self {
        Obs { value: Some(value), quality: Quality::Derived, reason: None, sources }
    }
    pub fn estimated(value: T, sources: &'static [&'static str]) -> Self {
        Obs { value: Some(value), quality: Quality::Estimated, reason: None, sources }
    }
    pub fn unavailable(reason: Reason) -> Self {
        Obs { value: None, quality: Quality::Unavailable, reason: Some(reason), sources: &[] }
    }
    pub fn is_available(&self) -> bool {
        self.value.is_some()
    }
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Obs<U> {
        Obs { value: self.value.map(f), quality: self.quality, reason: self.reason, sources: self.sources }
    }
    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

impl<T: Copy> Obs<T> {
    pub fn copied(&self) -> Option<T> {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_serializes_null_with_reason() {
        let o: Obs<f64> = Obs::unavailable(Reason::FirstInterval);
        let j = serde_json::to_value(&o).expect("serialize");
        assert!(j["value"].is_null());
        assert_eq!(j["quality"], "unavailable");
        assert_eq!(j["reason"], "first_interval");
    }

    #[test]
    fn measured_keeps_sources() {
        let o = Obs::measured(5u64, &["sysfs"]);
        let j = serde_json::to_value(&o).expect("serialize");
        assert_eq!(j["value"], 5);
        assert_eq!(j["sources"][0], "sysfs");
        assert!(j.get("reason").is_none());
    }
}
