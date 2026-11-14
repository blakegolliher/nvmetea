//! `nvmetea.capture/1`: the JSON capture written by `nvmetea record` and read
//! by `nvmetea compare` (`docs/schema/capture-v1.md`).
//!
//! The capture has its own types instead of serialising internal model
//! structures, so the file format stays stable while the model evolves.
//! Readers refuse an unknown **major** version and ignore unknown fields.
//! Unavailable values are absent (`null` or missing), never 0.

use nvmetea_core::model::Histogram;
use nvmetea_core::model::nvme::HIST_USED;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: &str = "nvmetea.capture/1";
pub const MAJOR: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Host {
    pub hostname: Option<String>,
    pub boot_id: Option<String>,
    pub kernel_release: Option<String>,
    pub distribution: Option<String>,
    pub arch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub capability: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Identity of a controller across captures: subsystem NQN + fabric address.
/// `nvmeN` names are not stable across reboots or reconnects.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ControllerKey {
    pub subsysnqn: Option<String>,
    pub transport: Option<String>,
    pub traddr: Option<String>,
    pub trsvcid: Option<String>,
    pub host_traddr: Option<String>,
}

impl ControllerKey {
    pub fn label(&self) -> String {
        format!("{}:{}", self.traddr.as_deref().unwrap_or("?"), self.trsvcid.as_deref().unwrap_or("?"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureController {
    pub name: String,
    pub key: ControllerKey,
    pub state: String,
    #[serde(default)]
    pub generation: Option<u64>,
    #[serde(default)]
    pub epoch: Option<u64>,
    #[serde(default)]
    pub io_queues: Option<u32>,
    #[serde(default)]
    pub queue_depth: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturePath {
    pub name: String,
    pub controller: String,
    #[serde(default)]
    pub ana_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureNamespace {
    pub name: String,
    #[serde(default)]
    pub nsid: Option<u32>,
    #[serde(default)]
    pub wwid: Option<String>,
    pub paths: Vec<CapturePath>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureTopology {
    pub controllers: Vec<CaptureController>,
    pub namespaces: Vec<CaptureNamespace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureTransition {
    pub at_unix_s: f64,
    pub controller: String,
    /// e.g. "live -> resetting", "added (live)", "removed (was live)".
    pub change: String,
    pub source: String,
}

/// Rates of one controller over one interval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControllerRates {
    pub controller: String,
    pub state: String,
    pub read_iops: Option<f64>,
    pub write_iops: Option<f64>,
    pub read_bytes_per_s: Option<f64>,
    pub write_bytes_per_s: Option<f64>,
    /// Level 1 request latency means of the interval, µs.
    pub read_mean_us: Option<f64>,
    pub write_mean_us: Option<f64>,
    pub inflight: Option<i64>,
    pub tcp_rtt_median_us: Option<u32>,
    pub tcp_retrans_segments_per_s: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntervalSummary {
    /// Seconds since the capture start (end of the interval).
    pub t_s: f64,
    pub interval_s: f64,
    pub controllers: Vec<ControllerRates>,
}

/// A histogram as sparse (internal bucket index, count) pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseHist(pub Vec<(u16, u64)>);

impl SparseHist {
    pub fn from_hist(h: &Histogram) -> SparseHist {
        SparseHist(h.buckets.iter().enumerate().filter(|(_, c)| **c > 0).map(|(i, c)| (i as u16, *c)).collect())
    }
    pub fn to_hist(&self) -> Histogram {
        let mut h = Histogram::default();
        for (i, c) in &self.0 {
            if (*i as usize) < HIST_USED {
                h.buckets[*i as usize] += c;
            }
        }
        h
    }
}

/// Distribution of one value over a window: exact sum and count, histogram.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dist {
    pub count: u64,
    /// Exact sum (ns); absent when only the histogram is known.
    #[serde(default)]
    pub sum_ns: Option<u64>,
    pub hist: SparseHist,
}

impl Dist {
    pub fn mean_ns(&self) -> Option<f64> {
        match (self.sum_ns, self.count) {
            (Some(s), c) if c > 0 => Some(s as f64 / c as f64),
            _ => None,
        }
    }
    /// Percentile from the histogram (upper bucket edge, ns).
    pub fn percentile_ns(&self, p: f64) -> Option<u64> {
        self.hist.to_hist().percentile(p).map(|x| x.ns)
    }
}

/// Level 1 latency of one controller and op over the capture window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyGroup {
    pub controller: String,
    pub key: ControllerKey,
    pub op: String,
    /// "command", "request", "stage_a", "stage_e2".
    pub metric: String,
    pub dist: Dist,
}

/// Level 1 counters of one queue over the capture window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueWindow {
    pub controller: String,
    pub qid: u16,
    pub op: String,
    pub dispatched: u64,
    pub bytes: u64,
    pub completed: u64,
    pub nvme_errors: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControllerWindow {
    pub controller: String,
    pub key: ControllerKey,
    pub retries: u64,
    pub failovers: u64,
    pub requeues: u64,
    pub nvme_errors: u64,
    /// TCP retransmitted segments over the window (sock_diag), when known.
    #[serde(default)]
    pub tcp_retrans_segments: Option<u64>,
}

/// One stage of one profile group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageDist {
    pub stage: String,
    pub family: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<String>,
    pub dist: Dist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageGroup {
    /// `None` = all controllers.
    pub controller: Option<String>,
    pub key: Option<ControllerKey>,
    pub op: String,
    pub variant: String,
    /// floor(log2(bytes)).
    pub size_class: u32,
    pub complete: u64,
    pub partial: u64,
    pub excluded: u64,
    pub request: Dist,
    pub stages: Vec<StageDist>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageCapture {
    pub sample_every: u32,
    pub flavour: String,
    pub records: u64,
    pub sum_check_failures: u64,
    pub groups: Vec<StageGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureEvent {
    pub at_unix_s: f64,
    /// "slow", "state", "tcp", "timeout", "uevent".
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Quality {
    /// Level 1 collector counters over the window (lost events, untracked, mismatches…).
    #[serde(default)]
    pub level1: BTreeMap<String, u64>,
    /// Level 2 collector counters over the window, when profiling.
    #[serde(default)]
    pub level2: BTreeMap<String, u64>,
    /// Events not stored because the capture's event limit was reached.
    pub events_dropped: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Overhead {
    pub cpu_seconds: Option<f64>,
    pub max_rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capture {
    pub schema: String,
    pub tool: Tool,
    pub host: Host,
    /// Instrumentation behind each measured quantity, e.g.
    /// `request: "P1+P3 raw_tp"`. Two captures' stages are comparable only
    /// when these agree.
    pub boundary_signature: BTreeMap<String, String>,
    pub capabilities: Vec<CapabilityStatus>,
    #[serde(default)]
    pub filters: BTreeMap<String, String>,
    pub start_unix_s: f64,
    pub end_unix_s: f64,
    pub duration_s: f64,
    pub interval_s: f64,
    pub topology_start: CaptureTopology,
    pub topology_end: CaptureTopology,
    pub transitions: Vec<CaptureTransition>,
    pub intervals: Vec<IntervalSummary>,
    /// Level 1 latency over the whole window (end − start of cumulative histograms).
    pub latency: Vec<LatencyGroup>,
    pub queues: Vec<QueueWindow>,
    pub controllers: Vec<ControllerWindow>,
    #[serde(default)]
    pub stages: Option<StageCapture>,
    pub events: Vec<CaptureEvent>,
    pub quality: Quality,
    pub self_overhead: Overhead,
}

#[derive(Debug)]
pub enum ReadError {
    Io(std::io::Error),
    Json(serde_json::Error),
    NotACapture,
    UnsupportedVersion(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::Json(e) => write!(f, "not valid capture JSON: {e}"),
            ReadError::NotACapture => write!(f, "not an nvmetea capture (no \"schema\": \"nvmetea.capture/N\")"),
            ReadError::UnsupportedVersion(v) => {
                write!(f, "capture schema {v} is newer than this nvmetea understands (major {MAJOR})")
            }
        }
    }
}

impl std::error::Error for ReadError {}

/// Major version of a schema string `nvmetea.capture/<major>[.<minor>]`.
pub fn schema_major(s: &str) -> Option<u32> {
    let v = s.strip_prefix("nvmetea.capture/")?;
    v.split('.').next()?.parse().ok()
}

pub fn from_json(text: &str) -> Result<Capture, ReadError> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(ReadError::Json)?;
    let schema = v.get("schema").and_then(|s| s.as_str()).ok_or(ReadError::NotACapture)?;
    match schema_major(schema) {
        None => Err(ReadError::NotACapture),
        Some(m) if m != MAJOR => Err(ReadError::UnsupportedVersion(schema.to_string())),
        Some(_) => serde_json::from_value(v).map_err(ReadError::Json),
    }
}

pub fn read(path: &std::path::Path) -> Result<Capture, ReadError> {
    from_json(&std::fs::read_to_string(path).map_err(ReadError::Io)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_round_trip() {
        let mut h = Histogram::default();
        for v in [100, 1500, 1500, 9_000_000] {
            h.record(v);
        }
        let s = SparseHist::from_hist(&h);
        assert_eq!(s.0.len(), 3);
        assert_eq!(s.to_hist(), h);
    }

    #[test]
    fn version_policy() {
        assert_eq!(schema_major("nvmetea.capture/1"), Some(1));
        assert_eq!(schema_major("nvmetea.capture/1.3"), Some(1));
        assert_eq!(schema_major("nvmetea.queues/1"), None);
        assert!(matches!(from_json(r#"{"schema":"nvmetea.capture/2"}"#), Err(ReadError::UnsupportedVersion(_))));
        assert!(matches!(from_json(r#"{"x":1}"#), Err(ReadError::NotACapture)));
        assert!(matches!(from_json("nope"), Err(ReadError::Json(_))));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let c = Capture {
            schema: SCHEMA.into(),
            tool: Tool { name: "nvmetea".into(), version: "0.1.0".into() },
            host: Host::default(),
            boundary_signature: BTreeMap::new(),
            capabilities: vec![],
            filters: BTreeMap::new(),
            start_unix_s: 0.0,
            end_unix_s: 1.0,
            duration_s: 1.0,
            interval_s: 1.0,
            topology_start: CaptureTopology::default(),
            topology_end: CaptureTopology::default(),
            transitions: vec![],
            intervals: vec![],
            latency: vec![],
            queues: vec![],
            controllers: vec![],
            stages: None,
            events: vec![],
            quality: Quality::default(),
            self_overhead: Overhead::default(),
        };
        let mut v = serde_json::to_value(&c).expect("ser");
        v.as_object_mut().expect("obj").insert("future_field".into(), serde_json::json!({"x": 1}));
        let back = from_json(&v.to_string()).expect("reads");
        assert_eq!(back.duration_s, 1.0);
    }
}
