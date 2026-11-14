//! The capture writer's output conforms to `docs/schema/capture-v1.schema.json`.
//! A minimal validator for the JSON Schema keywords that file uses: type,
//! required, properties, items, prefixItems, min/maxItems, enum, oneOf,
//! additionalProperties (schema form), $ref into $defs.

use nvmetea_core::model::Histogram;
use nvmetea_export::capture::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn type_ok(t: &str, v: &Value) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "number" => v.is_number(),
        "integer" => v.is_u64() || v.is_i64(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        _ => false,
    }
}

fn validate(root: &Value, s: &Value, v: &Value, path: &str, errs: &mut Vec<String>) {
    if let Some(r) = s.get("$ref").and_then(Value::as_str) {
        let name = r.trim_start_matches("#/$defs/");
        return validate(root, &root["$defs"][name], v, path, errs);
    }
    if let Some(alts) = s.get("oneOf").and_then(Value::as_array) {
        let ok = alts.iter().filter(|a| {
            let mut e = Vec::new();
            validate(root, a, v, path, &mut e);
            e.is_empty()
        });
        if ok.count() != 1 {
            errs.push(format!("{path}: oneOf"));
        }
        return;
    }
    match s.get("type") {
        Some(Value::String(t)) if !type_ok(t, v) => return errs.push(format!("{path}: not {t}")),
        Some(Value::Array(ts)) if !ts.iter().filter_map(Value::as_str).any(|t| type_ok(t, v)) => {
            return errs.push(format!("{path}: none of {ts:?}"));
        }
        _ => {}
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        if !e.contains(v) {
            errs.push(format!("{path}: {v} not in enum"));
        }
    }
    if let Some(o) = v.as_object() {
        for r in s.get("required").and_then(Value::as_array).into_iter().flatten() {
            let k = r.as_str().unwrap_or("");
            if !o.contains_key(k) {
                errs.push(format!("{path}: missing {k}"));
            }
        }
        let props = s.get("properties").and_then(Value::as_object);
        for (k, val) in o {
            let p = format!("{path}.{k}");
            match props.and_then(|p| p.get(k)) {
                Some(ps) => validate(root, ps, val, &p, errs),
                None => {
                    if let Some(ap) = s.get("additionalProperties").filter(|a| a.is_object()) {
                        validate(root, ap, val, &p, errs);
                    }
                }
            }
        }
    }
    if let Some(a) = v.as_array() {
        if let Some(n) = s.get("minItems").and_then(Value::as_u64) {
            if (a.len() as u64) < n {
                errs.push(format!("{path}: fewer than {n} items"));
            }
        }
        if let Some(n) = s.get("maxItems").and_then(Value::as_u64) {
            if (a.len() as u64) > n {
                errs.push(format!("{path}: more than {n} items"));
            }
        }
        if let Some(pi) = s.get("prefixItems").and_then(Value::as_array) {
            for (i, (ps, val)) in pi.iter().zip(a).enumerate() {
                validate(root, ps, val, &format!("{path}[{i}]"), errs);
            }
        }
        if let Some(is) = s.get("items") {
            for (i, val) in a.iter().enumerate() {
                validate(root, is, val, &format!("{path}[{i}]"), errs);
            }
        }
    }
}

fn schema() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/schema/capture-v1.schema.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("schema file")).expect("schema is JSON")
}

fn dist() -> Dist {
    let mut h = Histogram::default();
    h.record(1500);
    h.record(9000);
    Dist { count: 2, sum_ns: Some(10_500), hist: SparseHist::from_hist(&h) }
}

fn sample_capture() -> Capture {
    let key =
        ControllerKey { subsysnqn: Some("nqn.test".into()), traddr: Some("192.0.2.1".into()), ..Default::default() };
    let ctrl = CaptureController {
        name: "nvme2".into(),
        key: key.clone(),
        state: "live".into(),
        generation: Some(1),
        epoch: None,
        io_queues: Some(8),
        queue_depth: Some(32),
    };
    let topo = CaptureTopology {
        controllers: vec![ctrl],
        namespaces: vec![CaptureNamespace {
            name: "nvme2n1".into(),
            nsid: Some(1),
            wwid: None,
            paths: vec![CapturePath { name: "nvme2c2n1".into(), controller: "nvme2".into(), ana_state: None }],
        }],
    };
    Capture {
        schema: SCHEMA.into(),
        tool: Tool { name: "nvmetea".into(), version: "0.1.0".into() },
        host: Host { hostname: Some("h".into()), ..Default::default() },
        boundary_signature: BTreeMap::from([("request".into(), "raw_tp".into())]),
        capabilities: vec![CapabilityStatus {
            capability: "nvme_latency".into(),
            status: "active".into(),
            reason: None,
        }],
        filters: BTreeMap::new(),
        start_unix_s: 1.0,
        end_unix_s: 11.0,
        duration_s: 10.0,
        interval_s: 5.0,
        topology_start: topo.clone(),
        topology_end: topo,
        transitions: vec![CaptureTransition {
            at_unix_s: 2.0,
            controller: "nvme2".into(),
            change: "live -> resetting".into(),
            source: "uevent".into(),
        }],
        intervals: vec![IntervalSummary {
            t_s: 5.0,
            interval_s: 5.0,
            controllers: vec![ControllerRates {
                controller: "nvme2".into(),
                state: "live".into(),
                read_iops: Some(1.0),
                ..Default::default()
            }],
        }],
        latency: vec![LatencyGroup {
            controller: "nvme2".into(),
            key: key.clone(),
            op: "read".into(),
            metric: "request".into(),
            dist: dist(),
        }],
        queues: vec![QueueWindow {
            controller: "nvme2".into(),
            qid: 1,
            op: "read".into(),
            dispatched: 2,
            bytes: 8192,
            completed: 2,
            nvme_errors: 0,
        }],
        controllers: vec![ControllerWindow { controller: "nvme2".into(), key: key.clone(), ..Default::default() }],
        stages: Some(StageCapture {
            sample_every: 100,
            flavour: "fentry".into(),
            records: 2,
            sum_check_failures: 0,
            groups: vec![
                StageGroup {
                    controller: None,
                    key: None,
                    op: "read".into(),
                    variant: "read".into(),
                    size_class: 13,
                    complete: 2,
                    partial: 0,
                    excluded: 0,
                    request: dist(),
                    stages: vec![StageDist {
                        stage: "C1".into(),
                        family: "C".into(),
                        label: "remote".into(),
                        bound: Some("upper bound".into()),
                        dist: dist(),
                    }],
                },
                StageGroup {
                    controller: Some("nvme2".into()),
                    key: Some(key),
                    op: "read".into(),
                    variant: "read".into(),
                    size_class: 13,
                    complete: 2,
                    partial: 0,
                    excluded: 0,
                    request: dist(),
                    stages: vec![],
                },
            ],
        }),
        events: vec![CaptureEvent { at_unix_s: 3.0, kind: "slow".into(), text: "slow read".into() }],
        quality: Quality {
            level1: BTreeMap::from([("events_lost".into(), 0)]),
            level2: BTreeMap::new(),
            events_dropped: 0,
        },
        self_overhead: Overhead { cpu_seconds: Some(0.1), max_rss_bytes: None },
    }
}

#[test]
fn capture_conforms_to_the_schema() {
    let s = schema();
    let v = serde_json::to_value(sample_capture()).expect("ser");
    let mut errs = Vec::new();
    validate(&s, &s, &v, "$", &mut errs);
    assert!(errs.is_empty(), "{errs:#?}");
}

#[test]
fn the_validator_catches_violations() {
    let s = schema();
    let mut v = serde_json::to_value(sample_capture()).expect("ser");
    v["schema"] = json!(7);
    v.as_object_mut().expect("obj").remove("latency");
    v["events"][0]["kind"] = json!("bogus");
    v["stages"]["groups"][0]["request"]["hist"][0] = json!([1]);
    let mut errs = Vec::new();
    validate(&s, &s, &v, "$", &mut errs);
    let all = errs.join("\n");
    for needle in ["$.schema: not string", "missing latency", "not in enum", "fewer than 2 items"] {
        assert!(all.contains(needle), "{needle}: {all}");
    }
}

/// A capture written by a real `nvmetea record` run, when one is provided.
#[test]
fn recorded_capture_conforms_when_provided() {
    let Ok(p) = std::env::var("NVMETEA_CAPTURE") else { return };
    let s = schema();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).expect("capture")).expect("json");
    let mut errs = Vec::new();
    validate(&s, &s, &v, "$", &mut errs);
    assert!(errs.is_empty(), "{errs:#?}");
}
