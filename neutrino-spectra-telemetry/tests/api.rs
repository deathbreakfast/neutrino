//! Happy/sad coverage for field helpers, typed emitters, and `sink_forward`.
#![allow(missing_docs)]

use chrono::Utc;
use neutrino_spectra_telemetry::{
    secret_access_log_fields, sink_forward, truncate_message, NeutrinoSecretAccessLogLogger,
    NeutrinoSecretAccessRecorder, NEUTRINO_SECRET_ACCESS_LOG_TOPIC, NEUTRINO_SECRET_ACCESS_TOPIC,
};
use serde_json::json;

#[test]
fn secret_access_log_fields_happy() {
    let fields = secret_access_log_fields(
        "read",
        "sec_123",
        3,
        "/prod/db",
        "db-password",
        "granted",
        "svc-billing",
        "billing-worker",
        "",
    );
    assert_eq!(fields["action"], "read");
    assert_ne!(fields["secret_id"], "sec_123");
    assert_eq!(fields["version_num"], 3);
    assert_ne!(fields["scope_path"], "/prod/db");
    assert_ne!(fields["secret_name"], "db-password");
    assert_eq!(fields["outcome"], "granted");
    assert_eq!(fields["viewer_key"], "svc-billing");
    assert_ne!(fields["caller"], "billing-worker");
    assert_eq!(fields["error_message"], "");
}

#[test]
fn truncate_message_and_fields_error_clip_sad() {
    assert_eq!(truncate_message("short"), "short");
    assert_eq!(truncate_message(""), "");

    let long = "x".repeat(600);
    let truncated = truncate_message(&long);
    assert_eq!(truncated.len(), 512);
    assert!(truncated.ends_with('…'));
    assert_ne!(truncated, long);

    let fields = secret_access_log_fields(
        "write", "sec", 1, "/", "n", "denied", "viewer", "caller", &long,
    );
    let err = fields["error_message"].as_str().unwrap_or("");
    assert_eq!(err.len(), 512);
    assert!(err.ends_with('…'));
}

#[test]
fn typed_recorders_emit_without_spectra_sink_happy() {
    let ts = Utc::now();
    NeutrinoSecretAccessRecorder::record_at(1, json!({"action": "read", "outcome": "granted"}), ts);
    NeutrinoSecretAccessLogLogger::log_at(
        "read".into(),
        "sec_123".into(),
        3,
        "/prod/db".into(),
        "db-password".into(),
        "granted".into(),
        "svc-billing".into(),
        "billing-worker".into(),
        String::new(),
        ts,
    );
}

#[test]
fn typed_recorders_empty_labels_accepted_sad() {
    let ts = Utc::now();
    NeutrinoSecretAccessRecorder::record_at(0, json!({}), ts);
    NeutrinoSecretAccessLogLogger::log_at(
        String::new(),
        String::new(),
        0,
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        ts,
    );
}

#[test]
fn sink_forward_known_metrics_and_events_happy() {
    let ts = Utc::now();
    sink_forward::forward_counter(
        "neutrino_secret_access",
        json!({"action": "read", "outcome": "granted"}),
        1,
        ts,
    );
    sink_forward::forward_event(
        "neutrino_secret_access_log",
        &json!({
            "action": "read",
            "secret_id": "sec",
            "version_num": 2,
            "scope_path": "/a",
            "secret_name": "n",
            "outcome": "granted",
            "viewer_key": "v",
            "caller": "c",
            "error_message": ""
        }),
        ts,
    );
    // string version_num coerces via field_i64
    sink_forward::forward_event(
        "neutrino_secret_access_log",
        &json!({
            "action": "write",
            "secret_id": "sec",
            "version_num": "4",
            "scope_path": "/",
            "secret_name": "n",
            "outcome": "denied",
            "viewer_key": "v",
            "caller": "c",
            "error_message": "nope"
        }),
        ts,
    );
}

#[test]
fn sink_forward_unknown_and_missing_fields_ignored_sad() {
    let ts = Utc::now();

    // unknown metric / table names are no-ops
    sink_forward::forward_counter("not_a_neutrino_metric", json!({}), 1, ts);
    sink_forward::forward_event("unknown_table", &json!({}), ts);

    // missing / invalid fields coerce to empty string / 0
    sink_forward::forward_event("neutrino_secret_access_log", &json!({}), ts);
    sink_forward::forward_event(
        "neutrino_secret_access_log",
        &json!({
            "action": null,
            "secret_id": [],
            "version_num": "not-a-number",
            "scope_path": {},
            "outcome": true,
        }),
        ts,
    );
}

#[test]
fn topic_constants_are_non_empty_happy() {
    assert!(!NEUTRINO_SECRET_ACCESS_TOPIC.is_empty());
    assert!(
        NEUTRINO_SECRET_ACCESS_TOPIC.starts_with("spectra.metric."),
        "unexpected metric topic: {NEUTRINO_SECRET_ACCESS_TOPIC}"
    );
    assert!(NEUTRINO_SECRET_ACCESS_TOPIC.contains("neutrino_secret_access"));

    assert!(!NEUTRINO_SECRET_ACCESS_LOG_TOPIC.is_empty());
    assert!(
        NEUTRINO_SECRET_ACCESS_LOG_TOPIC.starts_with("spectra.event."),
        "unexpected event topic: {NEUTRINO_SECRET_ACCESS_LOG_TOPIC}"
    );
    assert!(NEUTRINO_SECRET_ACCESS_LOG_TOPIC.contains("neutrino_secret_access_log"));
}
