//! Consumer-side forwarders onto typed Neutrino Spectra helpers.
//!
//! # Examples
//!
//! ```rust,no_run
//! use neutrino_spectra_telemetry::sink_forward::forward_counter;
//! use chrono::Utc;
//! use serde_json::json;
//!
//! forward_counter(
//!     "neutrino_secret_access",
//!     json!({"action": "read", "outcome": "granted"}),
//!     1,
//!     Utc::now(),
//! );
//! ```

use crate::events::secret_access_log_fields;
use crate::helpers::{NeutrinoSecretAccessLogLogger, NeutrinoSecretAccessRecorder};

fn field_str(fields: &serde_json::Value, key: &str) -> String {
    fields
        .get(key)
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

fn field_i64(fields: &serde_json::Value, key: &str) -> i64 {
    fields
        .get(key)
        .and_then(|v| match v {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => s.parse().ok(),
            _ => None,
        })
        .unwrap_or(0)
}

/// Forward a metric emit onto the matching typed recorder.
pub fn forward_counter(
    name: &str,
    labels: serde_json::Value,
    delta: i64,
    ts: chrono::DateTime<chrono::Utc>,
) {
    if name == "neutrino_secret_access" {
        NeutrinoSecretAccessRecorder::record_at(delta, labels, ts);
    }
}

/// Forward an event emit onto the matching typed logger.
pub fn forward_event(table: &str, fields: &serde_json::Value, ts: chrono::DateTime<chrono::Utc>) {
    if table == "neutrino_secret_access_log" {
        let row = secret_access_log_fields(
            &field_str(fields, "action"),
            &field_str(fields, "secret_id"),
            field_i64(fields, "version_num"),
            &field_str(fields, "scope_path"),
            &field_str(fields, "secret_name"),
            &field_str(fields, "outcome"),
            &field_str(fields, "viewer_key"),
            &field_str(fields, "caller"),
            &field_str(fields, "error_message"),
        );
        NeutrinoSecretAccessLogLogger::log_at(
            field_str(&row, "action"),
            field_str(&row, "secret_id"),
            field_i64(&row, "version_num"),
            field_str(&row, "scope_path"),
            field_str(&row, "secret_name"),
            field_str(&row, "outcome"),
            field_str(&row, "viewer_key"),
            field_str(&row, "caller"),
            field_str(&row, "error_message"),
            ts,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn field_str_and_i64_happy_coercions() {
        let fields = json!({
            "s": "hello",
            "b": true,
            "n": 42,
            "ns": "7",
        });
        assert_eq!(field_str(&fields, "s"), "hello");
        assert_eq!(field_str(&fields, "b"), "true");
        assert_eq!(field_str(&fields, "n"), "42");
        assert_eq!(field_i64(&fields, "n"), 42);
        assert_eq!(field_i64(&fields, "ns"), 7);
    }

    #[test]
    fn field_str_and_i64_missing_or_invalid_default_sad() {
        let fields = json!({
            "arr": [],
            "obj": {},
            "bad": "not-a-number",
            "null": null,
        });
        assert_eq!(field_str(&fields, "missing"), "");
        assert_eq!(field_str(&fields, "arr"), "");
        assert_eq!(field_str(&fields, "obj"), "");
        assert_eq!(field_str(&fields, "null"), "");
        assert_eq!(field_i64(&fields, "missing"), 0);
        assert_eq!(field_i64(&fields, "bad"), 0);
        assert_eq!(field_i64(&fields, "arr"), 0);
        assert_eq!(field_i64(&fields, "null"), 0);
    }
}
