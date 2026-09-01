//! Build secret-access log fields and emit via typed recorder/logger.
//!
//! ```bash
//! CARGO_BUILD_JOBS=1 \
//!   cargo run -p neutrino-spectra-telemetry --example secret_access_emit_smoke
//! ```
//!
//! Success: `secret_access_emit_smoke: OK`.

#![allow(clippy::print_stdout)]

use chrono::Utc;
use neutrino_spectra_telemetry::{
    secret_access_log_fields, NeutrinoSecretAccessLogLogger, NeutrinoSecretAccessRecorder,
};

fn main() {
    let _fields = secret_access_log_fields(
        "read",
        "sec_example",
        1,
        "/lab/db",
        "example-secret",
        "granted",
        "svc-example",
        "example-caller",
        "",
    );
    let ts = Utc::now();
    NeutrinoSecretAccessRecorder::record_at(
        1,
        serde_json::json!({"action": "read", "outcome": "granted"}),
        ts,
    );
    NeutrinoSecretAccessLogLogger::log_at(
        "read".into(),
        "sec_example".into(),
        1,
        "/lab/db".into(),
        "example-secret".into(),
        "granted".into(),
        "svc-example".into(),
        "example-caller".into(),
        String::new(),
        ts,
    );
    println!("secret_access_emit_smoke: OK");
}
