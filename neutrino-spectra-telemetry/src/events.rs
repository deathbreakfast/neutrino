//! Event field builders for Neutrino secret access logs.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use serde_json::{json, Value};

const MAX_MESSAGE_LEN: usize = 512;

fn hash_fingerprint(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut hasher = DefaultHasher::new();
    trimmed.hash(&mut hasher);
    format!("h{:016x}", hasher.finish())
}

/// Truncate `message` to `MAX_MESSAGE_LEN` bytes, appending an ellipsis if shortened.
///
/// # Examples
///
/// ```rust
/// use neutrino_spectra_telemetry::truncate_message;
///
/// assert_eq!(truncate_message("ok"), "ok");
/// let long = "a".repeat(600);
/// let clipped = truncate_message(&long);
/// assert!(clipped.ends_with('…'));
/// assert_eq!(clipped.len(), 512);
/// ```
pub fn truncate_message(message: &str) -> String {
    if message.len() <= MAX_MESSAGE_LEN {
        message.to_string()
    } else {
        const ELLIPSIS: &str = "…";
        let budget = MAX_MESSAGE_LEN.saturating_sub(ELLIPSIS.len());
        format!("{}{ELLIPSIS}", &message[..budget])
    }
}

/// Build the JSON field set for a `neutrino_secret_access_log` row.
///
/// Secret-identifying metadata (`secret_id`, `scope_path`, `secret_name`, `caller`) is hashed
/// before persist so audit rows do not carry reversible fingerprints.
/// `error_message` is truncated via [`truncate_message`] before being included.
///
/// # Examples
///
/// ```rust,no_run
/// use neutrino_spectra_telemetry::secret_access_log_fields;
///
/// let fields = secret_access_log_fields(
///     "read",
///     "sec_123",
///     3,
///     "/prod/db",
///     "db-password",
///     "granted",
///     "svc-billing",
///     "billing-worker",
///     "",
/// );
/// assert_eq!(fields["action"], "read");
/// assert_ne!(fields["secret_id"], "sec_123");
/// ```
#[allow(clippy::too_many_arguments)]
pub fn secret_access_log_fields(
    action: &str,
    secret_id: &str,
    version_num: i64,
    scope_path: &str,
    secret_name: &str,
    outcome: &str,
    viewer_key: &str,
    caller: &str,
    error_message: &str,
) -> Value {
    json!({
        "action": action,
        "secret_id": hash_fingerprint(secret_id),
        "version_num": version_num,
        "scope_path": hash_fingerprint(scope_path),
        "secret_name": hash_fingerprint(secret_name),
        "outcome": outcome,
        "viewer_key": viewer_key,
        "caller": hash_fingerprint(caller),
        "error_message": truncate_message(error_message),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_message_happy_and_sad() {
        assert_eq!(truncate_message("ok"), "ok");
        assert_eq!(truncate_message(""), "");

        let long = "a".repeat(600);
        let clipped = truncate_message(&long);
        assert_eq!(clipped.len(), MAX_MESSAGE_LEN);
        assert!(clipped.ends_with('…'));
        assert_eq!(
            &clipped[..MAX_MESSAGE_LEN - "…".len()],
            &"a".repeat(MAX_MESSAGE_LEN - "…".len())
        );
    }

    #[test]
    fn secret_access_log_fields_happy_shape() {
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
        for key in ["secret_id", "scope_path", "secret_name", "caller"] {
            let value = fields[key].as_str().unwrap_or("");
            assert!(value.starts_with('h'));
            assert_eq!(value.len(), 17);
        }
    }

    #[test]
    fn secret_access_log_fields_truncates_error_message_sad() {
        let long = "e".repeat(600);
        let fields = secret_access_log_fields(
            "write", "sec", 1, "/", "n", "denied", "viewer", "caller", &long,
        );
        let err = fields["error_message"].as_str().unwrap_or("");
        assert_eq!(err.len(), MAX_MESSAGE_LEN);
        assert!(err.ends_with('…'));
    }
}
