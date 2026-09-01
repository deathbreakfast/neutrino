//! Emit UC1/UC3 rows for secret store access.

use std::cell::RefCell;

use spectra_core::{try_log_event, try_record_counter};
use valence::Actor;

use neutrino_spectra_telemetry::secret_access_log_fields;

thread_local! {
    static SECRET_ACCESS_CALLER: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Optional surface tag for secret access in this task (e.g. `pion_resolver`).
pub fn with_secret_access_caller<F, R>(caller: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    SECRET_ACCESS_CALLER.with(|slot| {
        let prev = slot.borrow().clone();
        *slot.borrow_mut() = Some(caller.to_string());
        let out = f();
        *slot.borrow_mut() = prev;
        out
    })
}

/// Read the surface tag set by the innermost [`with_secret_access_caller`] scope,
/// or an empty string when none is set.
pub fn current_secret_access_caller() -> String {
    SECRET_ACCESS_CALLER.with(|slot| slot.borrow().clone().unwrap_or_default())
}

/// Stable viewer identity label derived from a Valence [`Actor`], used to key
/// UC1/UC3 telemetry rows.
pub fn viewer_key_from_actor(actor: &Actor) -> String {
    match actor {
        Actor::User { user_id } => user_id.clone(),
        Actor::ServiceUser { service_name } => format!("service:{service_name}"),
        Actor::System { operation } => format!("system:{operation}"),
        Actor::Anonymous => "anonymous".to_string(),
    }
}

/// One secret access attempt.
#[derive(Debug, Clone)]
pub struct SecretAccessRecord {
    /// Action performed (`put`, `get`, `reveal`, `rotate`, `delete`, …).
    pub action: &'static str,
    /// Secret id involved, if known.
    pub secret_id: String,
    /// Secret version involved.
    pub version_num: i64,
    /// Scope path the secret is stored under.
    pub scope_path: String,
    /// Human-readable secret name.
    pub secret_name: String,
    /// Outcome (`ok`, `denied`, `error`, `not_found`, …).
    pub outcome: &'static str,
    /// Stable viewer identity label (see [`viewer_key_from_actor`]).
    pub viewer_key: String,
    /// Optional surface tag set via [`with_secret_access_caller`].
    pub caller: String,
    /// Error detail, empty on success.
    pub error_message: String,
}

impl SecretAccessRecord {
    /// Attach an error message to this record (builder-style).
    pub fn with_error(mut self, message: impl Into<String>) -> Self {
        self.error_message = message.into();
        self
    }
}

/// Record UC1 counter + UC3 event for a secret access attempt.
pub fn record_secret_access(record: SecretAccessRecord) {
    try_record_counter(
        "neutrino_secret_access",
        &[("action", record.action), ("outcome", record.outcome)],
        1,
    );
    try_log_event(
        "neutrino_secret_access_log",
        &secret_access_log_fields(
            record.action,
            &record.secret_id,
            record.version_num,
            &record.scope_path,
            &record.secret_name,
            record.outcome,
            &record.viewer_key,
            &record.caller,
            &record.error_message,
        ),
    );
}
