//! Neutrino secret access Spectra telemetry (metrics and events) and Valence audit helpers.

pub mod access;
mod audit;

pub use access::{
    current_secret_access_caller, record_secret_access, viewer_key_from_actor,
    with_secret_access_caller, SecretAccessRecord,
};
#[doc(hidden)]
pub use audit::set_audit_append_fail_for_tests;
pub use audit::{append_denial_audit_event, append_valence_audit_event};
