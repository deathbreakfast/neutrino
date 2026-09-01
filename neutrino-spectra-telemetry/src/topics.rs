//! Transport `*Payload` / `*_TOPIC` DTOs from Neutrino Spectra schemas.
//!
//! Each `*_TOPIC` constant is the Photon topic name a Spectra sink publishes to, and the
//! matching `*Payload` is the serialized wire type carried on that topic.
//!
//! # Examples
//!
//! ```rust,no_run
//! use neutrino_spectra_telemetry::topics::{
//!     NeutrinoSecretAccessLogPayload, NEUTRINO_SECRET_ACCESS_LOG_TOPIC,
//! };
//!
//! assert_eq!(
//!     NeutrinoSecretAccessLogPayload::topic(),
//!     NEUTRINO_SECRET_ACCESS_LOG_TOPIC
//! );
//! ```

/// Payload and topic constant for `neutrino_secret_access`.
pub use crate::schemas::neutrino_secret_access::{
    NeutrinoSecretAccessPayload, NEUTRINO_SECRET_ACCESS_TOPIC,
};
/// Payload and topic constant for `neutrino_secret_access_log`.
pub use crate::schemas::neutrino_secret_access_log::{
    NeutrinoSecretAccessLogPayload, NEUTRINO_SECRET_ACCESS_LOG_TOPIC,
};
