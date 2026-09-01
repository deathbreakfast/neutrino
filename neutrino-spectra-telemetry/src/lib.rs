//! Spectra-backed telemetry for [Neutrino] secret-access events.
//!
//! Typed event/metric schemas, Photon topic helpers, and JSON field builders for hosts
//! that log secret reads/writes themselves.
//!
//! [Neutrino] is a secrets store; this crate does not talk to Neutrino directly.
//!
//! Instead it gives Neutrino-adjacent hosts a typed way to record *who accessed which secret,
//! when, and with what outcome* through [Spectra]: [`secret_access_log_fields`] builds the JSON
//! row for a `neutrino_secret_access_log` event, and the generated `*Recorder` / `*Logger` types
//! (see [`NeutrinoSecretAccessRecorder`] / [`NeutrinoSecretAccessLogLogger`]) emit it.
//!
//! [Neutrino]: https://github.com/unified-field-dev/neutrino
//! [Spectra]: https://github.com/unified-field-dev/spectra
//!
//! ## Features
//!
//! - **Spectra access telemetry** — Field builders and Spectra schemas so hosts can log
//!   who accessed which secret, when, and with what outcome, without talking to Neutrino
//!   directly. Covers typed schemas, [`secret_access_log_fields`], generated
//!   topic/recorder helpers, and [`sink_forward`] re-emit. [Get started](#log-secret-access-events).
//!
//! This crate has no `*_TELEMETRY` install switch of its own: it does not sit in front of
//! Neutrino, so there is no process-wide sink to gate. Hosts call [`secret_access_log_fields`]
//! (or the typed recorders/loggers) directly at their own secret-access interception points.
//!
//! ## Getting started
//!
//! Hosts that intercept Neutrino secret reads/writes build the field set once per access and
//! log it through their installed Spectra sink. Full sequence:
//! [Log secret access events](#log-secret-access-events).
//!
//! ```rust,no_run
//! use neutrino_spectra_telemetry::secret_access_log_fields;
//!
//! let fields = secret_access_log_fields(
//!     "read",          // action
//!     "sec_123",       // secret_id
//!     3,               // version_num
//!     "/prod/db",      // scope_path
//!     "db-password",   // secret_name
//!     "granted",       // outcome
//!     "svc-billing",   // viewer_key
//!     "billing-worker", // caller
//!     "",              // error_message
//! );
//! spectra_core::try_log_event("neutrino_secret_access_log", &fields);
//! assert_eq!(fields["outcome"], "granted");
//! ```
//!
//! ## Log secret access events
//!
//! [`secret_access_log_fields`] builds the JSON row for a `neutrino_secret_access_log`
//! Spectra event so hosts can record secret reads and writes with a stable field shape.
//! Call it at each secret-access interception point after your host decides grant or
//! deny, then emit through the installed Spectra sink with `try_log_event`.
//!
//! **Prerequisites:** Spectra sink installed in the host; link this crate so schemas
//! register via `inventory`.
//!
//! ```rust,no_run
//! use neutrino_spectra_telemetry::secret_access_log_fields;
//!
//! let fields = secret_access_log_fields(
//!     "read",
//!     "sec_123",
//!     3,
//!     "/prod/db",
//!     "db-password",
//!     "granted",
//!     "svc-billing",
//!     "billing-worker",
//!     "",
//! );
//! spectra_core::try_log_event("neutrino_secret_access_log", &fields);
//! assert!(fields["outcome"] == "granted");
//! ```
//!
//! On deny paths, pass a non-empty `error_message` (truncated via [`truncate_message`]).
//! Next: [`sink_forward`] when a sink consumer re-emits onto typed recorders, or
//! [`helpers`] / [`topics`] for generated `*Recorder` / `*Payload` symbols.
//!
//! ## Generated schemas and topics
//!
//! Typed `*Recorder` / `*Logger` / `*Payload` / `*_TOPIC` symbols are re-exported at the crate
//! root and grouped under [`helpers`] and [`topics`]. One mid-level pattern for both surfaces:
//!
//! ```rust,no_run
//! use neutrino_spectra_telemetry::{
//!     NeutrinoSecretAccessLogPayload, NeutrinoSecretAccessRecorder,
//!     NEUTRINO_SECRET_ACCESS_LOG_TOPIC,
//! };
//!
//! NeutrinoSecretAccessRecorder::record(
//!     1,
//!     serde_json::json!({"action": "read", "outcome": "granted"}),
//! );
//! assert_eq!(
//!     NeutrinoSecretAccessLogPayload::topic(),
//!     NEUTRINO_SECRET_ACCESS_LOG_TOPIC
//! );
//! ```
//!
//! See [`helpers`] for the full recorder/logger set and [`topics`] for transport DTOs.
//!
//! ## Examples
//!
//! - Primary path: [Log secret access events](#log-secret-access-events)
//! - Getting started fence: [Getting started](#getting-started)
//! - Sink re-emit: [`sink_forward`]
//! - Generated types: [`helpers`], [`topics`]

#![allow(clippy::too_long_first_doc_paragraph)]

mod events;
/// Typed emit helpers from Neutrino Spectra schemas.
pub mod helpers;
// macro-generated Spectra schema types; documented via each schema's `description`
#[allow(missing_docs)]
mod schemas;
/// Forwarders for sink consumers that re-dispatch raw metric/event emits onto the matching
/// typed Spectra recorder generated from this crate's schemas.
///
/// # Examples
///
/// ```rust,no_run
/// use neutrino_spectra_telemetry::sink_forward;
/// use chrono::Utc;
/// use serde_json::json;
///
/// let ts = Utc::now();
/// sink_forward::forward_counter(
///     "neutrino_secret_access",
///     json!({"action": "read", "outcome": "granted"}),
///     1,
///     ts,
/// );
/// ```
pub mod sink_forward;
/// Transport `*Payload` / `*_TOPIC` DTOs from Neutrino Spectra schemas.
pub mod topics;

pub use helpers::*;
pub use topics::*;

pub use events::{secret_access_log_fields, truncate_message};
