//! Neutrino Spectra schema modules (inventory + typed helpers + topics).
//!
//! Each module wraps one `spectra_schema!` / `spectra_metric!` invocation under
//! `schemas/` at the repo root (relative to this file, one directory up from `src/`); the
//! macro generates the row/payload types, the typed logger/recorder, the Photon topic
//! constant, and the `inventory` registration for that table or counter. This module itself
//! is private — see [`crate::helpers`] and [`crate::topics`] for the re-exported,
//! effectively-public names.
#![allow(clippy::too_many_arguments)]

/// `neutrino_secret_access` counter schema (see `schemas/neutrino_secret_access_spectra_metric.rs`).
#[path = "../schemas/neutrino_secret_access_spectra_metric.rs"]
pub mod neutrino_secret_access;

/// `neutrino_secret_access_log` event schema (see
/// `schemas/neutrino_secret_access_log_spectra_schema.rs`).
#[path = "../schemas/neutrino_secret_access_log_spectra_schema.rs"]
pub mod neutrino_secret_access_log;
