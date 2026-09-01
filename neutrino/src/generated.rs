#![allow(
    dead_code,
    unused_imports,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction
)]
//! Valence-codegen output for the secret/audit schemas (`build.rs` + `schemas/`).
//! Generated model types are not hand-documented; see `../schemas/*.rs` for the
//! source-of-truth field definitions.

#[cfg(feature = "ssr")]
use crate::privacy_policies::{
    CREATE_NEUTRINO_SECRETS_GATE, NEUTRINO_SECRET_ENTITY, NEUTRINO_SECRET_VERSION_ENTITY,
    NEUTRINO_SUPER_USER, OWNER_SUBJECT_JSON,
};
#[cfg(feature = "ssr")]
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};

#[cfg(feature = "ssr")]
include!(concat!(env!("OUT_DIR"), "/generated_models.rs"));
