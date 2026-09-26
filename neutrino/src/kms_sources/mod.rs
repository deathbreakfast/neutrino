//! KMS-backed master key sources (AWS KMS, GCP KMS, Vault Transit).
//!
//! These unwrap a wrapped process master key. Customer secrets remain in Valence;
//! enable one Cargo feature and set `NEUTRINO_KEY_SOURCE` accordingly.

use crate::key_source::{MasterKeyError, MasterKeyProvenance, ResolvedMasterKey};

pub use crate::key_source::WrappedKeyDecryptor;

#[cfg(feature = "kms-aws")]
pub mod aws;

#[cfg(feature = "kms-gcp")]
pub mod gcp;

#[cfg(feature = "kms-vault-transit")]
pub mod vault_transit;

pub(crate) fn require_env(
    var: &'static str,
    source_kind: &'static str,
) -> Result<String, MasterKeyError> {
    let raw = std::env::var(var).map_err(|_| MasterKeyError::Config {
        source_kind,
        field: var,
    })?;
    let t = raw.trim();
    if t.is_empty() {
        return Err(MasterKeyError::Config {
            source_kind,
            field: var,
        });
    }
    Ok(t.to_string())
}

pub(crate) fn resolved_kms(
    bytes: zeroize::Zeroizing<Vec<u8>>,
    key_id: String,
) -> ResolvedMasterKey {
    ResolvedMasterKey::new(bytes, MasterKeyProvenance::Kms { key_id })
}

pub(crate) fn log_provider_err(provider: &str, operation: &str, error_class: &str) {
    log::warn!(
        target: "neutrino.master_key.provider",
        "provider={provider} operation={operation} error_class={error_class}"
    );
}
