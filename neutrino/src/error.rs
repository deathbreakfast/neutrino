//! Typed errors for Neutrino sealed-store and vault APIs.
//!
//! Distinct variants keep not-found, authz denials, and validation failures
//! inspectable before hosts collapse them into HTTP / `ServerFnError`. Valence,
//! Gauge, and crypto failures land in [`NeutrinoError::Service`] /
//! [`NeutrinoError::Crypto`] with the source chain preserved. Messages never
//! include plaintext secret values.

use std::fmt;

use crate::key_source::MasterKeyError;

/// Library-facing failures from [`crate::secret_store::SecretStore`], vault
/// product APIs, and related helpers.
#[derive(Debug)]
pub enum NeutrinoError {
    /// No secret (or version) for the given id.
    NotFound {
        /// Valence secret id (safe to log).
        id: String,
    },
    /// Caller failed a Gauge or [`crate::vault_authz`] check.
    AccessDenied {
        /// Operation label (e.g. `reveal`, `create`, `delete`).
        operation: &'static str,
    },
    /// Invalid caller input (empty name, plaintext, id, …).
    Validation {
        /// Field or parameter name.
        field: &'static str,
        /// Human-readable reason (no secret material).
        message: String,
    },
    /// Master-key / backend configuration failure.
    Config(MasterKeyError),
    /// Seal / unseal / key-derivation failure (no key material in messages).
    Crypto {
        /// Operation label (e.g. `seal`, `unseal`, `derive_data_key`).
        operation: &'static str,
        /// Source error.
        source: anyhow::Error,
    },
    /// Trait default or backend that does not implement an operation.
    Unsupported {
        /// Operation label (e.g. `delete`, `rotate`).
        operation: &'static str,
    },
    /// Underlying Valence, Gauge, audit, or other service failure.
    Service {
        /// Operation label (e.g. `put`, `get`, `audit_append`).
        operation: &'static str,
        /// Source error.
        source: anyhow::Error,
    },
}

/// Result alias for Neutrino library boundaries.
pub type NeutrinoResult<T> = Result<T, NeutrinoError>;

impl fmt::Display for NeutrinoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { id } => write!(f, "secret not found: {id}"),
            Self::AccessDenied { operation } => {
                write!(f, "not authorized to {operation}")
            }
            Self::Validation { message, .. } => write!(f, "{message}"),
            Self::Config(e) => write!(f, "{e}"),
            Self::Crypto { operation, source } => {
                write!(f, "crypto {operation} failed: {source}")
            }
            Self::Unsupported { operation } => {
                write!(
                    f,
                    "SecretStore::{operation} is not implemented for this backend"
                )
            }
            Self::Service { operation, source } => {
                write!(f, "neutrino {operation} failed: {source}")
            }
        }
    }
}

impl std::error::Error for NeutrinoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(e) => Some(e),
            Self::Crypto { source, .. } | Self::Service { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<MasterKeyError> for NeutrinoError {
    fn from(value: MasterKeyError) -> Self {
        Self::Config(value)
    }
}

impl NeutrinoError {
    #[cfg_attr(not(feature = "ssr"), allow(dead_code))]
    pub(crate) fn not_found(id: impl Into<String>) -> Self {
        Self::NotFound { id: id.into() }
    }

    #[cfg_attr(not(feature = "ssr"), allow(dead_code))]
    pub(crate) const fn access_denied(operation: &'static str) -> Self {
        Self::AccessDenied { operation }
    }

    pub(crate) fn validation(field: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            field,
            message: message.into(),
        }
    }

    pub(crate) fn crypto(operation: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self::Crypto {
            operation,
            source: source.into(),
        }
    }

    pub(crate) const fn unsupported(operation: &'static str) -> Self {
        Self::Unsupported { operation }
    }

    pub(crate) fn service(operation: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self::Service {
            operation,
            source: source.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NeutrinoError;
    use crate::key_source::MasterKeyError;
    use std::error::Error;

    #[test]
    fn display_and_source_for_variants() {
        let missing = NeutrinoError::not_found("abc");
        assert!(missing.to_string().contains("secret not found"));
        assert!(missing.to_string().contains("abc"));
        assert!(missing.source().is_none());

        let denied = NeutrinoError::access_denied("reveal");
        assert!(denied.to_string().contains("not authorized"));
        assert!(denied.to_string().contains("reveal"));
        assert!(denied.source().is_none());

        let validation = NeutrinoError::validation("Name", "Name is required.");
        assert_eq!(validation.to_string(), "Name is required.");
        assert!(matches!(
            &validation,
            NeutrinoError::Validation { field: "Name", .. }
        ));

        let config = NeutrinoError::from(MasterKeyError::NotSet);
        assert!(config.to_string().contains("NEUTRINO_MASTER_KEY"));
        assert!(config.source().is_some());

        let crypto = NeutrinoError::crypto("seal", anyhow::anyhow!("bad nonce"));
        assert!(crypto.to_string().contains("seal"));
        assert!(crypto.source().is_some());

        let unsupported = NeutrinoError::unsupported("delete");
        assert!(unsupported.to_string().contains("delete"));

        let service = NeutrinoError::service("put", anyhow::anyhow!("backend down"));
        assert!(service.to_string().contains("put"));
        assert!(service.to_string().contains("backend down"));
        assert!(service.source().is_some());
    }
}
