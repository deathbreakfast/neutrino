//! Deployment-agnostic secret backend selection (Neutrino default; cloud adapters optional).

use crate::error::{NeutrinoError, NeutrinoResult};

/// Which logical backend is selected for secret materialization.
///
/// Set `NEUTRINO_SECRET_BACKEND` to `neutrino` (default), `local`, or `manual`.
/// Values `cloud`, `cloud_managed`, and `external` select [`SecretBackendKind::CloudManagedStub`],
/// which [`ensure_secret_backend_supported`] rejects — there is no external vault adapter yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretBackendKind {
    /// [`crate::ValenceSealedStore`] — canonical encrypted Valence path.
    NeutrinoValence,
    /// Explicit alias for manual/monolithic deployments using the same store.
    LocalManual,
    /// Unsupported placeholder for a future external vault adapter.
    ///
    /// Selecting this kind via env does **not** switch storage; sealed-store
    /// operations fail closed until a real adapter ships.
    CloudManagedStub,
}

/// Resolve backend kind from environment (`NEUTRINO_SECRET_BACKEND`).
pub fn secret_backend_kind_from_env() -> SecretBackendKind {
    let Ok(raw) = std::env::var("NEUTRINO_SECRET_BACKEND") else {
        return SecretBackendKind::NeutrinoValence;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "local" | "manual" | "monolithic" => SecretBackendKind::LocalManual,
        "cloud" | "cloud_managed" | "external" => SecretBackendKind::CloudManagedStub,
        // "", "neutrino", "valence", and unrecognized values all default to Neutrino.
        _ => SecretBackendKind::NeutrinoValence,
    }
}

/// True when the selected kind uses the same Neutrino `SecretStore` implementation as production.
pub const fn uses_neutrino_sealed_store(kind: SecretBackendKind) -> bool {
    matches!(
        kind,
        SecretBackendKind::NeutrinoValence | SecretBackendKind::LocalManual
    )
}

/// Fail closed when `NEUTRINO_SECRET_BACKEND` selects an unsupported cloud/external kind.
///
/// Call before sealing or revealing so operators cannot believe a cloud vault is in use
/// while Valence continues silently.
pub fn ensure_secret_backend_supported() -> NeutrinoResult<()> {
    match secret_backend_kind_from_env() {
        SecretBackendKind::CloudManagedStub => Err(NeutrinoError::Unsupported {
            operation: "NEUTRINO_SECRET_BACKEND=cloud|cloud_managed|external",
        }),
        SecretBackendKind::NeutrinoValence | SecretBackendKind::LocalManual => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static BACKEND_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_backend_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _g = BACKEND_ENV_LOCK.lock().unwrap();
        let prev = std::env::var("NEUTRINO_SECRET_BACKEND").ok();
        match value {
            Some(v) => std::env::set_var("NEUTRINO_SECRET_BACKEND", v),
            None => std::env::remove_var("NEUTRINO_SECRET_BACKEND"),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var("NEUTRINO_SECRET_BACKEND", v),
            None => std::env::remove_var("NEUTRINO_SECRET_BACKEND"),
        }
        out
    }

    #[test]
    fn backend_kind_from_env_aliases() {
        with_backend_env(None, || {
            assert_eq!(
                secret_backend_kind_from_env(),
                SecretBackendKind::NeutrinoValence
            );
        });
        with_backend_env(Some("local"), || {
            assert_eq!(
                secret_backend_kind_from_env(),
                SecretBackendKind::LocalManual
            );
        });
        with_backend_env(Some("cloud_managed"), || {
            assert_eq!(
                secret_backend_kind_from_env(),
                SecretBackendKind::CloudManagedStub
            );
        });
        with_backend_env(Some("unknown-backend"), || {
            assert_eq!(
                secret_backend_kind_from_env(),
                SecretBackendKind::NeutrinoValence
            );
        });
    }

    #[test]
    fn uses_sealed_store_for_local_kinds() {
        assert!(uses_neutrino_sealed_store(
            SecretBackendKind::NeutrinoValence
        ));
        assert!(uses_neutrino_sealed_store(SecretBackendKind::LocalManual));
        assert!(!uses_neutrino_sealed_store(
            SecretBackendKind::CloudManagedStub
        ));
    }

    #[test]
    fn cloud_backend_fail_closed_sad() {
        with_backend_env(Some("cloud"), || {
            let err = ensure_secret_backend_supported().expect_err("cloud must fail closed");
            assert!(matches!(
                err,
                NeutrinoError::Unsupported {
                    operation: "NEUTRINO_SECRET_BACKEND=cloud|cloud_managed|external"
                }
            ));
        });
        with_backend_env(Some("external"), || {
            assert!(ensure_secret_backend_supported().is_err());
        });
    }

    #[test]
    fn default_and_local_backends_ok() {
        with_backend_env(None, || {
            ensure_secret_backend_supported().expect("default neutrino");
        });
        with_backend_env(Some("manual"), || {
            ensure_secret_backend_supported().expect("manual alias");
        });
    }
}
