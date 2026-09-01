//! Deployment-agnostic secret backend selection (Neutrino default; cloud adapters optional).

/// Which logical backend is selected for secret materialization.
///
/// Set `NEUTRINO_SECRET_BACKEND` to `neutrino` (default), `local`, `manual`, or `cloud` / `cloud_managed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretBackendKind {
    /// [`crate::ValenceSealedStore`] — canonical encrypted Valence path.
    NeutrinoValence,
    /// Explicit alias for manual/monolithic deployments using the same store.
    LocalManual,
    /// Future: external vault; currently [`secret_backend_kind_from_env`] still maps to Neutrino for steady-state until adapters land.
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
}
