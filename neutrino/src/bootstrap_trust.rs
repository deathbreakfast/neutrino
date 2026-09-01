//! Bootstrap vs steady-state secret classification — see [`crate`]-level rustdoc for
//! the full bootstrap-vs-steady-state model.
//!
//! | Env key | Class | Notes |
//! |---------|-------|-------|
//! | `NEUTRINO_MASTER_KEY`, `BOOTSTRAP_DB_*`, setup-wizard / Parton tokens | [`SecretLifecycleClass::BootstrapRequired`] | Needed before Neutrino can open |
//! | `UF_SMTP_*` | [`SecretLifecycleClass::OperatorOptional`] | Migrate when ready |
//! | `UF_OAUTH_GOOGLE_CLIENT_SECRET`, `UF_OAUTH_GITHUB_CLIENT_SECRET` | [`SecretLifecycleClass::SteadyState`] | First-boot env seed into Neutrino (`oauth.*.client_secret`); steady-state `get` by name |

/// How a secret is expected to be sourced over the deployment lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretLifecycleClass {
    /// First-boot / connectivity only; may appear in env until Neutrino (or DB) is seeded.
    BootstrapRequired,
    /// Must live in Neutrino (or an adapter with the same contract) after cutover.
    SteadyState,
    /// Optional operator env until migrated (document per integration).
    OperatorOptional,
}

/// Classify well-known bootstrap env keys. Unknown keys return `None` (callers treat as unclassified).
pub fn classify_env_key(name: &str) -> Option<SecretLifecycleClass> {
    match name.trim() {
        "NEUTRINO_MASTER_KEY"
        | "BOOTSTRAP_DB_URL"
        | "BOOTSTRAP_DB_LOGICALS_JSON"
        | "BOOTSTRAP_DB_USER"
        | "BOOTSTRAP_DB_PASS"
        | "BOOTSTRAP_DB_NS"
        | "BOOTSTRAP_DB_DATABASE"
        | "SETUP_WIZARD_IMPORT_TOKEN"
        | "SETUP_WIZARD_INTERNAL_SECRET"
        | "SETUP_WIZARD_BOOTSTRAP_MODE"
        | "SETUP_WIZARD_BOOTSTRAP_ID"
        | "SETUP_WIZARD_ALLOW_IMPORT"
        | "GLUON_CP_MIGRATION_HMAC_KEY"
        | "PARTON_SHARED_TOKEN"
        | "PARTON_ENROLLMENT_TOKEN" => Some(SecretLifecycleClass::BootstrapRequired),
        "UF_SMTP_PASSWORD" | "UF_SMTP_USERNAME" => Some(SecretLifecycleClass::OperatorOptional),
        "UF_OAUTH_GOOGLE_CLIENT_SECRET" | "UF_OAUTH_GITHUB_CLIENT_SECRET" => {
            Some(SecretLifecycleClass::SteadyState)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_bootstrap_keys() {
        assert_eq!(
            classify_env_key("NEUTRINO_MASTER_KEY"),
            Some(SecretLifecycleClass::BootstrapRequired)
        );
        assert_eq!(
            classify_env_key("BOOTSTRAP_DB_LOGICALS_JSON"),
            Some(SecretLifecycleClass::BootstrapRequired)
        );
        assert_eq!(
            classify_env_key("UF_SMTP_PASSWORD"),
            Some(SecretLifecycleClass::OperatorOptional)
        );
        assert_eq!(
            classify_env_key("UF_OAUTH_GOOGLE_CLIENT_SECRET"),
            Some(SecretLifecycleClass::SteadyState)
        );
        assert_eq!(
            classify_env_key("UF_OAUTH_GITHUB_CLIENT_SECRET"),
            Some(SecretLifecycleClass::SteadyState)
        );
        assert!(classify_env_key("UNKNOWN_KEY_XYZ").is_none());
    }
}
