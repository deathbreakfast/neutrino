//! One-time bootstrap seeding: copy bootstrap-only env material into Neutrino and emit `SecretRef` JSON for `scoped_credentials_refs_json`.

use serde::Serialize;

use crate::error::{NeutrinoError, NeutrinoResult};
use crate::secret_store::{PutSecretRequest, SecretRef, SecretStore};

/// Serializable `{ id, version, kind? }` envelope for `scoped_credentials_refs_json`
/// (same wire shape Nucleus provisioner credentials use).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecretRefEnvelopeWire {
    /// Secret id.
    pub id: String,
    /// Secret version, as a string (matches the upstream wire shape).
    pub version: String,
    /// Optional secret kind/category, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl From<SecretRef> for SecretRefEnvelopeWire {
    fn from(r: SecretRef) -> Self {
        Self {
            id: r.id.0,
            version: r.version.to_string(),
            kind: None,
        }
    }
}

/// Result of seeding bootstrap secrets from the environment into [`SecretStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededBootstrapSecrets {
    /// JSON array of [`SecretRefEnvelopeWire`] for `scoped_credentials_refs_json`.
    pub scoped_credentials_refs_json: String,
    /// True if at least one secret was written.
    pub seeded_any: bool,
}

/// Same as [`seed_bootstrap_secrets_from_env`] but accepts optional migration HMAC (for tests and deterministic seeding).
pub async fn seed_bootstrap_secrets_with(
    store: &dyn SecretStore,
    owner_actor: &str,
    migration_hmac: Option<&str>,
) -> NeutrinoResult<SeededBootstrapSecrets> {
    let mut refs: Vec<SecretRefEnvelopeWire> = Vec::new();

    if let Some(t) = migration_hmac.map(str::trim).filter(|s| !s.is_empty()) {
        let req = PutSecretRequest {
            name: "cp_migration_hmac".to_string(),
            scope_path: "/gluon/bootstrap".to_string(),
            kind: "migration_hmac".to_string(),
            plaintext: t.as_bytes().to_vec(),
            owner_actor: owner_actor.to_string(),
        };
        let r = store.put(req).await?;
        let mut env = SecretRefEnvelopeWire::from(r);
        env.kind = Some("migration_hmac".to_string());
        refs.push(env);
    }

    let seeded_any = !refs.is_empty();
    let scoped_credentials_refs_json =
        serde_json::to_string(&refs).map_err(|e| NeutrinoError::service("bootstrap_seed", e))?;
    Ok(SeededBootstrapSecrets {
        scoped_credentials_refs_json,
        seeded_any,
    })
}

/// Reads bootstrap-classified env vars and persists them via Neutrino, returning refs for infra snapshots.
///
/// Idempotent best-effort: duplicate puts may create new secret rows; callers should run once after DB placement.
pub async fn seed_bootstrap_secrets_from_env(
    store: &dyn SecretStore,
    owner_actor: &str,
) -> NeutrinoResult<SeededBootstrapSecrets> {
    let migration_hmac = if let (Ok(id), Ok(ver_s)) = (
        std::env::var("GLUON_CP_MIGRATION_HMAC_SECRET_ID"),
        std::env::var("GLUON_CP_MIGRATION_HMAC_SECRET_VERSION"),
    ) {
        let id = id.trim().to_string();
        let ver: i64 = ver_s.trim().parse().unwrap_or(0);
        if id.is_empty() || ver <= 0 {
            None
        } else {
            let revealed = store
                .get(&crate::secret_store::SecretId(id.clone()))
                .await?;
            if revealed.version as i64 != ver {
                return Err(NeutrinoError::validation(
                    "GLUON_CP_MIGRATION_HMAC_SECRET_VERSION",
                    format!(
                        "GLUON_CP_MIGRATION_HMAC_SECRET_VERSION mismatch (expected {}, got {})",
                        ver, revealed.version
                    ),
                ));
            }
            Some(String::from_utf8(revealed.plaintext.to_vec()).map_err(|e| {
                NeutrinoError::service(
                    "bootstrap_seed",
                    anyhow::anyhow!("migration hmac utf-8: {e}"),
                )
            })?)
        }
    } else {
        std::env::var("GLUON_CP_MIGRATION_HMAC_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    seed_bootstrap_secrets_with(store, owner_actor, migration_hmac.as_deref()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::{RevealedSecret, SecretId};
    use async_trait::async_trait;

    struct MockStore {
        puts: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl SecretStore for MockStore {
        async fn put(&self, req: PutSecretRequest) -> NeutrinoResult<SecretRef> {
            self.puts.lock().unwrap().push(req.name);
            Ok(SecretRef {
                id: SecretId("test-id".into()),
                version: 1,
            })
        }

        async fn get(&self, _: &SecretId) -> NeutrinoResult<RevealedSecret> {
            Err(NeutrinoError::service("mock", anyhow::anyhow!("mock")))
        }
    }

    #[tokio::test]
    async fn seed_empty_without_material() {
        let store = MockStore {
            puts: std::sync::Mutex::new(vec![]),
        };
        let out = seed_bootstrap_secrets_with(&store, "system", None)
            .await
            .unwrap();
        assert!(!out.seeded_any);
        assert_eq!(out.scoped_credentials_refs_json, "[]");
    }

    #[tokio::test]
    async fn seed_writes_migration_hmac_when_provided() {
        let store = MockStore {
            puts: std::sync::Mutex::new(vec![]),
        };
        let out = seed_bootstrap_secrets_with(&store, "system", Some("supersecret"))
            .await
            .unwrap();
        assert!(out.seeded_any);
        assert!(out.scoped_credentials_refs_json.contains("test-id"));
        assert_eq!(store.puts.lock().unwrap().len(), 1);
    }
}
