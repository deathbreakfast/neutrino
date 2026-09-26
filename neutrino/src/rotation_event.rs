//! Photon `neutrino.secret.rotated` publish helpers (feature `photon`).

// Photon topic macro expands to futures-based publish helpers.
use futures as _;

/// Published after Neutrino material rotates (DB-scoped consumers apply via Gluon/Boson).
#[photon::topic(name = "neutrino.secret.rotated")]
pub struct NeutrinoSecretRotated {
    /// Neutrino secret id that rotated.
    pub secret_id: String,
    /// New secret version after rotation.
    pub version: i64,
    /// Optional logical backend / partition hint for consumers.
    #[serde(default)]
    pub logical: Option<String>,
    /// Optional scope path (for DB-scoped filter without a Valence secret load).
    #[serde(default)]
    pub scope_path: Option<String>,
    /// Idempotency / tracing key for Parton correlation.
    pub correlation: String,
}

/// Emit a rotation event (e.g. after a new secret version is committed).
pub async fn publish_neutrino_secret_rotated(
    secret_id: impl Into<String>,
    version: i64,
    logical: Option<String>,
    correlation: impl Into<String>,
) -> anyhow::Result<()> {
    publish_neutrino_secret_rotated_with_scope(secret_id, version, logical, None, correlation).await
}

/// Publish with an optional scope path (preferred for DB-scoped filter).
pub async fn publish_neutrino_secret_rotated_with_scope(
    secret_id: impl Into<String>,
    version: i64,
    logical: Option<String>,
    scope_path: Option<String>,
    correlation: impl Into<String>,
) -> anyhow::Result<()> {
    let _ = NeutrinoSecretRotated {
        secret_id: secret_id.into(),
        version,
        logical,
        scope_path,
        correlation: correlation.into(),
    }
    .publish()
    .await?;
    Ok(())
}

/// Publish only when `scope_path` is DB-scoped; otherwise no-op (`Ok(false)`).
pub async fn publish_if_db_scoped_secret_rotated(
    secret_id: impl Into<String>,
    version: i64,
    logical: Option<String>,
    scope_path: &str,
    correlation: impl Into<String>,
) -> anyhow::Result<bool> {
    if !crate::is_db_scoped_creds_path(scope_path) {
        return Ok(false);
    }
    publish_neutrino_secret_rotated_with_scope(
        secret_id,
        version,
        logical,
        Some(scope_path.trim().to_string()),
        correlation,
    )
    .await?;
    Ok(true)
}
