//! [`SecretStore`] trait and request/response types.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::NeutrinoResult;

/// Opaque secret identifier (Valence row id).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretId(
    /// Underlying Valence record id string.
    pub String,
);

/// Monotonic version number for a secret.
pub type SecretVersionId = i64;

/// Reference persisted in infra JSON (no plaintext).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRef {
    /// Secret id.
    pub id: SecretId,
    /// Version this reference points at.
    pub version: SecretVersionId,
}

/// Request to create (or reuse) a secret.
#[derive(Debug, Clone)]
pub struct PutSecretRequest {
    /// Human-readable secret name.
    pub name: String,
    /// Scope path the secret is stored under.
    pub scope_path: String,
    /// Secret kind/category (free-form, product-defined).
    pub kind: String,
    /// Raw plaintext bytes to seal.
    pub plaintext: Vec<u8>,
    /// Actor label recorded as the owner/creator.
    pub owner_actor: String,
}

/// A decrypted secret version, ready for one-shot use.
#[derive(Debug, Clone)]
pub struct RevealedSecret {
    /// Secret id.
    pub id: SecretId,
    /// Version that was revealed.
    pub version: SecretVersionId,
    /// Secret kind/category.
    pub kind: String,
    /// Decrypted plaintext bytes; zeroized on drop.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Creation timestamp of this secret.
    pub created_at: DateTime<Utc>,
}

/// Request a short-lived lease of plaintext for env injection / apply paths.
#[derive(Debug, Clone)]
pub struct LeaseRequest {
    /// Secret to lease.
    pub secret_id: SecretId,
    /// Pin a version when set; otherwise the current active version (or grace if requested).
    pub version: Option<SecretVersionId>,
    /// Subject label recorded on the lease (e.g. `gluon-agent-{cell}`).
    pub leased_to: String,
    /// How long the caller may treat the plaintext as valid.
    pub ttl: std::time::Duration,
}

/// Short-lived plaintext handle from [`SecretStore::lease`].
#[derive(Debug, Clone)]
pub struct SecretLease {
    /// Opaque lease id (correlation / audit).
    pub lease_id: String,
    /// Secret id.
    pub id: SecretId,
    /// Version that was leased.
    pub version: SecretVersionId,
    /// Decrypted plaintext; zeroized on drop.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Subject the lease was issued to.
    pub leased_to: String,
    /// When this lease should be considered expired.
    pub expires_at: DateTime<Utc>,
}

/// Backend-agnostic contract for storing, reading, and rotating secrets.
///
/// [`crate::sealed_store::ValenceSealedStore`] is the canonical Valence-backed
/// implementation; other backends (KMS/HSM adapters) can implement this trait
/// without changing callers.
///
/// # Errors
///
/// Methods return [`NeutrinoResult`]. Configuration failures from
/// [`crate::key_source::resolve_master_key`] surface as
/// [`crate::NeutrinoError::Config`] before they wrap into service failures
/// inside the sealed store.
///
/// `dyn SecretStore` requires the `async_trait` crate; that macro emits `#[must_use]`
/// on `Result`-returning methods, which trips `clippy::double_must_use` — allowed below.
#[async_trait]
#[allow(clippy::double_must_use)] // async_trait adds #[must_use] on Result methods
pub trait SecretStore: Send + Sync {
    /// Create a new secret (always creates a new id/version 1).
    async fn put(&self, req: PutSecretRequest) -> NeutrinoResult<SecretRef>;

    /// If a secret with the same `name` and `scope_path` already exists, return its
    /// [`SecretRef`] when the plaintext is unchanged, or [`rotate`](Self::rotate) when
    /// it changed. Otherwise creates a new row (same as [`put`](Self::put)).
    ///
    /// Default implementation always calls [`put`](Self::put) (always creates a new id).
    async fn put_or_reuse(&self, req: PutSecretRequest) -> NeutrinoResult<SecretRef> {
        self.put(req).await
    }

    /// Decrypt and return the current version of a secret.
    async fn get(&self, id: &SecretId) -> NeutrinoResult<RevealedSecret>;

    /// Remove a secret and all versions. Default: not supported.
    async fn delete(&self, _id: &SecretId) -> NeutrinoResult<()> {
        Err(crate::NeutrinoError::unsupported("delete"))
    }

    /// Replace ciphertext with a new version row; bumps [`SecretRef::version`]. Default: not supported.
    ///
    /// The previous version is left in `grace` status so consumers can still lease it during
    /// apply windows. Call [`extend_grace`](Self::extend_grace) after a failed apply to keep
    /// that prior version leaseable.
    async fn rotate(
        &self,
        _id: &SecretId,
        _new_plaintext: Vec<u8>,
        _actor: &str,
    ) -> NeutrinoResult<SecretRef> {
        Err(crate::NeutrinoError::unsupported("rotate"))
    }

    /// Decrypt an `active` or `grace` version for short-lived use (Reveal-gated).
    ///
    /// Default: not supported.
    async fn lease(&self, _req: LeaseRequest) -> NeutrinoResult<SecretLease> {
        Err(crate::NeutrinoError::unsupported("lease"))
    }

    /// Mark the version immediately prior to `current_version` as `grace` so it remains
    /// leaseable after a failed consumer apply. Default: not supported.
    async fn extend_grace(
        &self,
        _id: &SecretId,
        _grace_secs: u64,
        _actor: &str,
    ) -> NeutrinoResult<()> {
        Err(crate::NeutrinoError::unsupported("extend_grace"))
    }

    /// Health check for wiring tests.
    async fn ping(&self) -> NeutrinoResult<()> {
        Ok(())
    }
}
