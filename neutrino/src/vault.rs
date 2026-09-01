//! Product-local vault API used by `neutrino-app` `#[server]` wrappers.
//!
//! These functions implement create / list / reveal / rotate / delete / ping
//! against [`crate::ValenceSealedStore`]. Validation messages never include
//! plaintext secret values.
//!
//! Authorization: list/reveal/delete/rotate require per-secret Gauge permissions when
//! available, with [`VaultAccessContext`] as a compat bridge for scope-prefix break-glass.
//! Audit attribution: pass the request actor via [`store_from_valence_for_request`] while
//! keeping system Valence for ORM.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use valence::Valence;

use crate::error::{NeutrinoError, NeutrinoResult};
use crate::sealed_store::{list_secrets, ListedSecret, ValenceSealedStore};
use crate::secret_store::{PutSecretRequest, SecretId, SecretStore};
use crate::vault_authz::ensure_can_access_secret;
use crate::vault_gauge::{actor_can_secret, auth_valence_for_access};
use gauge::resource_permissions::ResourceAction;

pub use crate::vault_authz::VaultAccessContext;

async fn ensure_vault_reveal(
    orm_v: &Valence,
    access: &VaultAccessContext,
    secret_id: &str,
    owner_subject_json: &str,
    scope_path: &str,
) -> NeutrinoResult<()> {
    let auth_v = auth_valence_for_access(orm_v, access.actor_label.as_str());
    if actor_can_secret(&auth_v, secret_id, ResourceAction::Reveal).await? {
        return Ok(());
    }
    ensure_can_access_secret(access, owner_subject_json, scope_path)
}

async fn ensure_vault_edit(
    orm_v: &Valence,
    access: &VaultAccessContext,
    secret_id: &str,
    owner_subject_json: &str,
    scope_path: &str,
) -> NeutrinoResult<()> {
    let auth_v = auth_valence_for_access(orm_v, access.actor_label.as_str());
    if actor_can_secret(&auth_v, secret_id, ResourceAction::Edit).await? {
        return Ok(());
    }
    ensure_can_access_secret(access, owner_subject_json, scope_path)
}

async fn ensure_vault_delete(
    orm_v: &Valence,
    access: &VaultAccessContext,
    secret_id: &str,
    owner_subject_json: &str,
    scope_path: &str,
) -> NeutrinoResult<()> {
    let auth_v = auth_valence_for_access(orm_v, access.actor_label.as_str());
    if actor_can_secret(&auth_v, secret_id, ResourceAction::Delete).await? {
        return Ok(());
    }
    ensure_can_access_secret(access, owner_subject_json, scope_path)
}

/// Row for vault list views (no ciphertext / plaintext).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSecretRow {
    /// Secret id.
    pub id: String,
    /// Human-readable secret name.
    pub name: String,
    /// Scope path the secret is stored under (e.g. `/gluon/provider_account/...`).
    pub scope_path: String,
    /// Secret kind/category (free-form, product-defined).
    pub kind: String,
    /// Current version number (increments on rotate).
    pub current_version: i64,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
}

/// One-shot reveal payload (base64 for JSON-safe transport).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevealedVaultSecret {
    /// Base64-encoded plaintext; zeroized on drop.
    pub plaintext_b64: String,
}

impl std::fmt::Debug for RevealedVaultSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevealedVaultSecret")
            .field("plaintext_b64", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RevealedVaultSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.plaintext_b64.zeroize();
    }
}

fn require_trimmed(field: &'static str, value: &str) -> NeutrinoResult<String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(NeutrinoError::validation(
            field,
            format!("{field} is required."),
        ));
    }
    Ok(trimmed)
}

fn require_plaintext(plaintext: String) -> NeutrinoResult<Vec<u8>> {
    let bytes = plaintext.into_bytes();
    if bytes.is_empty() {
        return Err(NeutrinoError::validation(
            "Plaintext",
            "Plaintext is required.",
        ));
    }
    Ok(bytes)
}

fn require_new_plaintext(new_plaintext: String) -> NeutrinoResult<Vec<u8>> {
    let bytes = new_plaintext.into_bytes();
    if bytes.is_empty() {
        return Err(NeutrinoError::validation(
            "New plaintext",
            "New plaintext is required.",
        ));
    }
    Ok(bytes)
}

fn require_secret_id(id: &str) -> NeutrinoResult<String> {
    require_trimmed("Secret id", id)
}

fn row_from_listed(r: ListedSecret) -> VaultSecretRow {
    VaultSecretRow {
        id: r.id,
        name: r.name,
        scope_path: r.scope_path,
        kind: r.kind,
        current_version: r.current_version,
        created_at: r.created_at.to_rfc3339(),
    }
}

async fn listed_for_id(valence: &Valence, sid: &str) -> NeutrinoResult<ListedSecret> {
    let listed = list_secrets(valence).await?;
    listed
        .into_iter()
        .find(|r| r.id == sid)
        .ok_or_else(|| NeutrinoError::not_found(sid))
}

/// Verifies that the sealed store can be reached (health check).
pub async fn neutrino_vault_ping(store: &ValenceSealedStore) -> NeutrinoResult<()> {
    store.ping().await
}

/// Lists non-sensitive metadata for every vault secret (browsable by decision).
///
/// The returned DTO excludes ciphertext and `owner_subject_json`; reveal/delete/rotate
/// still enforce per-secret Gauge permissions separately.
pub async fn list_vault_secrets(
    valence: &Valence,
    _access: &VaultAccessContext,
) -> NeutrinoResult<Vec<VaultSecretRow>> {
    let listed = list_secrets(valence).await?;
    Ok(listed
        .into_iter()
        .filter(|r| !r.id.is_empty())
        .map(row_from_listed)
        .collect())
}

/// Creates a new secret (version 1).
pub async fn create_vault_secret(
    store: &ValenceSealedStore,
    name: String,
    scope_path: String,
    kind: String,
    plaintext: String,
    owner_actor: String,
) -> NeutrinoResult<VaultSecretRow> {
    let name = require_trimmed("Name", &name)?;
    let scope_path = require_trimmed("Scope path", &scope_path)?;
    let kind = require_trimmed("Kind", &kind)?;
    let pt = require_plaintext(plaintext)?;

    let pref = store
        .put(PutSecretRequest {
            name: name.clone(),
            scope_path: scope_path.clone(),
            kind: kind.clone(),
            plaintext: pt,
            owner_actor,
        })
        .await?;

    Ok(VaultSecretRow {
        id: pref.id.0,
        name,
        scope_path,
        kind,
        current_version: pref.version,
        created_at: Utc::now().to_rfc3339(),
    })
}

/// Returns the current version plaintext (base64) when `access` is authorized.
pub async fn reveal_vault_secret(
    store: &ValenceSealedStore,
    id: String,
    access: &VaultAccessContext,
) -> NeutrinoResult<RevealedVaultSecret> {
    let sid = require_secret_id(&id)?;
    let meta = listed_for_id(store.valence.as_ref(), &sid).await?;
    ensure_vault_reveal(
        store.valence.as_ref(),
        access,
        &sid,
        &meta.owner_subject_json,
        &meta.scope_path,
    )
    .await?;
    let revealed = store.get(&SecretId(sid)).await?;
    Ok(RevealedVaultSecret {
        plaintext_b64: B64.encode(revealed.plaintext.as_slice()),
    })
}

/// Deletes a secret and all versions when `access` is authorized.
///
/// [`ValenceSealedStore::delete`](crate::ValenceSealedStore::delete) queues Valence
/// pending-deletion; this then runs the deletion DAG so list/reveal no longer see
/// the row (product hard-delete contract).
pub async fn delete_vault_secret(
    store: &ValenceSealedStore,
    id: String,
    access: &VaultAccessContext,
) -> NeutrinoResult<()> {
    let sid = require_secret_id(&id)?;
    let meta = listed_for_id(store.valence.as_ref(), &sid).await?;
    ensure_vault_delete(
        store.valence.as_ref(),
        access,
        &sid,
        &meta.owner_subject_json,
        &meta.scope_path,
    )
    .await?;
    store.delete(&SecretId(sid.clone())).await?;
    finalize_secret_deletion(store.valence.as_ref(), &sid).await
}

const SECRET_TABLE: &str = "neutrino_secret";

async fn finalize_secret_deletion(valence: &Valence, bare_id: &str) -> NeutrinoResult<()> {
    let dag = valence::deletion::dag::DeletionDag::compute(SECRET_TABLE, bare_id, valence)
        .await
        .map_err(|e| NeutrinoError::service("delete_dag", e))?;
    if !dag.restrict_violations.is_empty() {
        return Err(NeutrinoError::service(
            "delete_dag",
            anyhow::anyhow!(
                "secret delete restricted ({} violation(s))",
                dag.restrict_violations.len()
            ),
        ));
    }
    for node in &dag.nodes {
        let backend = valence
            .backend_for_table(&node.table)
            .map_err(|e| NeutrinoError::service("delete_dag", e))?;
        backend
            .delete_record(&node.table, &node.record_id)
            .await
            .map_err(|e| NeutrinoError::service("delete_dag", e))?;
    }
    Ok(())
}

/// Rotates ciphertext to a new version and returns updated metadata.
pub async fn rotate_vault_secret(
    store: &ValenceSealedStore,
    id: String,
    new_plaintext: String,
    actor: &str,
    access: &VaultAccessContext,
) -> NeutrinoResult<VaultSecretRow> {
    let sid = require_secret_id(&id)?;
    let meta = listed_for_id(store.valence.as_ref(), &sid).await?;
    ensure_vault_edit(
        store.valence.as_ref(),
        access,
        &sid,
        &meta.owner_subject_json,
        &meta.scope_path,
    )
    .await?;
    let pt = require_new_plaintext(new_plaintext)?;

    let cref = store.rotate(&SecretId(sid.clone()), pt, actor).await?;
    let _ = cref;

    let listed = list_secrets(store.valence.as_ref()).await?;
    let row = listed
        .into_iter()
        .find(|r| r.id == sid)
        .ok_or_else(|| NeutrinoError::not_found(&sid))?;

    Ok(row_from_listed(row))
}

/// Convenience: build a [`ValenceSealedStore`] from an owned [`Valence`] (no
/// request-actor audit override).
#[must_use]
pub fn store_from_valence(valence: Valence) -> ValenceSealedStore {
    ValenceSealedStore {
        valence: Arc::new(valence),
        request_actor: None,
    }
}

/// Build a store that uses system/ORM Valence but attributes audit rows to
/// `request_actor`.
#[must_use]
pub fn store_from_valence_for_request(
    valence: Valence,
    request_actor: impl Into<String>,
) -> ValenceSealedStore {
    ValenceSealedStore {
        valence: Arc::new(valence),
        request_actor: Some(request_actor.into()),
    }
}

#[cfg(test)]
mod validation_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::{
        require_new_plaintext, require_plaintext, require_secret_id, require_trimmed,
        RevealedVaultSecret,
    };

    #[test]
    fn create_fields_reject_blank_sad() {
        assert!(require_trimmed("Name", "  ").is_err());
        assert!(require_trimmed("Scope path", "").is_err());
        assert!(require_trimmed("Kind", "\t").is_err());
        let err = require_trimmed("Name", "").unwrap_err().to_string();
        assert!(err.contains("Name is required"));
    }

    #[test]
    fn plaintext_reject_empty_sad() {
        let err = require_plaintext(String::new()).unwrap_err().to_string();
        assert!(err.contains("Plaintext is required"));
        // Never embed caller-supplied secret material in the error.
        assert!(!err.contains("hunter2"));
    }

    #[test]
    fn rotate_plaintext_reject_empty_sad() {
        let err = require_new_plaintext(String::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("New plaintext is required"));
    }

    #[test]
    fn secret_id_reject_blank_sad() {
        let err = require_secret_id("   ").unwrap_err().to_string();
        assert!(err.contains("Secret id is required"));
    }

    #[test]
    fn trimmed_fields_accepted_happy_path() {
        assert_eq!(require_trimmed("Name", "  smtp  ").unwrap(), "smtp");
        assert_eq!(require_plaintext("ok".into()).unwrap(), b"ok".to_vec());
        assert_eq!(require_secret_id("abc").unwrap(), "abc");
    }

    #[test]
    fn revealed_vault_secret_debug_redacts_plaintext() {
        let secret = RevealedVaultSecret {
            plaintext_b64: "c2VjcmV0".into(),
        };
        let dbg = format!("{secret:?}");
        assert!(!dbg.contains("c2VjcmV0"));
        assert!(dbg.contains("REDACTED"));
    }
}
