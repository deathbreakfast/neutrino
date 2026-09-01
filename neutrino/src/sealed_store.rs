//! Valence-backed [`crate::secret_store::SecretStore`] using [`crate::crypto`].

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use valence::extract_id_from_record;
use valence::extract_id_from_record_display;
use valence::Model;
use valence::RecordId;
use valence::RecordPredicate;
use valence::Valence;

use crate::crypto;
use crate::error::{NeutrinoError, NeutrinoResult};
use crate::generated::{NeutrinoSecret, NeutrinoSecretVersion, NeutrinoSecretVersionStatus};
use crate::instrumentation::{
    append_denial_audit_event, append_valence_audit_event, current_secret_access_caller,
    record_secret_access, viewer_key_from_actor, SecretAccessRecord,
};
use crate::key_source::master_key_from_env;
use crate::secret_store::{PutSecretRequest, RevealedSecret, SecretId, SecretRef, SecretStore};
use crate::vault_authz::{ensure_can_access_secret, VaultAccessContext};
use crate::vault_gauge::{
    actor_can_secret, auth_valence_for_store, delete_secret_permission_bundle,
    ensure_can_create_secret, ensure_secret_permission_bundle, maintainer_actor_for_put,
};
use gauge::resource_permissions::ResourceAction;

/// Non-sensitive row for vault listings (no ciphertext).
#[derive(Debug, Clone)]
pub struct ListedSecret {
    /// Secret id.
    pub id: String,
    /// Human-readable secret name.
    pub name: String,
    /// Scope path the secret is stored under.
    pub scope_path: String,
    /// Secret kind/category.
    pub kind: String,
    /// Current version number.
    pub current_version: i64,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Owner / grant JSON used for per-secret authz.
    pub owner_subject_json: String,
}

/// All [`NeutrinoSecret`] rows (metadata only), sorted by `created_at` ascending.
///
/// Returns every secret's metadata; `owner_subject_json` is included for vault-layer
/// authz bridges but must not appear in product list DTOs ([`crate::vault::VaultSecretRow`]).
pub async fn list_secrets(valence: &Valence) -> NeutrinoResult<Vec<ListedSecret>> {
    let mut rows: Vec<NeutrinoSecret> = NeutrinoSecret::query(valence)
        .await
        .map_err(|e| NeutrinoError::service("valence", e))?;
    rows.sort_by_key(|r| *r.created_at());
    Ok(rows
        .into_iter()
        .map(|r| ListedSecret {
            id: r
                .id()
                .map(|rec| extract_id_from_record(rec).unwrap_or_else(|_| rec.to_string()))
                .unwrap_or_default(),
            name: r.name().clone(),
            scope_path: r.scope_path().clone(),
            kind: r.kind().clone(),
            current_version: *r.current_version(),
            created_at: *r.created_at(),
            owner_subject_json: owner_subject_wire(r.owner_subject_json()),
        })
        .collect())
}

/// Wire form for [`crate::vault_authz`] (JSON object text).
///
/// SQLite read/update paths sometimes surface the document as a JSON string
/// scalar (possibly nested). Unwrap until we have an object/array or a plain
/// actor label.
fn owner_subject_wire(v: &serde_json::Value) -> String {
    match normalize_owner_subject_value(v.clone()) {
        serde_json::Value::Null => "{}".to_string(),
        other => serde_json::to_string(&other).unwrap_or_else(|_| "{}".to_string()),
    }
}

fn normalize_owner_subject_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return serde_json::json!({});
            }
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
                return normalize_owner_subject_value(parsed);
            }
            serde_json::json!({ "actor": s })
        }
        other => other,
    }
}

const KEY_ID: &str = "argon2id-v1";

fn salt_for(secret_id: &str, ver: i64) -> Vec<u8> {
    format!("{secret_id}|v{ver}").into_bytes()
}

fn audit_actor_from_valence(valence: &Valence) -> String {
    match valence.actor().user_id() {
        Some(user_id) => user_id.to_string(),
        None => match valence.actor() {
            valence::Actor::ServiceUser { service_name } => service_name.clone(),
            valence::Actor::System { operation } => operation.clone(),
            valence::Actor::Anonymous => "anonymous".to_string(),
            valence::Actor::User { user_id } => user_id.clone(),
        },
    }
}

/// Prefer the request actor threaded from the product vault layer; fall
/// back to the Valence ORM actor (often System) only when unset.
fn audit_actor_for_store(store: &ValenceSealedStore) -> String {
    store
        .request_actor
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| audit_actor_from_valence(store.valence.as_ref()))
}

fn viewer_key_for_store(store: &ValenceSealedStore) -> String {
    store
        .request_actor
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| viewer_key_from_actor(store.valence.actor()))
}

fn audit_append_must_succeed(action: &'static str) -> bool {
    matches!(action, "put" | "delete" | "rotate")
}

/// Gate for `put_or_reuse` when a name+scope row already exists (decrypt / rotate).
///
/// Create permission alone must not authorize overwriting another principal's secret.
/// System / Super User / per-secret Edit, or owner/grant/prefix via
/// [`VaultAccessContext`], may proceed — same OR story as vault rotate.
async fn ensure_may_reuse_or_rotate_existing(
    store: &ValenceSealedStore,
    secret_id: &str,
    owner_subject_json: &str,
    scope_path: &str,
) -> NeutrinoResult<()> {
    let auth_v = auth_valence_for_store(store);
    if actor_can_secret(&auth_v, secret_id, ResourceAction::Edit).await? {
        return Ok(());
    }
    let label = store
        .request_actor
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| audit_actor_from_valence(store.valence.as_ref()));
    let access = VaultAccessContext::owner_only(label);
    ensure_can_access_secret(&access, owner_subject_json, scope_path)
}

async fn emit_access(
    store: &ValenceSealedStore,
    action: &'static str,
    audit_actor: &str,
    secret_id: &str,
    version_num: i64,
    scope_path: &str,
    secret_name: &str,
    outcome: &'static str,
    error_message: &str,
) -> NeutrinoResult<()> {
    let viewer_key = viewer_key_for_store(store);
    record_secret_access(SecretAccessRecord {
        action,
        secret_id: secret_id.to_string(),
        version_num,
        scope_path: scope_path.to_string(),
        secret_name: secret_name.to_string(),
        outcome,
        viewer_key,
        caller: crate::instrumentation::access::current_secret_access_caller(),
        error_message: error_message.to_string(),
    });
    let audit_outcome = match outcome {
        "ok" => "ok",
        "denied" => "denied",
        _ => "error",
    };
    match if audit_outcome == "denied" {
        append_denial_audit_event(
            store.valence.as_ref(),
            audit_actor,
            action,
            secret_id,
            version_num,
            error_message,
        )
        .await
    } else {
        append_valence_audit_event(
            store.valence.as_ref(),
            audit_actor,
            action,
            secret_id,
            version_num,
            audit_outcome,
            error_message,
        )
        .await
    } {
        Ok(()) => Ok(()),
        Err(e) => {
            log::warn!(
                target: "neutrino_sealed_store",
                "audit append failed action={action} secret_id={secret_id}: {e}"
            );
            if audit_append_must_succeed(action) {
                Err(NeutrinoError::service("audit_append", e))
            } else {
                Ok(())
            }
        }
    }
}

/// Production store: encrypts with `NEUTRINO_MASTER_KEY`, persists via Valence models.
pub struct ValenceSealedStore {
    /// Valence handle used for all model reads/writes and audit event appends.
    ///
    /// Vault server fns keep this as **system** Valence so ORM privacy
    /// (`SYSTEM_ONLY`) succeeds; human attribution uses [`Self::request_actor`].
    pub valence: Arc<Valence>,
    /// Authenticated request actor label for audit/telemetry.
    /// When `None`, audit falls back to [`Self::valence`]'s actor.
    pub request_actor: Option<String>,
}

#[async_trait]
impl SecretStore for ValenceSealedStore {
    async fn put(&self, req: PutSecretRequest) -> NeutrinoResult<SecretRef> {
        let auth_v = auth_valence_for_store(self);
        ensure_can_create_secret(&auth_v).await?;

        let master = master_key_from_env()?;
        let ver: i64 = 1;
        let now = Utc::now();
        let sid = Uuid::new_v4().to_string();
        let maintainer = maintainer_actor_for_put(self, req.owner_actor.as_str());

        ensure_secret_permission_bundle(
            self.valence.as_ref(),
            sid.as_str(),
            req.name.as_str(),
            maintainer.as_str(),
        )
        .await?;

        let secret_row = NeutrinoSecret::new(
            req.name.clone(),
            req.scope_path.clone(),
            req.kind.clone(),
            ver,
            serde_json::json!({ "actor": req.owner_actor }),
            serde_json::json!({}),
            now,
            now,
        )
        .map_err(|e| NeutrinoError::service("valence", e))?;

        let created = match NeutrinoSecret::upsert(sid.as_str(), secret_row, self.valence.as_ref())
            .await
        {
            Ok(row) => row,
            Err(e) => {
                let _ = delete_secret_permission_bundle(self.valence.as_ref(), sid.as_str()).await;
                return Err(NeutrinoError::service("valence", e));
            }
        };
        let Some(rec) = created.id() else {
            let _ = delete_secret_permission_bundle(self.valence.as_ref(), sid.as_str()).await;
            return Err(NeutrinoError::service(
                "put",
                anyhow::anyhow!("secret create missing id"),
            ));
        };
        let persisted_id =
            extract_id_from_record(rec).map_err(|e| NeutrinoError::service("valence", e))?;

        let salt = salt_for(persisted_id.as_str(), ver);
        let (nonce, ct) = crypto::seal(master.as_slice(), &salt, &req.plaintext)?;
        let secret_rid = RecordId::new("neutrino_secret", persisted_id.as_str());

        let ver_row = NeutrinoSecretVersion::new(
            secret_rid,
            ver,
            B64.encode(&ct),
            B64.encode(&nonce),
            KEY_ID.to_string(),
            NeutrinoSecretVersionStatus::Active,
            now,
            req.owner_actor.clone(),
        )
        .map_err(|e| NeutrinoError::service("valence", e))?;

        if let Err(e) = NeutrinoSecretVersion::create(ver_row, self.valence.as_ref()).await {
            let _ = NeutrinoSecret::delete(persisted_id.as_str(), self.valence.as_ref()).await;
            let _ =
                delete_secret_permission_bundle(self.valence.as_ref(), persisted_id.as_str()).await;
            return Err(NeutrinoError::service("valence", e));
        }

        emit_access(
            self,
            "put",
            req.owner_actor.as_str(),
            persisted_id.as_str(),
            ver,
            req.scope_path.as_str(),
            req.name.as_str(),
            "ok",
            "",
        )
        .await?;

        Ok(SecretRef {
            id: SecretId(persisted_id),
            version: ver,
        })
    }

    async fn put_or_reuse(&self, req: PutSecretRequest) -> NeutrinoResult<SecretRef> {
        let mut matches: Vec<NeutrinoSecret> = NeutrinoSecret::query(self.valence.as_ref())
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?
            .into_iter()
            .filter(|r| r.name() == &req.name && r.scope_path() == &req.scope_path)
            .collect();
        if matches.is_empty() {
            return self.put(req).await;
        }
        matches.sort_by_key(|r| *r.updated_at());
        if matches.len() > 1 {
            record_secret_access(SecretAccessRecord {
                action: "put_or_reuse",
                secret_id: String::new(),
                version_num: 0,
                scope_path: req.scope_path.clone(),
                secret_name: req.name.clone(),
                outcome: "ok",
                viewer_key: viewer_key_from_actor(self.valence.actor()),
                caller: current_secret_access_caller(),
                error_message: format!(
                    "duplicate rows for name={} scope={}; using latest by updated_at",
                    req.name, req.scope_path
                ),
            });
        }
        let existing = matches.pop().ok_or_else(|| {
            NeutrinoError::service(
                "put_or_reuse",
                anyhow::anyhow!("put_or_reuse: expected non-empty"),
            )
        })?;
        let rec = existing.id().ok_or_else(|| {
            NeutrinoError::service(
                "put_or_reuse",
                anyhow::anyhow!("neutrino secret missing id"),
            )
        })?;
        let sid = extract_id_from_record(rec).map_err(|e| NeutrinoError::service("valence", e))?;
        let owner_json = owner_subject_wire(existing.owner_subject_json());
        ensure_may_reuse_or_rotate_existing(
            self,
            sid.as_str(),
            owner_json.as_str(),
            existing.scope_path().as_str(),
        )
        .await?;
        let id = SecretId(sid);
        let revealed = self.get(&id).await?;
        if revealed.plaintext.as_slice() == req.plaintext.as_slice() {
            record_secret_access(SecretAccessRecord {
                action: "put_or_reuse",
                secret_id: id.0.clone(),
                version_num: *existing.current_version(),
                scope_path: existing.scope_path().clone(),
                secret_name: existing.name().clone(),
                outcome: "ok",
                viewer_key: viewer_key_from_actor(self.valence.actor()),
                caller: current_secret_access_caller(),
                error_message: String::new(),
            });
            return Ok(SecretRef {
                id: revealed.id,
                version: *existing.current_version(),
            });
        }
        self.rotate(&id, req.plaintext, req.owner_actor.as_str())
            .await
    }

    async fn get(&self, id: &SecretId) -> NeutrinoResult<RevealedSecret> {
        let id_key = extract_id_from_record_display(id.0.as_str()).unwrap_or_else(|_| id.0.clone());
        let secret = match NeutrinoSecret::get(&id_key, self.valence.as_ref()).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                let actor = audit_actor_for_store(self);
                emit_access(
                    self,
                    "get",
                    actor.as_str(),
                    id.0.as_str(),
                    0,
                    "",
                    "",
                    "not_found",
                    "secret not found",
                )
                .await?;
                return Err(NeutrinoError::not_found(&id.0));
            }
            Err(e) => {
                let msg = e.to_string();
                let actor = audit_actor_for_store(self);
                emit_access(
                    self,
                    "get",
                    actor.as_str(),
                    id.0.as_str(),
                    0,
                    "",
                    "",
                    "error",
                    msg.as_str(),
                )
                .await?;
                return Err(NeutrinoError::service("valence", anyhow::anyhow!(msg)));
            }
        };
        let vnum = *secret.current_version();
        self.reveal_at_version_with_action(id, vnum, "get").await
    }

    async fn delete(&self, id: &SecretId) -> NeutrinoResult<()> {
        let sid = id.0.as_str();
        let secret = NeutrinoSecret::get(sid, self.valence.as_ref())
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?
            .ok_or_else(|| NeutrinoError::not_found(sid))?;
        let ver = *secret.current_version();
        let scope_path = secret.scope_path().clone();
        let secret_name = secret.name().clone();

        let actor = audit_actor_for_store(self);
        emit_access(
            self,
            "delete",
            actor.as_str(),
            sid,
            ver,
            scope_path.as_str(),
            secret_name.as_str(),
            "ok",
            "",
        )
        .await?;

        delete_secret_permission_bundle(self.valence.as_ref(), sid).await?;
        NeutrinoSecret::delete(sid, self.valence.as_ref())
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?;
        Ok(())
    }

    async fn rotate(
        &self,
        id: &SecretId,
        new_plaintext: Vec<u8>,
        actor: &str,
    ) -> NeutrinoResult<SecretRef> {
        let master = master_key_from_env()?;
        let sid = id.0.as_str();
        let secret = NeutrinoSecret::get(sid, self.valence.as_ref())
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?
            .ok_or_else(|| NeutrinoError::not_found(sid))?;
        let scope_path = secret.scope_path().clone();
        let secret_name = secret.name().clone();
        let old_ver = *secret.current_version();
        let new_ver = old_ver + 1;
        let now = Utc::now();

        let secret_rid = RecordId::new("neutrino_secret", sid);
        let rows = NeutrinoSecretVersion::query(self.valence.as_ref())
            .where_secret_id(RecordPredicate::Equals(secret_rid.clone()))
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?;
        let old_row = rows
            .into_iter()
            .find(|r| *r.version_num() == old_ver)
            .ok_or_else(|| {
                NeutrinoError::service("rotate", anyhow::anyhow!("current version row missing"))
            })?;

        let salt = salt_for(sid, new_ver);
        let (nonce, ct) = crypto::seal(master.as_slice(), &salt, &new_plaintext)?;

        let secret_rid = RecordId::new("neutrino_secret", sid);
        let new_ver_row = NeutrinoSecretVersion::new(
            secret_rid,
            new_ver,
            B64.encode(&ct),
            B64.encode(&nonce),
            KEY_ID.to_string(),
            NeutrinoSecretVersionStatus::Active,
            now,
            actor.to_string(),
        )
        .map_err(|e| NeutrinoError::service("valence", e))?;
        NeutrinoSecretVersion::create(new_ver_row, self.valence.as_ref())
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?;

        old_row
            .get_mutable(self.valence.as_ref())
            .set_status(NeutrinoSecretVersionStatus::Archived)
            .map_err(|e| NeutrinoError::service("rotate", e))?
            .commit()
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?;

        NeutrinoSecret::get(sid, self.valence.as_ref())
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?
            .ok_or_else(|| NeutrinoError::service("rotate", anyhow::anyhow!("secret vanished")))?
            .get_mutable(self.valence.as_ref())
            .set_current_version(new_ver)
            .map_err(|e| NeutrinoError::service("rotate", e))?
            .set_updated_at(now)
            .map_err(|e| NeutrinoError::service("rotate", e))?
            // Re-assert owner as a JSON object so SQLite update paths that
            // string-wrap Json scalars cannot break the authz compat bridge.
            .set_owner_subject_json(normalize_owner_subject_value(
                secret.owner_subject_json().clone(),
            ))
            .map_err(|e| NeutrinoError::service("rotate", e))?
            .commit()
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?;

        emit_access(
            self,
            "rotate",
            actor,
            sid,
            new_ver,
            scope_path.as_str(),
            secret_name.as_str(),
            "ok",
            "",
        )
        .await?;

        Ok(SecretRef {
            id: id.clone(),
            version: new_ver,
        })
    }
}

impl ValenceSealedStore {
    /// Decrypt a specific `NeutrinoSecretVersion` row (Pion may pin an older `version` than
    /// [`NeutrinoSecret::current_version`] in queued action payloads).
    pub async fn reveal_at_version(
        &self,
        id: &SecretId,
        version: i64,
    ) -> NeutrinoResult<RevealedSecret> {
        self.reveal_at_version_with_action(id, version, "reveal")
            .await
    }

    async fn reveal_at_version_with_action(
        &self,
        id: &SecretId,
        version: i64,
        action: &'static str,
    ) -> NeutrinoResult<RevealedSecret> {
        let master = master_key_from_env()?;
        let id_key = extract_id_from_record_display(id.0.as_str()).unwrap_or_else(|_| id.0.clone());
        let actor = audit_actor_for_store(self);

        let secret = match NeutrinoSecret::get(&id_key, self.valence.as_ref()).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                emit_access(
                    self,
                    action,
                    actor.as_str(),
                    id.0.as_str(),
                    version,
                    "",
                    "",
                    "not_found",
                    "secret not found",
                )
                .await?;
                return Err(NeutrinoError::not_found(&id.0));
            }
            Err(e) => {
                let msg = e.to_string();
                emit_access(
                    self,
                    action,
                    actor.as_str(),
                    id.0.as_str(),
                    version,
                    "",
                    "",
                    "error",
                    msg.as_str(),
                )
                .await?;
                return Err(NeutrinoError::service("valence", anyhow::anyhow!(msg)));
            }
        };

        let scope_path = secret.scope_path().clone();
        let secret_name = secret.name().clone();
        let secret_rid = RecordId::new("neutrino_secret", id_key.as_str());
        let rows = NeutrinoSecretVersion::query(self.valence.as_ref())
            .where_secret_id(RecordPredicate::Equals(secret_rid.clone()))
            .await
            .map_err(|e| NeutrinoError::service("valence", e))?;
        let row = match rows.into_iter().find(|r| *r.version_num() == version) {
            Some(row) => row,
            None => {
                let msg = format!("secret version {version} not found for id {}", id.0);
                emit_access(
                    self,
                    action,
                    actor.as_str(),
                    id.0.as_str(),
                    version,
                    scope_path.as_str(),
                    secret_name.as_str(),
                    "not_found",
                    msg.as_str(),
                )
                .await?;
                return Err(NeutrinoError::not_found(&id.0));
            }
        };

        if *row.status() == NeutrinoSecretVersionStatus::Archived {
            let msg = format!("secret version {version} is archived");
            emit_access(
                self,
                action,
                actor.as_str(),
                id.0.as_str(),
                version,
                scope_path.as_str(),
                secret_name.as_str(),
                "denied",
                msg.as_str(),
            )
            .await?;
            return Err(NeutrinoError::validation("version", msg));
        }

        let vnum = version;
        let salt = salt_for(id_key.as_str(), vnum);
        let nonce = match B64.decode(row.nonce_b64().as_bytes()) {
            Ok(n) => n,
            Err(e) => {
                let msg = format!("nonce b64: {e}");
                emit_access(
                    self,
                    action,
                    actor.as_str(),
                    id.0.as_str(),
                    version,
                    scope_path.as_str(),
                    secret_name.as_str(),
                    "error",
                    msg.as_str(),
                )
                .await?;
                return Err(NeutrinoError::service("valence", anyhow::anyhow!(msg)));
            }
        };
        let ct = match B64.decode(row.sealed_payload_b64().as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("payload b64: {e}");
                emit_access(
                    self,
                    action,
                    actor.as_str(),
                    id.0.as_str(),
                    version,
                    scope_path.as_str(),
                    secret_name.as_str(),
                    "error",
                    msg.as_str(),
                )
                .await?;
                return Err(NeutrinoError::service("valence", anyhow::anyhow!(msg)));
            }
        };
        let pt = match crypto::unseal(master.as_slice(), &salt, &nonce, &ct) {
            Ok(p) => p,
            Err(e) => {
                let msg = e.to_string();
                emit_access(
                    self,
                    action,
                    actor.as_str(),
                    id.0.as_str(),
                    version,
                    scope_path.as_str(),
                    secret_name.as_str(),
                    "error",
                    msg.as_str(),
                )
                .await?;
                return Err(e);
            }
        };

        emit_access(
            self,
            action,
            actor.as_str(),
            id.0.as_str(),
            version,
            scope_path.as_str(),
            secret_name.as_str(),
            "ok",
            "",
        )
        .await?;

        Ok(RevealedSecret {
            id: id.clone(),
            version: vnum,
            kind: secret.kind().clone(),
            plaintext: pt,
            created_at: *row.created_at(),
        })
    }
}
