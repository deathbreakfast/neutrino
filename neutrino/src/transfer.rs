//! Move a vault between hosts: export sealed rows and the audit chain, import them verbatim.
//!
//! A [`TransferBundle`] carries ciphertext and audit events exactly as stored; it never holds
//! key material. Each version's data key derives from the master key plus `"{secret_id}|v{ver}"`,
//! so rows opened with the same master key on the new host decrypt without re-sealing. The cell
//! reads the key through its own [`crate::KeySource`]; the sending host generates a fresh key
//! per install with [`generate_master_key_hex`] and drops its copy with [`purge_exported`].

use std::collections::HashMap;
use std::fmt::Write as _;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use valence::extract_id_from_record;
use valence::Model;
use valence::RecordId;
use valence::Valence;
use zeroize::Zeroizing;

use crate::audit::{prev_ref, verify_audit_chain, AuditChainLink};
use crate::error::{NeutrinoError, NeutrinoResult};
use crate::generated::{
    NeutrinoSecret, NeutrinoSecretAuditEvent, NeutrinoSecretAuditEventOutcome,
    NeutrinoSecretVersion, NeutrinoSecretVersionStatus,
};
use crate::key_source::clear_master_key_cache;
use crate::vault_gauge::{delete_secret_permission_bundle, ensure_secret_permission_bundle};

/// One `neutrino_secret` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSecret {
    /// Secret id (the salt for every version's data key).
    pub id: String,
    /// Secret name.
    pub name: String,
    /// Scope path.
    pub scope_path: String,
    /// Secret kind.
    pub kind: String,
    /// Current version number.
    pub current_version: i64,
    /// Owner subject JSON as stored.
    pub owner_subject_json: serde_json::Value,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// One `neutrino_secret_version` row; the ciphertext is carried as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferVersion {
    /// Row id.
    pub id: String,
    /// Parent secret id.
    pub secret_id: String,
    /// Version number.
    pub version_num: i64,
    /// Sealed payload, base64.
    pub sealed_payload_b64: String,
    /// XChaCha20 nonce, base64.
    pub nonce_b64: String,
    /// Key derivation label.
    pub key_id: String,
    /// `active`, `grace` or `archived`.
    pub status: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Creating actor label.
    pub created_by: String,
}

/// One `neutrino_secret_audit_event` row; `id` is the chain digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferAuditEvent {
    /// Row id (blake3 chain digest).
    pub id: String,
    /// Previous digest or `genesis`.
    pub prev_event_hash: String,
    /// Actor label.
    pub actor: String,
    /// Operation name.
    pub action: String,
    /// Parent secret id.
    pub secret_id: String,
    /// Secret version the event refers to.
    pub version_num: i64,
    /// `ok`, `denied` or `error`.
    pub outcome: String,
    /// Error text, empty on success.
    pub error_message: String,
    /// Event time.
    pub ts: DateTime<Utc>,
}

/// Everything needed to rebuild a vault on another host. Holds no key material.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferBundle {
    /// Secret metadata rows.
    pub secrets: Vec<TransferSecret>,
    /// Sealed version rows.
    pub versions: Vec<TransferVersion>,
    /// Audit events across all secrets.
    pub audit_events: Vec<TransferAuditEvent>,
}

/// Counts from [`import_bundle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportReport {
    /// Secrets written.
    pub secrets: usize,
    /// Versions written.
    pub versions: usize,
    /// Audit events written.
    pub audit_events: usize,
}

fn svc(op: &'static str, e: impl std::fmt::Display) -> NeutrinoError {
    NeutrinoError::service(op, anyhow::anyhow!("{e}"))
}

fn row_id(rec: Option<&RecordId>, op: &'static str) -> NeutrinoResult<String> {
    let rec = rec.ok_or_else(|| svc(op, "row missing id"))?;
    extract_id_from_record(rec).map_err(|e| svc(op, e))
}

const fn status_str(s: &NeutrinoSecretVersionStatus) -> &'static str {
    match s {
        NeutrinoSecretVersionStatus::Active => "active",
        NeutrinoSecretVersionStatus::Grace => "grace",
        NeutrinoSecretVersionStatus::Archived => "archived",
    }
}

fn status_parse(s: &str) -> NeutrinoResult<NeutrinoSecretVersionStatus> {
    match s {
        "active" => Ok(NeutrinoSecretVersionStatus::Active),
        "grace" => Ok(NeutrinoSecretVersionStatus::Grace),
        "archived" => Ok(NeutrinoSecretVersionStatus::Archived),
        other => Err(NeutrinoError::validation(
            "transfer_bundle",
            format!("unknown version status {other:?}"),
        )),
    }
}

const fn outcome_str(o: &NeutrinoSecretAuditEventOutcome) -> &'static str {
    match o {
        NeutrinoSecretAuditEventOutcome::Ok => "ok",
        NeutrinoSecretAuditEventOutcome::Denied => "denied",
        NeutrinoSecretAuditEventOutcome::Error => "error",
    }
}

fn outcome_parse(s: &str) -> NeutrinoResult<NeutrinoSecretAuditEventOutcome> {
    match s {
        "ok" => Ok(NeutrinoSecretAuditEventOutcome::Ok),
        "denied" => Ok(NeutrinoSecretAuditEventOutcome::Denied),
        "error" => Ok(NeutrinoSecretAuditEventOutcome::Error),
        other => Err(NeutrinoError::validation(
            "transfer_bundle",
            format!("unknown audit outcome {other:?}"),
        )),
    }
}

/// Generate a fresh 256-bit master key as 64 hex characters (the form `EnvKeySource` accepts).
///
/// Call once per install so no two installs share a key.
pub fn generate_master_key_hex() -> Zeroizing<String> {
    let mut raw = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(&mut *raw);
    let mut out = Zeroizing::new(String::with_capacity(64));
    for b in raw.iter() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Read every secret, version and audit event as stored. Needs a System (or super-user) handle.
///
/// # Errors
///
/// Returns [`NeutrinoError`] when a query fails or a row has no id.
pub async fn export_bundle(valence: &Valence) -> NeutrinoResult<TransferBundle> {
    let mut bundle = TransferBundle::default();
    let secrets = NeutrinoSecret::query(valence, valence::use_!(r"When an operator **moves the Neutrino vault to a new host**, we copy each secret's **name, scope, kind and current version**—not the secret itself—so the new host can serve the same secrets."))
        .await
        .map_err(|e| svc("export_bundle", e))?;
    for s in secrets {
        let owner = s.owner_subject_json().cloned().ok_or_else(|| {
            svc(
                "export_bundle",
                "owner subject not readable; use a System handle",
            )
        })?;
        bundle.secrets.push(TransferSecret {
            id: row_id(s.id(), "export_bundle")?,
            name: s.name().clone(),
            scope_path: s.scope_path().clone(),
            kind: s.kind().clone(),
            current_version: *s.current_version(),
            owner_subject_json: owner,
            created_at: *s.created_at(),
            updated_at: *s.updated_at(),
        });
    }
    let versions = NeutrinoSecretVersion::query(valence, valence::use_!(r"When an operator **moves the Neutrino vault to a new host**, we copy each **sealed version** as stored (still encrypted) so the new host can unlock it with the same master key."))
        .await
        .map_err(|e| svc("export_bundle", e))?;
    for v in versions {
        bundle.versions.push(TransferVersion {
            id: row_id(v.id(), "export_bundle")?,
            secret_id: extract_id_from_record(v.secret_id())
                .map_err(|e| svc("export_bundle", e))?,
            version_num: *v.version_num(),
            sealed_payload_b64: v.sealed_payload_b64().clone(),
            nonce_b64: v.nonce_b64().clone(),
            key_id: v.key_id().clone(),
            status: status_str(v.status()).to_string(),
            created_at: *v.created_at(),
            created_by: v.created_by().clone(),
        });
    }
    let events = NeutrinoSecretAuditEvent::query(valence, valence::use_!(r"When an operator **moves the Neutrino vault to a new host**, we copy the **audit events** as stored so the tamper-evident chain still verifies there."))
        .await
        .map_err(|e| svc("export_bundle", e))?;
    for e in events {
        bundle.audit_events.push(TransferAuditEvent {
            id: row_id(e.id(), "export_bundle")?,
            prev_event_hash: e.prev_event_hash().clone(),
            actor: e.actor().clone(),
            action: e.action().clone(),
            secret_id: e.secret_id().clone(),
            version_num: *e.version_num(),
            outcome: outcome_str(e.outcome()).to_string(),
            error_message: e.error_message().clone(),
            ts: *e.ts(),
        });
    }
    bundle.secrets.sort_by(|a, b| a.id.cmp(&b.id));
    bundle.versions.sort_by(|a, b| a.id.cmp(&b.id));
    bundle.audit_events.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(bundle)
}

/// Check the bundle without touching a database: sealed payloads decode, versions point at
/// bundled secrets, and every secret's audit chain verifies from `genesis`.
///
/// # Errors
///
/// Returns [`NeutrinoError::Validation`] naming the first break.
pub fn verify_bundle(bundle: &TransferBundle) -> NeutrinoResult<()> {
    let known: std::collections::HashSet<&str> =
        bundle.secrets.iter().map(|s| s.id.as_str()).collect();
    for v in &bundle.versions {
        if !known.contains(v.secret_id.as_str()) {
            return Err(NeutrinoError::validation(
                "transfer_bundle",
                format!("version {} references unknown secret {}", v.id, v.secret_id),
            ));
        }
        status_parse(v.status.as_str())?;
        let nonce = B64.decode(v.nonce_b64.as_bytes());
        let ct = B64.decode(v.sealed_payload_b64.as_bytes());
        if nonce.map(|n| n.len()) != Ok(24) || ct.is_err() {
            return Err(NeutrinoError::validation(
                "transfer_bundle",
                format!("version {} has a malformed sealed payload", v.id),
            ));
        }
    }
    let mut by_secret: HashMap<&str, Vec<&TransferAuditEvent>> = HashMap::new();
    for e in &bundle.audit_events {
        if !known.contains(e.secret_id.as_str()) {
            return Err(NeutrinoError::validation(
                "transfer_bundle",
                format!(
                    "audit event {} references unknown secret {}",
                    e.id, e.secret_id
                ),
            ));
        }
        outcome_parse(e.outcome.as_str())?;
        by_secret.entry(e.secret_id.as_str()).or_default().push(e);
    }
    for (sid, events) in by_secret {
        let mut next: HashMap<&str, &TransferAuditEvent> = HashMap::new();
        for e in &events {
            if next
                .insert(prev_ref(e.prev_event_hash.as_str()), e)
                .is_some()
            {
                return Err(NeutrinoError::validation(
                    "audit_chain",
                    format!(
                        "fork in chain for secret {sid} at prev {}",
                        e.prev_event_hash
                    ),
                ));
            }
        }
        let mut links = Vec::with_capacity(events.len());
        let mut prev = "genesis";
        while let Some(e) = next.get(prev) {
            links.push(AuditChainLink {
                event_id: e.id.clone(),
                prev_event_hash: e.prev_event_hash.clone(),
                actor: e.actor.clone(),
                action: e.action.clone(),
                secret_id: e.secret_id.clone(),
                version: e.version_num,
                outcome: e.outcome.clone(),
                ts_rfc3339: e.ts.to_rfc3339(),
            });
            prev = e.id.as_str();
        }
        if links.len() != events.len() {
            return Err(NeutrinoError::validation(
                "audit_chain",
                format!(
                    "gap in chain for secret {sid}: {} of {} events reachable from genesis",
                    links.len(),
                    events.len()
                ),
            ));
        }
        verify_audit_chain(&links)?;
    }
    Ok(())
}

/// Write a bundle onto this host under a System handle, after [`verify_bundle`] passes.
///
/// Rows keep their ids, so the same master key opens them. Re-importing the same bundle
/// rewrites identical rows. `maintainer_actor` owns each secret's Gauge bundle on this host
/// (skipped for non-user labels, as in `put`).
///
/// # Errors
///
/// Returns [`NeutrinoError`] when the bundle fails verification or a write fails.
pub async fn import_bundle(
    valence: &Valence,
    bundle: &TransferBundle,
    maintainer_actor: &str,
) -> NeutrinoResult<ImportReport> {
    verify_bundle(bundle)?;
    for s in &bundle.secrets {
        let row = NeutrinoSecret::new(
            s.name.clone(),
            s.scope_path.clone(),
            s.kind.clone(),
            s.current_version,
            s.owner_subject_json.clone(),
            serde_json::json!({}),
            s.created_at,
            s.updated_at,
        )
        .map_err(|e| svc("import_bundle", e))?;
        NeutrinoSecret::upsert(s.id.as_str(), row, valence, valence::use_!(r"When an operator **moves the Neutrino vault to a new host**, we save each secret's **name, scope, kind and current version**—not the secret itself—so this host serves the same secrets."))
            .await
            .map_err(|e| svc("import_bundle", e))?;
        ensure_secret_permission_bundle(valence, s.id.as_str(), s.name.as_str(), maintainer_actor)
            .await?;
    }
    for v in &bundle.versions {
        let row = NeutrinoSecretVersion::new(
            RecordId::new("neutrino_secret", v.secret_id.as_str()),
            v.version_num,
            v.sealed_payload_b64.clone(),
            v.nonce_b64.clone(),
            v.key_id.clone(),
            status_parse(v.status.as_str())?,
            v.created_at,
            v.created_by.clone(),
        )
        .map_err(|e| svc("import_bundle", e))?;
        NeutrinoSecretVersion::upsert(v.id.as_str(), row, valence, valence::use_!(r"When an operator **moves the Neutrino vault to a new host**, we save each **sealed version** exactly as received (still encrypted) so it unlocks with the same master key."))
            .await
            .map_err(|e| svc("import_bundle", e))?;
    }
    for e in &bundle.audit_events {
        let row = NeutrinoSecretAuditEvent::new(
            e.prev_event_hash.clone(),
            e.actor.clone(),
            e.action.clone(),
            e.secret_id.clone(),
            Some(RecordId::new("neutrino_secret", e.secret_id.as_str())),
            e.version_num,
            outcome_parse(e.outcome.as_str())?,
            e.error_message.clone(),
            e.ts,
        )
        .map_err(|e| svc("import_bundle", e))?;
        NeutrinoSecretAuditEvent::upsert(e.id.as_str(), row, valence, valence::use_!(r"When an operator **moves the Neutrino vault to a new host**, we save the **audit events** exactly as received so the tamper-evident chain still verifies."))
            .await
            .map_err(|e| svc("import_bundle", e))?;
    }
    Ok(ImportReport {
        secrets: bundle.secrets.len(),
        versions: bundle.versions.len(),
        audit_events: bundle.audit_events.len(),
    })
}

/// Delete the exported secrets, versions, audit events and Gauge bundles from this host and
/// drop the cached master key. The caller removes the key from its own env or file.
///
/// Audit rows are deleted by id because the secret delete only nulls their parent link.
///
/// # Errors
///
/// Returns [`NeutrinoError`] when a delete fails.
pub async fn purge_exported(valence: &Valence, bundle: &TransferBundle) -> NeutrinoResult<()> {
    for e in &bundle.audit_events {
        NeutrinoSecretAuditEvent::delete_now(e.id.as_str(), valence, valence::use_!(r"When an operator **finishes moving the Neutrino vault**, we delete the old host's **audit events** so no copy stays behind."))
            .await
            .map_err(|e| svc("purge_exported", e))?;
    }
    for s in &bundle.secrets {
        // `delete_now` (not queued `delete`): finalize must see the old copy gone before it drops the key.
        NeutrinoSecret::delete_now(s.id.as_str(), valence, valence::use_!(r"When an operator **finishes moving the Neutrino vault**, we delete the old host's secrets and their sealed versions so no copy stays behind."))
            .await
            .map_err(|e| svc("purge_exported", e))?;
        delete_secret_permission_bundle(valence, s.id.as_str()).await?;
    }
    clear_master_key_cache();
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::audit::hash_event;

    fn chain_bundle() -> TransferBundle {
        let ts = "2020-01-01T00:00:00+00:00"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let mk = |prev: &str, action: &str| {
            let id = hash_event(prev, "a", action, "s1", 1, "ok", ts.to_rfc3339().as_str());
            TransferAuditEvent {
                id,
                prev_event_hash: prev.to_string(),
                actor: "a".into(),
                action: action.into(),
                secret_id: "s1".into(),
                version_num: 1,
                outcome: "ok".into(),
                error_message: String::new(),
                ts,
            }
        };
        let e1 = mk("genesis", "put");
        let e2 = mk(e1.id.as_str(), "get");
        TransferBundle {
            secrets: vec![TransferSecret {
                id: "s1".into(),
                name: "n".into(),
                scope_path: "/s".into(),
                kind: "k".into(),
                current_version: 1,
                owner_subject_json: serde_json::json!({"actor": "a"}),
                created_at: ts,
                updated_at: ts,
            }],
            versions: vec![],
            audit_events: vec![e2, e1],
        }
    }

    #[test]
    fn generated_key_is_64_hex_and_unique() {
        let a = generate_master_key_hex();
        let b = generate_master_key_hex();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(*a, *b);
    }

    #[test]
    fn bundle_serde_round_trips_and_verifies() {
        let b = chain_bundle();
        verify_bundle(&b).expect("valid chain, any row order");
        let json = serde_json::to_string(&b).unwrap();
        let back: TransferBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
        verify_bundle(&back).expect("verifies after round trip");
    }

    #[test]
    fn tampered_event_is_rejected() {
        let mut b = chain_bundle();
        b.audit_events[0].actor = "mallory".into();
        assert!(verify_bundle(&b).is_err());
    }

    #[test]
    fn dropped_link_is_rejected() {
        let mut b = chain_bundle();
        let first = b
            .audit_events
            .iter()
            .position(|e| e.prev_event_hash == "genesis")
            .unwrap();
        b.audit_events.remove(first);
        assert!(verify_bundle(&b).is_err());
    }

    #[test]
    fn fork_is_rejected() {
        let mut b = chain_bundle();
        let mut dup = b.audit_events[0].clone();
        dup.id = "other".into();
        b.audit_events.push(dup);
        assert!(verify_bundle(&b).is_err());
    }

    #[test]
    fn audit_event_of_unknown_secret_is_rejected() {
        let mut b = chain_bundle();
        b.secrets.clear();
        assert!(verify_bundle(&b).is_err());
    }

    #[test]
    fn version_of_unknown_secret_is_rejected() {
        let mut b = chain_bundle();
        b.versions.push(TransferVersion {
            id: "v".into(),
            secret_id: "ghost".into(),
            version_num: 1,
            sealed_payload_b64: String::new(),
            nonce_b64: String::new(),
            key_id: "argon2id-v1".into(),
            status: "active".into(),
            created_at: Utc::now(),
            created_by: "a".into(),
        });
        assert!(verify_bundle(&b).is_err());
    }
}
