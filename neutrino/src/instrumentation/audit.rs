//! Append tamper-evident Valence audit events for Neutrino secret operations.

use chrono::{DateTime, Utc};
use valence::{Actor, Model, RecordId, StringPredicate, Valence};

use crate::audit::hash_event;
use crate::error::{NeutrinoError, NeutrinoResult};
use crate::generated::{NeutrinoSecretAuditEvent, NeutrinoSecretAuditEventOutcome};

#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(debug_assertions)]
static AUDIT_APPEND_FAIL_FOR_TESTS: AtomicBool = AtomicBool::new(false);

/// Force [`append_valence_audit_event`] to fail (integration tests only).
#[doc(hidden)]
#[cfg(debug_assertions)]
pub fn set_audit_append_fail_for_tests(fail: bool) {
    AUDIT_APPEND_FAIL_FOR_TESTS.store(fail, Ordering::SeqCst);
}

/// No-op in release builds (test hook is debug-only).
#[doc(hidden)]
#[cfg(not(debug_assertions))]
#[allow(clippy::missing_const_for_fn)]
pub fn set_audit_append_fail_for_tests(_fail: bool) {}

fn audit_outcome(outcome: &str) -> NeutrinoSecretAuditEventOutcome {
    match outcome {
        "ok" => NeutrinoSecretAuditEventOutcome::Ok,
        "denied" => NeutrinoSecretAuditEventOutcome::Denied,
        _ => NeutrinoSecretAuditEventOutcome::Error,
    }
}

async fn last_audit_hash_for_secret(v: &Valence, secret_id: &str) -> NeutrinoResult<String> {
    let rows = NeutrinoSecretAuditEvent::query(v)
        .where_secret_id(StringPredicate::Equals(secret_id.to_string()))
        .await
        .map_err(|e| NeutrinoError::service("audit_query", e))?;
    let mut latest: Option<(DateTime<Utc>, String)> = None;
    for r in rows {
        let ts = *r.ts();
        let id = r.id().map(|rid| rid.to_string()).unwrap_or_default();
        if id.is_empty() {
            continue;
        }
        if latest.as_ref().map(|(t, _)| ts > *t).unwrap_or(true) {
            latest = Some((ts, id));
        }
    }
    Ok(latest
        .map(|(_, id)| id)
        .unwrap_or_else(|| "genesis".to_string()))
}

async fn append_audit_row(
    valence: &Valence,
    actor: &str,
    action: &str,
    secret_id: &str,
    version: i64,
    outcome: &str,
    error_message: &str,
) -> NeutrinoResult<()> {
    #[cfg(debug_assertions)]
    if AUDIT_APPEND_FAIL_FOR_TESTS.load(Ordering::SeqCst) {
        return Err(NeutrinoError::service(
            "audit_append",
            anyhow::anyhow!("audit append disabled for test"),
        ));
    }
    let prev = last_audit_hash_for_secret(valence, secret_id).await?;
    let ts = Utc::now();
    let ev_hash = hash_event(
        prev.as_str(),
        actor,
        action,
        secret_id,
        version,
        outcome,
        ts.to_rfc3339().as_str(),
    );
    let parent_secret_rid = RecordId::new("neutrino_secret", secret_id);
    let ev = NeutrinoSecretAuditEvent::new(
        prev,
        actor.to_string(),
        action.to_string(),
        secret_id.to_string(),
        parent_secret_rid,
        version,
        audit_outcome(outcome),
        error_message.to_string(),
        ts,
    )
    .map_err(|e| NeutrinoError::service("audit_append", e))?;
    NeutrinoSecretAuditEvent::upsert(ev_hash.as_str(), ev, valence)
        .await
        .map_err(|e| NeutrinoError::service("audit_append", e))?;
    Ok(())
}

/// Append one chained audit row (put/get/reveal/rotate/delete) under the caller's Valence.
///
/// Success-path rows require the session actor to pass parent-secret Update via
/// `defer_to_edge` on the audit schema. Denied reads use [`append_denial_audit_event`].
pub async fn append_valence_audit_event(
    valence: &Valence,
    actor: &str,
    action: &str,
    secret_id: &str,
    version: i64,
    outcome: &str,
    error_message: &str,
) -> NeutrinoResult<()> {
    append_audit_row(
        valence,
        actor,
        action,
        secret_id,
        version,
        outcome,
        error_message,
    )
    .await
}

/// Append a denial audit row via System Valence (denied actors cannot Update the parent secret).
pub async fn append_denial_audit_event(
    system_valence: &Valence,
    actor: &str,
    action: &str,
    secret_id: &str,
    version: i64,
    error_message: &str,
) -> NeutrinoResult<()> {
    let system = if system_valence.actor().is_system() {
        system_valence.clone()
    } else {
        system_valence.with_actor(Actor::System {
            operation: "neutrino_audit_denial".into(),
        })
    };
    append_audit_row(
        &system,
        actor,
        action,
        secret_id,
        version,
        "denied",
        error_message,
    )
    .await
}
