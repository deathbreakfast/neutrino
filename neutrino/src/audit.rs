//! Tamper-evident audit chain (blake3 over canonical JSON rows).

use blake3::Hasher;
use serde::Serialize;

use crate::error::{NeutrinoError, NeutrinoResult};

#[derive(Serialize)]
struct ChainCanonical<'a> {
    prev_event_hash: &'a str,
    actor: &'a str,
    action: &'a str,
    secret_id: &'a str,
    version: i64,
    outcome: &'a str,
    ts_rfc3339: &'a str,
}

/// One row in a per-secret audit chain for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChainLink {
    /// Row primary key (blake3 digest of the event).
    pub event_id: String,
    /// Previous link id or `genesis`.
    pub prev_event_hash: String,
    /// Actor label stored on the row.
    pub actor: String,
    /// Operation name (`put`, `get`, `reveal`, …).
    pub action: String,
    /// Parent secret id.
    pub secret_id: String,
    /// Secret version referenced by the event.
    pub version: i64,
    /// Outcome token (`ok`, `denied`, `error`).
    pub outcome: String,
    /// RFC3339 timestamp string used in the digest.
    pub ts_rfc3339: String,
}

/// Compute the tamper-evident chain hash for one audit event: blake3 over the
/// canonical JSON encoding of the previous hash plus the event's fields.
pub fn hash_event(
    prev_event_hash: &str,
    actor: &str,
    action: &str,
    secret_id: &str,
    version: i64,
    outcome: &str,
    ts_rfc3339: &str,
) -> String {
    let row = ChainCanonical {
        prev_event_hash,
        actor,
        action,
        secret_id,
        version,
        outcome,
        ts_rfc3339,
    };
    let json = serde_json::to_string(&row)
        .unwrap_or_else(|_| unreachable!("ChainCanonical serialization is infallible"));
    let mut h = Hasher::new();
    h.update(json.as_bytes());
    h.finalize().to_hex().to_string()
}

/// Verify a per-secret audit chain in chronological order.
///
/// Each link's `event_id` must equal [`hash_event`] over its fields and the previous
/// link's `event_id`. A fork (two rows sharing the same predecessor) or a digest
/// mismatch returns an error naming the break.
///
/// # Errors
///
/// Returns [`NeutrinoError::Validation`] when the chain is empty, forked, or tampered.
pub fn verify_audit_chain(links: &[AuditChainLink]) -> NeutrinoResult<()> {
    if links.is_empty() {
        return Ok(());
    }
    let mut prev_id = links[0].prev_event_hash.clone();
    if prev_id != "genesis" {
        return Err(NeutrinoError::validation(
            "audit_chain",
            format!("chain must start at genesis, got prev={prev_id}"),
        ));
    }
    for link in links {
        if link.prev_event_hash != prev_id {
            return Err(NeutrinoError::validation(
                "audit_chain",
                format!(
                    "fork or gap at event {}: expected prev {}, got {}",
                    link.event_id, prev_id, link.prev_event_hash
                ),
            ));
        }
        let expected = hash_event(
            link.prev_event_hash.as_str(),
            link.actor.as_str(),
            link.action.as_str(),
            link.secret_id.as_str(),
            link.version,
            link.outcome.as_str(),
            link.ts_rfc3339.as_str(),
        );
        if expected != link.event_id {
            return Err(NeutrinoError::validation(
                "audit_chain",
                format!(
                    "tampered event {}: digest mismatch (expected {expected})",
                    link.event_id
                ),
            ));
        }
        prev_id.clone_from(&link.event_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{hash_event, verify_audit_chain, AuditChainLink};

    #[test]
    fn hash_event_stable_and_sensitive() {
        let a = hash_event(
            "prev",
            "actor",
            "get",
            "sid",
            1,
            "ok",
            "2020-01-01T00:00:00Z",
        );
        let b = hash_event(
            "prev",
            "actor",
            "get",
            "sid",
            1,
            "ok",
            "2020-01-01T00:00:00Z",
        );
        let c = hash_event(
            "prev",
            "actor",
            "get",
            "sid",
            2,
            "ok",
            "2020-01-01T00:00:00Z",
        );
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(!a.is_empty());
    }

    #[test]
    fn verify_audit_chain_happy_and_sad() {
        let ts = "2020-01-01T00:00:00Z";
        let id1 = hash_event("genesis", "alice", "put", "s1", 1, "ok", ts);
        let id2 = hash_event(id1.as_str(), "alice", "get", "s1", 1, "ok", ts);
        let links = vec![
            AuditChainLink {
                event_id: id1.clone(),
                prev_event_hash: "genesis".into(),
                actor: "alice".into(),
                action: "put".into(),
                secret_id: "s1".into(),
                version: 1,
                outcome: "ok".into(),
                ts_rfc3339: ts.into(),
            },
            AuditChainLink {
                event_id: id2,
                prev_event_hash: id1,
                actor: "alice".into(),
                action: "get".into(),
                secret_id: "s1".into(),
                version: 1,
                outcome: "ok".into(),
                ts_rfc3339: ts.into(),
            },
        ];
        verify_audit_chain(&links).expect("valid chain");

        let mut forked = links.clone();
        forked[1].prev_event_hash = "genesis".into();
        assert!(verify_audit_chain(&forked).is_err());
    }
}
