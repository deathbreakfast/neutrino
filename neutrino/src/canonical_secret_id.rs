//! Canonical bare secret ids for Gauge permission names and bundle ensure.
//!
//! Every call site that passes a secret id into `permission_name` or
//! `ensure_resource_permission_bundle` must use [`canonical_secret_id`] so
//! prefixed record ids (`neutrino_secret:{uuid}`) and bare pk strings resolve to
//! the same ACL key.

use valence::extract_id_from_record_display;

use crate::error::{NeutrinoError, NeutrinoResult};

/// Normalize a secret id to the bare Valence primary key used in Gauge ACL keys.
///
/// Strips a `neutrino_secret:` table prefix when present. Empty ids are rejected.
///
/// # Errors
///
/// Returns [`NeutrinoError::Validation`] when `raw` is empty after trimming.
pub fn canonical_secret_id(raw: &str) -> NeutrinoResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(NeutrinoError::validation(
            "secret_id",
            "secret id is required",
        ));
    }
    let bare = extract_id_from_record_display(trimmed).unwrap_or_else(|_| trimmed.to_string());
    if bare.trim().is_empty() {
        return Err(NeutrinoError::validation(
            "secret_id",
            "secret id is required",
        ));
    }
    Ok(bare)
}

#[cfg(test)]
mod tests {
    use super::canonical_secret_id;

    #[test]
    fn canonical_secret_id_strips_table_prefix_happy() {
        assert_eq!(
            canonical_secret_id("neutrino_secret:abc-123").unwrap(),
            "abc-123"
        );
        assert_eq!(canonical_secret_id("abc-123").unwrap(), "abc-123");
    }

    #[test]
    fn canonical_secret_id_rejects_empty_sad() {
        assert!(canonical_secret_id("").is_err());
        assert!(canonical_secret_id("   ").is_err());
    }

    #[test]
    fn colliding_raw_ids_produce_distinct_permission_fragments() {
        use gauge::resource_permissions::{
            normalize_id_fragment, permission_name, ResourceAction, ResourceKind,
        };
        let a = normalize_id_fragment("abc-123");
        let b = normalize_id_fragment("abc_123");
        assert_ne!(a, b, "digest suffix must separate sanitized collisions");
        assert_ne!(
            permission_name(
                ResourceKind::NeutrinoSecret,
                "abc-123",
                ResourceAction::Reveal
            ),
            permission_name(
                ResourceKind::NeutrinoSecret,
                "abc_123",
                ResourceAction::Reveal
            ),
        );
    }
}
