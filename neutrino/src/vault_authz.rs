//! Per-secret / per-scope authorization for product vault APIs.
//!
//! **Prefer** Gauge per-secret permissions (see [`crate::create_initial_neutrino_groups`]
//! and vault APIs) via `actor_can` on
//! `neutrino_secret.{id}.{View|Reveal|Edit|Delete}`. This module remains a **compat bridge**
//! for owner JSON grants and scope-prefix break-glass until fine-grained ACL UI lands.

use serde::Deserialize;

use crate::error::{NeutrinoError, NeutrinoResult};

/// Request-side access context for vault list/reveal/delete/rotate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultAccessContext {
    /// Actor label matching create-time `owner_actor` / `owner_subject_json.actor`
    /// (e.g. `user:alice`, `service:setup-wizard`).
    pub actor_label: String,
    /// Scope path prefixes the caller may access in addition to owned/granted
    /// secrets. Empty means no break-glass / prefix access. Use `"/"` for
    /// full-vault break-glass (Super User).
    pub allowed_scope_prefixes: Vec<String>,
}

impl VaultAccessContext {
    /// Context that only matches secrets owned by `actor_label` (no prefix break-glass).
    #[must_use]
    pub fn owner_only(actor_label: impl Into<String>) -> Self {
        Self {
            actor_label: actor_label.into(),
            allowed_scope_prefixes: Vec::new(),
        }
    }

    /// Full-vault break-glass (Super User / trusted system).
    #[must_use]
    pub fn break_glass(actor_label: impl Into<String>) -> Self {
        Self {
            actor_label: actor_label.into(),
            allowed_scope_prefixes: vec!["/".to_string()],
        }
    }
}

#[derive(Debug, Deserialize)]
struct OwnerSubject {
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    grants: Vec<OwnerGrant>,
}

#[derive(Debug, Deserialize)]
struct OwnerGrant {
    principal: String,
    #[serde(default)]
    scope_prefix: String,
}

fn parse_owner_subject(raw: &str) -> OwnerSubject {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return OwnerSubject {
            actor: None,
            grants: Vec::new(),
        };
    }
    serde_json::from_str(trimmed).unwrap_or(OwnerSubject {
        actor: None,
        grants: Vec::new(),
    })
}

/// True when `scope_path` is under `prefix` (path-prefix match).
///
/// `prefix == "/"` matches every non-empty scope. Otherwise the secret path must
/// equal the prefix or start with `prefix` followed by `/`.
#[must_use]
pub fn scope_path_matches_prefix(scope_path: &str, prefix: &str) -> bool {
    let scope = scope_path.trim();
    let prefix = prefix.trim();
    if scope.is_empty() || prefix.is_empty() {
        return false;
    }
    if prefix == "/" {
        return true;
    }
    let prefix = prefix.trim_end_matches('/');
    scope == prefix || scope.starts_with(&format!("{prefix}/"))
}

/// Returns `true` when `access` may see/reveal a secret with the given ownership
/// and scope metadata.
#[must_use]
pub fn can_access_secret(
    access: &VaultAccessContext,
    owner_subject_json: &str,
    scope_path: &str,
) -> bool {
    let owner = parse_owner_subject(owner_subject_json);
    let scope = scope_path.trim();
    let actor = access.actor_label.trim();

    if actor.is_empty() {
        return false;
    }

    // Fail closed when neither owner nor scope is present (legacy / unset).
    let has_owner = owner
        .actor
        .as_ref()
        .map(|a| !a.trim().is_empty())
        .unwrap_or(false);
    let has_scope = !scope.is_empty();
    if !has_owner && !has_scope && owner.grants.is_empty() {
        return false;
    }

    if let Some(ref owner_actor) = owner.actor {
        if owner_actor.trim() == actor {
            return true;
        }
    }

    for grant in &owner.grants {
        if grant.principal.trim() != actor {
            continue;
        }
        if grant.scope_prefix.trim().is_empty() {
            // Principal grant on this secret with no scope constraint.
            return true;
        }
        if scope_path_matches_prefix(scope, &grant.scope_prefix) {
            return true;
        }
    }

    if has_scope {
        for prefix in &access.allowed_scope_prefixes {
            if scope_path_matches_prefix(scope, prefix) {
                return true;
            }
        }
    }

    false
}

/// Deny with a stable error when [`can_access_secret`] is false.
///
/// # Errors
///
/// Returns [`NeutrinoError::AccessDenied`] when the caller may not access the secret.
pub fn ensure_can_access_secret(
    access: &VaultAccessContext,
    owner_subject_json: &str,
    scope_path: &str,
) -> NeutrinoResult<()> {
    if can_access_secret(access, owner_subject_json, scope_path) {
        Ok(())
    } else {
        Err(NeutrinoError::access_denied("access this secret"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::{
        can_access_secret, ensure_can_access_secret, scope_path_matches_prefix, VaultAccessContext,
    };
    use crate::NeutrinoError;

    #[test]
    fn owner_match_allows_happy_path() {
        let access = VaultAccessContext::owner_only("user:alice");
        assert!(can_access_secret(
            &access,
            r#"{"actor":"user:alice"}"#,
            "/gluon/provider_account/1"
        ));
    }

    #[test]
    fn non_owner_denied_without_prefix_sad() {
        let access = VaultAccessContext::owner_only("user:bob");
        assert!(!can_access_secret(
            &access,
            r#"{"actor":"user:alice"}"#,
            "/gluon/provider_account/1"
        ));
        let err = ensure_can_access_secret(
            &access,
            r#"{"actor":"user:alice"}"#,
            "/gluon/provider_account/1",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            NeutrinoError::AccessDenied {
                operation: "access this secret"
            }
        ));
        assert!(err.to_string().contains("not authorized"));
    }

    #[test]
    fn secrets_reveal_scope_prefix_allows_happy_path() {
        let access = VaultAccessContext {
            actor_label: "user:ops".into(),
            allowed_scope_prefixes: vec!["/gluon".into()],
        };
        assert!(can_access_secret(
            &access,
            r#"{"actor":"user:alice"}"#,
            "/gluon/provider_account/1"
        ));
        assert!(!can_access_secret(
            &access,
            r#"{"actor":"user:alice"}"#,
            "/uf-notifications/smtp"
        ));
    }

    #[test]
    fn grant_principal_allows_happy_path() {
        let access = VaultAccessContext::owner_only("user:bob");
        let subject =
            r#"{"actor":"user:alice","grants":[{"principal":"user:bob","scope_prefix":"/gluon"}]}"#;
        assert!(can_access_secret(
            &access,
            subject,
            "/gluon/provider_account/9"
        ));
    }

    #[test]
    fn empty_owner_and_scope_fail_closed_sad() {
        let access = VaultAccessContext::break_glass("user:ops");
        // Break-glass still needs a scope_path to match "/".
        assert!(!can_access_secret(&access, "{}", ""));
        assert!(can_access_secret(
            &access,
            r#"{"actor":"user:alice"}"#,
            "/any/scope"
        ));
    }

    #[test]
    fn scope_prefix_boundary_happy_path() {
        assert!(scope_path_matches_prefix("/gluon/a", "/gluon"));
        assert!(scope_path_matches_prefix("/gluon", "/gluon"));
        assert!(!scope_path_matches_prefix("/gluonx", "/gluon"));
        assert!(scope_path_matches_prefix("/x", "/"));
    }
}
