//! Gauge per-secret authorization for Neutrino vault APIs.
//!
//! Prefer [`actor_can_secret`] / coarse create gates over legacy
//! [`crate::vault_authz::VaultAccessContext`] JSON grants. The access context remains as a
//! **compat bridge** for scope-prefix break-glass until dedicated Gauge grants ship in UI.

use gauge::actor_can_raw::actor_can_raw;
use gauge::generated::PermissionDomain;
use gauge::resource_permissions::{
    ensure_resource_permission_bundle, permission_name, seed_resource_kind_catalog, ResourceAction,
    ResourceKind, ResourcePermissionError, ResourcePermissionSpec, CREATE_NEUTRINO_SECRETS,
};
use valence::{Actor, Model, Valence};

use crate::canonical_secret_id::canonical_secret_id;
use crate::error::{NeutrinoError, NeutrinoResult};
use crate::sealed_store::ValenceSealedStore;

pub use gauge::resource_permissions::NEUTRINO_SECRET_RESOURCE;

const NEUTRINO_CATALOG_DOMAIN_ID: &str = "rp_catalog_neutrino_secret";

/// Ensure Neutrino secret default groups and `CreateNeutrinoSecrets`.
///
/// Call once during **host wiring** before serving Neutrino seal/put APIs. Idempotent.
pub async fn create_initial_neutrino_groups(v: &Valence) -> Result<(), ResourcePermissionError> {
    seed_resource_kind_catalog(
        v,
        ResourceKind::NeutrinoSecret,
        NEUTRINO_CATALOG_DOMAIN_ID,
        "Neutrino secret create",
        "rp_perm_create_neutrino_secrets",
    )
    .await
}

/// Fail fast when the Gauge Neutrino catalog was not seeded at boot.
///
/// Without [`create_initial_neutrino_groups`], non-System actors fail closed on every
/// vault operation with no diagnostic.
///
/// # Errors
///
/// Returns [`NeutrinoError::Config`] when the catalog domain row is missing.
pub async fn assert_neutrino_catalog_seeded(v: &Valence) -> NeutrinoResult<()> {
    let exists = PermissionDomain::get(NEUTRINO_CATALOG_DOMAIN_ID, v)
        .await
        .map_err(|e| NeutrinoError::service("assert_neutrino_catalog_seeded", e))?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(NeutrinoError::service(
            "assert_neutrino_catalog_seeded",
            anyhow::anyhow!(
                "Neutrino Gauge catalog not seeded: call create_initial_neutrino_groups at worker boot"
            ),
        ))
    }
}

/// Bare Valence user id from an audit / owner label (`user:alice` → `alice`).
#[must_use]
pub fn user_id_from_actor_label(label: &str) -> Option<String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("user:") {
        let id = rest.trim();
        if id.is_empty() {
            return None;
        }
        return Some(id.to_string());
    }
    if trimmed.contains(':') {
        return None;
    }
    Some(trimmed.to_string())
}

/// Valence handle whose actor matches the human/service label on the store (for Gauge checks).
#[must_use]
pub fn auth_valence_for_store(store: &ValenceSealedStore) -> Valence {
    auth_valence_for_label(store.valence.as_ref(), store.request_actor.as_deref())
}

/// Build an authorization Valence from a base handle and request actor label.
///
/// When `base` is System and `request_actor` is **present but not** a User/ServiceUser
/// label, returns Anonymous so Gauge checks fail closed. When `request_actor` is
/// absent and `base` is System, preserves System (control-plane from-start lane).
#[must_use]
pub fn auth_valence_for_label(base: &Valence, request_actor: Option<&str>) -> Valence {
    if let Some(label) = request_actor.filter(|s| !s.trim().is_empty()) {
        if let Some(uid) = user_id_from_actor_label(label) {
            let lower = uid.to_ascii_lowercase();
            if lower == "system"
                || lower == "anonymous"
                || lower.starts_with("chronon.")
                || lower == "gluon-lab-ops"
                || lower == "gluon-system"
                || lower == "gluon.system"
            {
                if base.actor().is_system() {
                    return base.with_actor(Actor::Anonymous);
                }
            } else {
                return base.with_actor(Actor::User { user_id: uid });
            }
        }
        if let Some(svc) = label.strip_prefix("service:") {
            let name = svc.trim();
            if !name.is_empty() {
                return base.with_actor(Actor::ServiceUser {
                    service_name: name.to_string(),
                });
            }
        }
        if base.actor().is_system() {
            return base.with_actor(Actor::Anonymous);
        }
    }
    base.clone()
}

/// Authorization Valence derived from [`crate::vault_authz::VaultAccessContext::actor_label`].
#[must_use]
pub fn auth_valence_for_access(base: &Valence, actor_label: &str) -> Valence {
    auth_valence_for_label(base, Some(actor_label))
}

/// System actors and Super User always pass; otherwise checks Gauge permission name.
///
/// # Errors
///
/// Propagates Gauge service failures. When `request_actor` on a System ORM handle cannot be
/// resolved to a User/ServiceUser, authorization denies rather than defaulting to System.
pub async fn actor_can_secret(
    auth_v: &Valence,
    secret_id: &str,
    action: ResourceAction,
) -> NeutrinoResult<bool> {
    if auth_v.actor().is_system() {
        return Ok(true);
    }
    if gauge::super_user::actor_is_super_user(auth_v)
        .await
        .unwrap_or(false)
    {
        return Ok(true);
    }
    let sid = canonical_secret_id(secret_id)?;
    let name = permission_name(ResourceKind::NeutrinoSecret, sid.as_str(), action);
    actor_can_raw(auth_v, &name)
        .await
        .map_err(|e| NeutrinoError::service("actor_can_secret", e))
}

/// Deny when the actor may not perform `action` on `secret_id` (no legacy bridge).
#[allow(dead_code)] // reserved for Gauge-only callers without VaultAccessContext bridge
pub async fn ensure_actor_can_secret(
    auth_v: &Valence,
    secret_id: &str,
    action: ResourceAction,
) -> NeutrinoResult<()> {
    if actor_can_secret(auth_v, secret_id, action).await? {
        Ok(())
    } else {
        Err(NeutrinoError::access_denied("access this secret"))
    }
}

/// Create gate: System **or** `CreateNeutrinoSecrets` (control-plane break-glass uses System).
pub async fn ensure_can_create_secret(auth_v: &Valence) -> NeutrinoResult<()> {
    if auth_v.actor().is_system() {
        return Ok(());
    }
    if actor_can_raw(auth_v, CREATE_NEUTRINO_SECRETS.permission_name)
        .await
        .unwrap_or(false)
    {
        return Ok(());
    }
    Err(NeutrinoError::access_denied("create secrets"))
}

/// Maintainer id for Gauge ensure: request actor label, else Valence user id, else owner on put.
pub fn maintainer_actor_for_put(store: &ValenceSealedStore, owner_actor: &str) -> String {
    if let Some(label) = store
        .request_actor
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        return label.to_string();
    }
    if let Some(uid) = store.valence.actor().user_id() {
        return format!("user:{uid}");
    }
    owner_actor.to_string()
}

/// True when `maintainer_actor` can own a Gauge owners-group membership (Lepton user).
///
/// Control-plane seals use System Valence with `owner_actor` / labels like `system` or
/// `service:…` — those persist ciphertext without a per-secret bundle (same skip pattern as
/// Gluon System app create). Session seals with `user:…` still auto-ensure.
#[must_use]
pub fn maintainer_is_gauge_user(maintainer_actor: &str) -> bool {
    let Some(uid) = user_id_from_actor_label(maintainer_actor) else {
        return false;
    };
    let lower = uid.to_ascii_lowercase();
    // Control-plane / Chronon / lab audit labels — not Lepton users.
    if lower.starts_with("chronon.")
        || lower == "gluon-lab-ops"
        || lower == "gluon-system"
        || lower == "gluon.system"
    {
        return false;
    }
    !(lower.is_empty() || lower == "system" || lower == "anonymous")
}

/// Idempotently materialize the per-secret Gauge bundle after seal (integrators do not call this).
///
/// No-ops (Ok) when the maintainer is not a Gauge user so System/control-plane seals stay
/// compatible with Gluon provider seed / DNS / registry paths.
pub async fn ensure_secret_permission_bundle(
    orm_v: &Valence,
    secret_id: &str,
    display_name: &str,
    maintainer_actor: &str,
) -> NeutrinoResult<()> {
    let sid = canonical_secret_id(secret_id)?;
    if !maintainer_is_gauge_user(maintainer_actor) {
        log::info!(
            "[neutrino] skip Gauge secret bundle (no user maintainer) secret_id={sid} maintainer={maintainer_actor}"
        );
        return Ok(());
    }
    ensure_resource_permission_bundle(
        orm_v,
        ResourcePermissionSpec {
            kind: ResourceKind::NeutrinoSecret,
            resource_id: sid,
            display_name: display_name.to_string(),
            actions: ResourceKind::NeutrinoSecret.default_actions(),
            maintainer_actor: maintainer_actor.to_string(),
        },
    )
    .await
    .map_err(|e| NeutrinoError::service("ensure_secret_permission_bundle", e))?;
    Ok(())
}

/// Tear down the per-secret Gauge bundle (permissions, owners group, domain).
pub async fn delete_secret_permission_bundle(
    orm_v: &Valence,
    secret_id: &str,
) -> NeutrinoResult<()> {
    let sid = canonical_secret_id(secret_id)?;
    gauge::resource_permissions::delete_resource_permission_bundle(
        orm_v,
        ResourceKind::NeutrinoSecret,
        sid.as_str(),
    )
    .await
    .map_err(|e| NeutrinoError::service("delete_secret_permission_bundle", e))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::{auth_valence_for_label, maintainer_is_gauge_user, user_id_from_actor_label};
    use valence::Actor;

    #[test]
    fn user_id_from_actor_label_strips_user_prefix_happy() {
        assert_eq!(
            user_id_from_actor_label("user:alice").as_deref(),
            Some("alice")
        );
        assert_eq!(user_id_from_actor_label("bob").as_deref(), Some("bob"));
    }

    #[test]
    fn user_id_from_actor_label_rejects_empty_and_non_user_prefixes_sad() {
        assert!(user_id_from_actor_label("").is_none());
        assert!(user_id_from_actor_label("   ").is_none());
        assert!(user_id_from_actor_label("user:").is_none());
        assert!(user_id_from_actor_label("user:  ").is_none());
        assert!(user_id_from_actor_label("service:dns").is_none());
        assert!(user_id_from_actor_label("system:ops").is_none());
    }

    #[test]
    fn maintainer_is_gauge_user_accepts_human_labels_happy() {
        assert!(maintainer_is_gauge_user("user:alice"));
        assert!(maintainer_is_gauge_user("alice"));
    }

    #[test]
    fn maintainer_is_gauge_user_skips_system_and_service_sad() {
        assert!(!maintainer_is_gauge_user("system"));
        assert!(!maintainer_is_gauge_user("user:system"));
        assert!(!maintainer_is_gauge_user("user:System"));
        assert!(!maintainer_is_gauge_user("anonymous"));
        assert!(!maintainer_is_gauge_user("user:anonymous"));
        assert!(!maintainer_is_gauge_user("service:gluon"));
        assert!(!maintainer_is_gauge_user(""));
        assert!(!maintainer_is_gauge_user(
            "chronon.ensure_gluon_provider_account"
        ));
        assert!(!maintainer_is_gauge_user("gluon-lab-ops"));
        assert!(!maintainer_is_gauge_user("gluon-system"));
    }

    #[test]
    fn auth_valence_for_label_fail_closed_on_system_without_user_sad() {
        use std::sync::Arc;
        use valence::{DatabaseBackend, Valence, MEM_ENGINE_ID};

        let backend: Arc<dyn DatabaseBackend> = Arc::new(valence::InMemoryBackend::new());
        let system = Valence::builder()
            .add_backend(MEM_ENGINE_ID, backend)
            .with_actor(Actor::System {
                operation: "test".into(),
            })
            .build()
            .expect("valence");
        let auth = auth_valence_for_label(&system, None);
        assert!(auth.actor().is_system());
        let auth2 = auth_valence_for_label(&system, Some("system"));
        assert!(auth2.actor().is_anonymous());
        let auth3 = auth_valence_for_label(&system, Some("user:alice"));
        assert_eq!(auth3.actor().user_id(), Some("alice"));
    }
}
