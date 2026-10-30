//! Gauge per-secret authz for Neutrino put + vault reveal.
//!
//! Run: `cargo test -p neutrino --features rbac-tests --test vault_gauge_authz`

#![cfg(feature = "rbac-tests")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod gauge_test_wiring;
mod tolerant_mem;

use std::sync::Arc;

use gauge::resource_permissions::{
    permission_name, permission_record_id, ResourceAction, ResourceKind,
};
use gauge::service;
use neutrino::secret_store::{PutSecretRequest, SecretStore};
use neutrino::vault::{
    create_vault_secret, delete_vault_secret, list_vault_secrets, reveal_vault_secret,
    rotate_vault_secret, store_from_valence_for_request,
};
use neutrino::{NeutrinoError, ValenceSealedStore};
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter, Model,
    RegisterBackendLogicalNamesOptions, Valence, MEM_ENGINE_ID, SQLITE_ENGINE_ID,
};

use gauge_test_wiring::{seed_user, wire_neutrino_gauge_groups};

fn prepare_test_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    unsafe {
        std::env::set_var("NEUTRINO_MASTER_KEY", "0".repeat(64));
        std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
}

struct SplitValence {
    system: Valence,
    gauge: Arc<dyn DatabaseBackend>,
    neutrino: Arc<dyn DatabaseBackend>,
}

/// One backend per logical: `default` (lepton), `gauge`, and `neutrino`.
async fn split_system_valence() -> SplitValence {
    prepare_test_env();
    let default: Arc<dyn DatabaseBackend> = Arc::new(tolerant_mem::TolerantMemBackend::new());
    let gauge: Arc<dyn DatabaseBackend> = Arc::new(valence::InMemoryBackend::new());
    let neutrino: Arc<dyn DatabaseBackend> = Arc::new(valence::InMemoryBackend::new());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        Arc::clone(&default),
        &["default"],
        RegisterBackendLogicalNamesOptions {
            register_alias_engine_id: Some(SQLITE_ENGINE_ID),
        },
    );
    gauge::embedded_surreal::register_storage(&mut router, Arc::clone(&gauge));
    neutrino::embedded_surreal::register_storage(&mut router, Arc::clone(&neutrino));
    let system = Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(router_key("default", MEM_ENGINE_ID))
        .with_actor(Actor::System {
            operation: "vault_gauge_authz".to_string(),
        })
        .build()
        .expect("valence");
    wire_neutrino_gauge_groups(&system).await;
    SplitValence {
        system,
        gauge,
        neutrino,
    }
}

async fn system_valence() -> Valence {
    split_system_valence().await.system
}

async fn add_user_to_creators_group(user_id: &str, system: &Valence) {
    let group = gauge::generated::PermissionGroup::get("neutrino.secret.creators", system, valence::use_!(r"**Test:** Fixture **Permission Group** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get creators group")
        .expect("neutrino.secret.creators must exist");
    let user = lepton::generated::User::get(user_id, system, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get user")
        .expect("user row");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{user_id}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("user id").clone(),
            user_id.to_string(),
        )
        .expect("principal"),
        system,
        valence::use_!(r"**Test:** Fixture **Permission User Principal** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert principal");
    group
        .relate_to_member_record(principal.id().expect("principal id"), system, valence::use_!(r"**Test:** When an operator **adds a group member** in **Gauge**, we **write the member edge** so that principal inherits the group's grants. Operators see the updated members on the group detail."))
        .await
        .expect("relate member");
}

/// Grant a per-secret Gauge action to `user_id` (direct allowed-principal; no legacy owner).
async fn grant_secret_action(
    system: &Valence,
    secret_id: &str,
    action: ResourceAction,
    user_id: &str,
) {
    let perm_id = permission_record_id(ResourceKind::NeutrinoSecret, secret_id, action);
    let permission = gauge::generated::Permission::get(&perm_id, system, valence::use_!(r"**Test:** Fixture **Permission** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get permission")
        .unwrap_or_else(|| panic!("permission {perm_id} must exist after bundle ensure"));
    let user = lepton::generated::User::get(user_id, system, valence::use_!(r"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get user")
        .expect("user row");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{user_id}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("user id").clone(),
            user_id.to_string(),
        )
        .expect("principal"),
        system,
        valence::use_!(r"**Test:** Fixture **Permission User Principal** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert principal");
    permission
        .relate_to_allowed_principal_record(principal.id().expect("principal id"), system, valence::use_!(r"**Test:** When Gauge **grants a permission to a principal**, we **write the allowed-principal edge** so later checks know who may act. Operators and tests see that membership on the permission."))
        .await
        .expect("grant action");
}

async fn create_as_creator(system: &Valence, creator: &str, name: &str) -> String {
    seed_user(creator, &format!("{creator}@example.test"), system).await;
    add_user_to_creators_group(creator, system).await;
    let store = store_from_valence_for_request(system.clone(), format!("user:{creator}"));
    let row = create_vault_secret(
        &store,
        name.into(),
        format!("/scope/{name}"),
        "password".into(),
        "pt".into(),
        format!("user:{creator}"),
    )
    .await
    .expect("create with CreateNeutrinoSecrets");
    row.id
}

#[tokio::test]
async fn create_initial_neutrino_groups_idempotent_happy_path() {
    let system = system_valence().await;
    wire_neutrino_gauge_groups(&system).await;
}

#[tokio::test]
async fn put_ensure_creates_gauge_bundle_happy_path() {
    let system = system_valence().await;
    seed_user("creator", "creator@example.test", &system).await;
    add_user_to_creators_group("creator", &system).await;

    let store = ValenceSealedStore {
        valence: Arc::new(system.clone()),
        request_actor: Some("user:creator".into()),
    };
    let row = create_vault_secret(
        &store,
        "bundle_target".into(),
        "/scope/bundle".into(),
        "password".into(),
        "pt".into(),
        "user:creator".into(),
    )
    .await
    .expect("create with CreateNeutrinoSecrets");

    let maintain_name = permission_name(
        ResourceKind::NeutrinoSecret,
        &row.id,
        ResourceAction::Maintain,
    );
    let creator_v = system.with_actor(Actor::User {
        user_id: "creator".to_string(),
    });
    assert!(
        service::actor_can(&creator_v, &maintain_name)
            .await
            .expect("actor_can"),
        "maintainer must hold Maintain after auto-ensure"
    );

    let reveal_name = permission_name(
        ResourceKind::NeutrinoSecret,
        &row.id,
        ResourceAction::Reveal,
    );
    assert!(
        gauge::generated::Permission::query(&system, valence::use_!(r"**Test:** Fixture **Permission** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
            .where_name(valence::StringPredicate::Equals(reveal_name.clone()))
            .limit(1)
            .first()
            .await
            .expect("query reveal permission")
            .is_some(),
        "Reveal permission row must exist for secret bundle"
    );
}

fn bare_id(id: &str) -> &str {
    id.split_once(':').map_or(id, |(_, rest)| rest)
}

#[tokio::test]
async fn secret_and_permission_rows_on_separate_backends_happy_path() {
    let split = split_system_valence().await;
    let row_id = create_as_creator(&split.system, "split_creator", "split_target").await;

    let reveal_name = permission_name(
        ResourceKind::NeutrinoSecret,
        &row_id,
        ResourceAction::Reveal,
    );
    let permission = gauge::generated::Permission::query(&split.system, valence::use_!(r"**Test:** Fixture **Permission** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .where_name(valence::StringPredicate::Equals(reveal_name))
        .limit(1)
        .first()
        .await
        .expect("query reveal permission")
        .expect("reveal permission row");
    let permission_id = permission.id().expect("permission id").to_string();

    let secret_on = |backend: &Arc<dyn DatabaseBackend>| {
        let backend = Arc::clone(backend);
        let id = bare_id(&row_id).to_string();
        async move {
            backend
                .get_record("neutrino_secret", &id)
                .await
                .ok()
                .flatten()
        }
    };
    let permission_on = |backend: &Arc<dyn DatabaseBackend>| {
        let backend = Arc::clone(backend);
        let id = bare_id(&permission_id).to_string();
        async move { backend.get_record("permission", &id).await.ok().flatten() }
    };

    assert!(
        secret_on(&split.neutrino).await.is_some(),
        "secret row on neutrino backend"
    );
    assert!(
        secret_on(&split.gauge).await.is_none(),
        "secret row must not reach gauge backend"
    );
    assert!(
        permission_on(&split.gauge).await.is_some(),
        "permission row on gauge backend"
    );
    assert!(
        permission_on(&split.neutrino).await.is_none(),
        "permission row must not reach neutrino backend"
    );
}

#[tokio::test]
async fn put_denied_without_create_neutrino_secrets_sad() {
    let system = system_valence().await;
    seed_user("no_create", "no_create@example.test", &system).await;

    let user_v = system.with_actor(Actor::User {
        user_id: "no_create".to_string(),
    });
    let store = ValenceSealedStore {
        valence: Arc::new(system.clone()),
        request_actor: Some("user:no_create".into()),
    };
    let _ = user_v;
    let err = create_vault_secret(
        &store,
        "denied".into(),
        "/scope/d".into(),
        "password".into(),
        "pt".into(),
        "user:no_create".into(),
    )
    .await
    .expect_err("must deny without CreateNeutrinoSecrets");
    assert!(
        matches!(
            err,
            NeutrinoError::AccessDenied {
                operation: "create secrets"
            }
        ),
        "got: {err}"
    );
}

#[tokio::test]
async fn put_or_reuse_denied_without_create_neutrino_secrets_sad() {
    let system = system_valence().await;
    seed_user("no_reuse", "no_reuse@example.test", &system).await;

    let store = ValenceSealedStore {
        valence: Arc::new(system.clone()),
        request_actor: Some("user:no_reuse".into()),
    };
    let err = store
        .put_or_reuse(PutSecretRequest {
            name: "reuse_denied".into(),
            scope_path: "/scope/reuse_denied".into(),
            kind: "password".into(),
            plaintext: b"pt".to_vec(),
            owner_actor: "user:no_reuse".into(),
        })
        .await
        .expect_err("put_or_reuse create path must deny without CreateNeutrinoSecrets");
    assert!(
        matches!(
            err,
            NeutrinoError::AccessDenied {
                operation: "create secrets"
            }
        ),
        "got: {err}"
    );
}

#[tokio::test]
async fn system_owner_put_skips_bundle_happy() {
    let system = system_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(system.clone()),
        request_actor: None,
    };
    let pref = store
        .put(PutSecretRequest {
            name: "sys_seal".into(),
            scope_path: "/gluon/provider/sys".into(),
            kind: "password".into(),
            plaintext: b"control-plane".to_vec(),
            owner_actor: "system".into(),
        })
        .await
        .expect("System seal with owner_actor=system must succeed");

    let maintain_name = permission_name(
        ResourceKind::NeutrinoSecret,
        &pref.id.0,
        ResourceAction::Maintain,
    );
    assert!(
        gauge::generated::Permission::query(&system, valence::use_!(r"**Test:** Fixture **Permission** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
            .where_name(valence::StringPredicate::Equals(maintain_name))
            .limit(1)
            .first()
            .await
            .expect("query")
            .is_none(),
        "control-plane seal must skip Gauge per-secret bundle"
    );
}

#[tokio::test]
async fn reveal_denied_without_reveal_grant_sad() {
    let system = system_valence().await;
    seed_user("owner_u", "owner_u@example.test", &system).await;
    seed_user("stranger_u", "stranger_u@example.test", &system).await;
    add_user_to_creators_group("owner_u", &system).await;

    let owner_v = system.with_actor(Actor::User {
        user_id: "owner_u".to_string(),
    });
    let store = store_from_valence_for_request(system.clone(), "user:owner_u");
    let _ = owner_v;
    let created = create_vault_secret(
        &store,
        "locked".into(),
        "/scope/locked".into(),
        "password".into(),
        "secret-pt".into(),
        "user:owner_u".into(),
    )
    .await
    .expect("owner create");

    let stranger_v = system.with_actor(Actor::User {
        user_id: "stranger_u".to_string(),
    });
    let stranger_store = store_from_valence_for_request(system.clone(), "user:stranger_u");
    let _ = stranger_v;
    let err = reveal_vault_secret(&stranger_store, created.id)
        .await
        .expect_err("stranger must not reveal");
    assert!(
        matches!(
            err,
            NeutrinoError::AccessDenied {
                operation: "access this secret"
            }
        ),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn reveal_allowed_via_gauge_grant_without_legacy_owner_happy() {
    let system = system_valence().await;
    let secret_id = create_as_creator(&system, "owner_reveal", "gauge_reveal").await;
    seed_user("grantee_reveal", "grantee_reveal@example.test", &system).await;
    grant_secret_action(
        &system,
        &secret_id,
        ResourceAction::Reveal,
        "grantee_reveal",
    )
    .await;

    let store = store_from_valence_for_request(system.clone(), "user:grantee_reveal");
    let revealed = reveal_vault_secret(&store, secret_id)
        .await
        .expect("Gauge Reveal grant must allow");
    // "pt" → standard base64 (never log other plaintext in assertions).
    assert_eq!(revealed.plaintext_b64, "cHQ=");
}

#[tokio::test]
async fn list_browsable_all_secrets_reveal_still_gated_happy() {
    let system = system_valence().await;
    let secret_id = create_as_creator(&system, "owner_list", "gauge_list").await;
    seed_user("viewer_list", "viewer_list@example.test", &system).await;
    seed_user("stranger_list", "stranger_list@example.test", &system).await;
    grant_secret_action(&system, &secret_id, ResourceAction::View, "viewer_list").await;

    let rows = list_vault_secrets(&system, None).await.expect("list");
    assert!(
        rows.iter().any(|r| r.id == secret_id),
        "list includes secret for viewer"
    );

    let stranger_rows = list_vault_secrets(&system, None).await.expect("list");
    assert!(
        stranger_rows.iter().any(|r| r.id == secret_id),
        "browsable list includes foreign secrets"
    );

    let store = store_from_valence_for_request(system.clone(), "user:stranger_list");
    let err = reveal_vault_secret(&store, secret_id.clone())
        .await
        .expect_err("stranger reveal must deny");
    assert!(
        matches!(err, NeutrinoError::AccessDenied { .. }),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn rotate_denied_without_edit_grant_sad() {
    let system = system_valence().await;
    let secret_id = create_as_creator(&system, "owner_rot", "gauge_rot").await;
    seed_user("viewer_rot", "viewer_rot@example.test", &system).await;
    grant_secret_action(&system, &secret_id, ResourceAction::View, "viewer_rot").await;

    let store = store_from_valence_for_request(system.clone(), "user:viewer_rot");
    let err = rotate_vault_secret(&store, secret_id, "new-pt".into(), "user:viewer_rot")
        .await
        .expect_err("View without Edit must deny rotate");
    assert!(
        matches!(
            err,
            NeutrinoError::AccessDenied {
                operation: "access this secret"
            }
        ),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn delete_denied_without_delete_grant_sad() {
    let system = system_valence().await;
    let secret_id = create_as_creator(&system, "owner_del", "gauge_del").await;
    seed_user("viewer_del", "viewer_del@example.test", &system).await;
    grant_secret_action(&system, &secret_id, ResourceAction::View, "viewer_del").await;

    let store = store_from_valence_for_request(system.clone(), "user:viewer_del");
    let err = delete_vault_secret(&store, secret_id.clone())
        .await
        .expect_err("View without Delete must deny delete");
    assert!(
        matches!(
            err,
            NeutrinoError::AccessDenied {
                operation: "access this secret"
            }
        ),
        "got: {err:?}"
    );

    // Side effect: secret still listed for owner (secret still listed).
    let rows = list_vault_secrets(&system, None).await.expect("owner list");
    assert!(
        rows.iter().any(|r| r.id == secret_id),
        "denied delete must leave secret intact"
    );
}

#[tokio::test]
async fn put_or_reuse_denied_for_non_owner_creator_sad() {
    let system = system_valence().await;
    seed_user("owner_reuse", "owner_reuse@example.test", &system).await;
    seed_user("other_creator", "other_creator@example.test", &system).await;
    add_user_to_creators_group("owner_reuse", &system).await;
    add_user_to_creators_group("other_creator", &system).await;

    let owner_store = store_from_valence_for_request(system.clone(), "user:owner_reuse");
    let created = create_vault_secret(
        &owner_store,
        "shared_name".into(),
        "/scope/reuse_cross".into(),
        "password".into(),
        "owner-pt".into(),
        "user:owner_reuse".into(),
    )
    .await
    .expect("owner create");

    let stranger_store = store_from_valence_for_request(system.clone(), "user:other_creator");
    let err = stranger_store
        .put_or_reuse(PutSecretRequest {
            name: "shared_name".into(),
            scope_path: "/scope/reuse_cross".into(),
            kind: "password".into(),
            plaintext: b"hijack-pt".to_vec(),
            owner_actor: "user:other_creator".into(),
        })
        .await
        .expect_err("CreateNeutrinoSecrets must not rotate foreign name+scope");
    assert!(
        matches!(
            err,
            NeutrinoError::AccessDenied {
                operation: "access this secret"
            }
        ),
        "got: {err:?}"
    );

    let still = reveal_vault_secret(&owner_store, created.id)
        .await
        .expect("owner reveal after denied reuse");
    assert_eq!(still.plaintext_b64, "b3duZXItcHQ="); // "owner-pt"
}

#[tokio::test]
async fn put_or_reuse_allowed_for_owner_happy_path() {
    let system = system_valence().await;
    seed_user("reuse_owner", "reuse_owner@example.test", &system).await;
    add_user_to_creators_group("reuse_owner", &system).await;

    let store = store_from_valence_for_request(system.clone(), "user:reuse_owner");
    let first = store
        .put_or_reuse(PutSecretRequest {
            name: "owned_reuse".into(),
            scope_path: "/scope/owned_reuse".into(),
            kind: "password".into(),
            plaintext: b"v1".to_vec(),
            owner_actor: "user:reuse_owner".into(),
        })
        .await
        .expect("owner put");
    let second = store
        .put_or_reuse(PutSecretRequest {
            name: "owned_reuse".into(),
            scope_path: "/scope/owned_reuse".into(),
            kind: "password".into(),
            plaintext: b"v2".to_vec(),
            owner_actor: "user:reuse_owner".into(),
        })
        .await
        .expect("owner rotate via put_or_reuse");
    assert_eq!(first.id.0, second.id.0);
    assert!(second.version > first.version);
}

/// A registered service user: a `service_user_account` row owned by `owner`.
async fn register_service_user(
    system: &Valence,
    owner: &str,
) -> lepton_identity::service_users::ServiceUserId {
    use lepton::generated::{
        ServiceUserAccount, ServiceUserAccountOwnerKind, ServiceUserAccountStatus,
    };
    use lepton_identity::service_users::ServiceUserId;
    use valence::RecordId;

    static GATE: std::sync::Once = std::sync::Once::new();
    GATE.call_once(|| {
        gauge::service_users::install_gauge_service_user_gate().expect("service user gate");
    });
    let _stats = gauge::service_users::seed_service_user_permissions(system)
        .await
        .expect("seed service user permissions");
    seed_user(owner, &format!("{owner}@example.test"), system).await;
    gauge_test_wiring::add_user_to_group(
        owner,
        gauge::service_users::SERVICE_USER_CREATORS_GROUP_ID,
        system,
    )
    .await;
    let owner_v = system.with_actor(Actor::User {
        user_id: owner.to_string(),
    });
    let id = ServiceUserId::new_v4();
    let owner_ref = RecordId::new("user", owner);
    let now = chrono::Utc::now();
    let row = ServiceUserAccount::new(
        Some(owner_ref.clone()),
        ServiceUserAccountOwnerKind::User,
        Some(owner_ref),
        "vault-bot".to_string(),
        "vaultbot".to_string(),
        "Fixture service user".to_string(),
        None,
        ServiceUserAccountStatus::Active,
        None,
        now,
        now,
    )
    .expect("service user row");
    ServiceUserAccount::upsert(id.as_str(), row, &owner_v, valence::use_!(r"**Test:** Fixture **service user** save for `tests` so the suite can arrange and assert vault access. CI and developers running the suite only."))
        .await
        .expect("create service user");
    id
}

/// A secret created by a human owner, with the Reveal action granted to the service user.
async fn secret_revealable_by_service_user(
    system: &Valence,
    id: &lepton_identity::service_users::ServiceUserId,
) -> String {
    let secret_id = create_as_creator(system, "secret_owner", "svc_target").await;
    let perm_id = permission_record_id(
        ResourceKind::NeutrinoSecret,
        &secret_id,
        ResourceAction::Reveal,
    );
    let permission = gauge::generated::Permission::get(&perm_id, system, valence::use_!(r"**Test:** Fixture **Permission** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."))
        .await
        .expect("get permission")
        .expect("permission exists after bundle ensure");
    let principal = gauge::generated::PermissionServiceUserPrincipal::upsert(
        &format!("svc:{}", id.as_str()),
        gauge::generated::PermissionServiceUserPrincipal::new(
            valence::RecordId::new("service_user_account", id.as_str()),
            id.as_str().to_string(),
        )
        .expect("principal row"),
        system,
        valence::use_!(r"**Test:** Fixture **Permission Service User Principal** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("service user principal");
    permission
        .relate_to_allowed_principal_record(principal.id().expect("principal id"), system, valence::use_!(r"**Test:** When Gauge **grants a permission to a principal**, we **write the allowed-principal edge** so later checks know who may act. Operators and tests see that membership on the permission."))
        .await
        .expect("grant reveal");
    secret_id
}

#[tokio::test]
async fn forged_service_user_label_denied_sad() {
    let system = system_valence().await;
    let id = register_service_user(&system, "owner_forge").await;
    let secret_id = secret_revealable_by_service_user(&system, &id).await;
    let label = format!("service:svc:{}", id.as_str());
    // A System or User handle carrying the service user's label is a forgery.
    let bases = [
        system.clone(),
        system.with_actor(Actor::User {
            user_id: "owner_forge".into(),
        }),
    ];
    for base in bases {
        let store = store_from_valence_for_request(base, label.clone());
        let err = reveal_vault_secret(&store, secret_id.clone())
            .await
            .expect_err("forged label must not reveal");
        assert!(matches!(err, NeutrinoError::AccessDenied { .. }), "{err:?}");
    }
}

#[tokio::test]
async fn service_user_allowed_through_grant_happy() {
    let system = system_valence().await;
    let id = register_service_user(&system, "owner_ok").await;
    let secret_id = secret_revealable_by_service_user(&system, &id).await;
    let label = format!("service:svc:{}", id.as_str());
    let store = store_from_valence_for_request(system.with_actor(id.actor()), label);
    reveal_vault_secret(&store, secret_id)
        .await
        .expect("the registered service user reveals what it was granted");
}
