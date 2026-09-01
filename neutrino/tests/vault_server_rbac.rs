//! Gauge RBAC for vault server-fn permission names.
//!
//! `neutrino-app` gates each vault `#[server]` with these exact permission
//! strings via `gauge::service::actor_can`. Tests assert deny-without-grant and
//! allow-with-grant for every name.
//!
//! Run: `cargo test -p neutrino --features rbac-tests --test vault_server_rbac`

#![cfg(feature = "rbac-tests")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chrono::Utc;
use gauge::service;
use gauge::types::{
    PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
};
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter, Model,
    RegisterBackendLogicalNamesOptions, Valence, MEM_ENGINE_ID, SQLITE_ENGINE_ID,
};

/// Permission names used by `neutrino-app` vault `#[server]` wrappers.
const VAULT_SERVER_PERMISSIONS: &[&str] = &[
    "SecretsRead",
    "SecretsReveal",
    "SecretsWrite",
    "SecretsRotate",
];

fn prepare_test_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    unsafe {
        std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
}

async fn test_valence(actor: Actor) -> Valence {
    prepare_test_env();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(valence::InMemoryBackend::new());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        Arc::clone(&backend),
        gauge::embedded_surreal::EMBEDDED_SURREAL_LOGICAL_NAMES,
        RegisterBackendLogicalNamesOptions {
            register_alias_engine_id: Some(SQLITE_ENGINE_ID),
        },
    );
    router.register(
        router_key(gauge::embedded_surreal::LOGICAL_NAME, SQLITE_ENGINE_ID),
        backend,
    );
    Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(router_key(
            gauge::embedded_surreal::LOGICAL_NAME,
            MEM_ENGINE_ID,
        ))
        .with_actor(actor)
        .build()
        .expect("valence build")
}

async fn seed_user(id: &str, email: &str, valence: &Valence) {
    let _ = email; // email lives on AccountEmail upstream; label kept for call-site readability
    let now = Utc::now();
    let user = lepton::generated::User::new(
        Some(lepton::generated::UserUserType::Person),
        Some("test-password-hash".to_string()),
        Some(lepton::generated::UserStatus::Active),
        None,
        None,
        Some(now),
        None,
        None,
        now,
        now,
    )
    .expect("build user");
    lepton::generated::User::upsert(id, user, valence)
        .await
        .expect("upsert user");
}

fn record_pk_id(rid: Option<&valence::RecordId>) -> String {
    rid.and_then(|r| valence::extract_id_from_record(r).ok())
        .unwrap_or_default()
}

struct VaultPermWorld {
    owner_ctx: Valence,
    member_ctx: Valence,
    permission_id: String,
    permission_name: String,
}

async fn seed_vault_permission(permission_name: &str) -> VaultPermWorld {
    let system = test_valence(Actor::System {
        operation: "vault_server_rbac_setup".to_string(),
    })
    .await;

    seed_user("owner", "owner@example.com", &system).await;
    seed_user("member", "member@example.com", &system).await;

    let owner_ctx = system.with_actor(Actor::User {
        user_id: "owner".to_string(),
    });
    let member_ctx = system.with_actor(Actor::User {
        user_id: "member".to_string(),
    });

    let group = service::create_group(
        PermissionGroupCreateInput {
            name: format!("{permission_name}-owners"),
            description: "vault rbac owners".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create group");
    let group_id = record_pk_id(group.id());

    let domain = service::create_domain(
        PermissionDomainCreateInput {
            name: format!("{permission_name}-domain"),
            description: "vault rbac domain".to_string(),
        },
        &owner_ctx,
    )
    .await
    .expect("create domain");
    let domain_id = record_pk_id(domain.id());

    let permission = service::create_permission(
        PermissionCreateInput {
            name: permission_name.to_string(),
            description: format!("vault server fn gate: {permission_name}"),
            owners_group_id: group_id,
            domain_id,
        },
        &owner_ctx,
    )
    .await
    .expect("create permission");

    VaultPermWorld {
        owner_ctx,
        member_ctx,
        permission_id: record_pk_id(permission.id()),
        permission_name: permission_name.to_string(),
    }
}

#[tokio::test]
async fn vault_server_permissions_deny_without_grant_sad() {
    for &perm in VAULT_SERVER_PERMISSIONS {
        let world = seed_vault_permission(perm).await;
        let allowed = service::actor_can(&world.member_ctx, &world.permission_name)
            .await
            .expect("actor_can");
        assert!(
            !allowed,
            "{perm}: member must be denied without grant (server fn gate)"
        );
    }
}

#[tokio::test]
async fn vault_server_permissions_allow_with_grant_happy_path() {
    for &perm in VAULT_SERVER_PERMISSIONS {
        let world = seed_vault_permission(perm).await;
        service::grant_permission_to_user(&world.permission_id, "member", &world.owner_ctx)
            .await
            .expect("grant");

        let allowed = service::actor_can(&world.member_ctx, &world.permission_name)
            .await
            .expect("actor_can after grant");
        assert!(
            allowed,
            "{perm}: member must be allowed after grant (server fn gate)"
        );
    }
}
