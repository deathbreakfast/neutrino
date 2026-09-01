//! Security remediation contract tests (T12, T14, T15).

#![cfg(feature = "rbac-tests")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod gauge_test_wiring;

use std::sync::Arc;

use gauge::resource_permissions::{
    normalize_id_fragment, permission_name, ResourceAction, ResourceKind,
};
use neutrino::vault::{
    create_vault_secret, reveal_vault_secret, store_from_valence_for_request, VaultAccessContext,
};
use neutrino::{assert_neutrino_catalog_seeded, create_initial_neutrino_groups, NeutrinoError};
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter,
    RegisterBackendLogicalNamesOptions, Valence, MEM_ENGINE_ID, SQLITE_ENGINE_ID,
};

fn prepare_test_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    unsafe {
        std::env::set_var("NEUTRINO_MASTER_KEY", "0".repeat(64));
        std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
    }
}

async fn system_valence() -> Valence {
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
        .with_actor(Actor::System {
            operation: "security_contract".to_string(),
        })
        .build()
        .expect("valence")
}

#[tokio::test]
async fn catalog_missing_fails_at_boot_sad() {
    let v = system_valence().await;
    let err = assert_neutrino_catalog_seeded(&v)
        .await
        .expect_err("unseeded catalog");
    assert!(err.to_string().contains("catalog not seeded"), "got: {err}");
}

#[tokio::test]
async fn catalog_seeded_then_assert_ok_happy() {
    let v = system_valence().await;
    create_initial_neutrino_groups(&v).await.expect("seed");
    assert_neutrino_catalog_seeded(&v).await.expect("seeded");
}

#[test]
fn colliding_ids_distinct_permission_names_t14() {
    let a = normalize_id_fragment("abc-123");
    let b = normalize_id_fragment("abc_123");
    assert_ne!(a, b);
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

#[tokio::test]
async fn operators_group_member_denied_without_per_secret_grant_sad() {
    let v = system_valence().await;
    gauge_test_wiring::wire_neutrino_gauge_groups(&v).await;
    gauge_test_wiring::seed_default_vault_users(&v).await;
    gauge_test_wiring::seed_user("creator", "creator@example.test", &v).await;
    gauge_test_wiring::seed_user("operator", "operator@example.test", &v).await;
    gauge_test_wiring::add_user_to_creators_group("creator", &v).await;
    gauge_test_wiring::add_user_to_group("operator", "neutrino.secret.operators", &v).await;

    let store = store_from_valence_for_request(v.clone(), "user:creator");
    let row = create_vault_secret(
        &store,
        "op_test".into(),
        "/op".into(),
        "password".into(),
        "pt".into(),
        "user:creator".into(),
    )
    .await
    .expect("create");

    let op_store = store_from_valence_for_request(v.clone(), "user:operator");
    let err = reveal_vault_secret(
        &op_store,
        row.id,
        &VaultAccessContext::owner_only("user:operator"),
    )
    .await
    .expect_err("operators umbrella must not reveal without per-secret grant");
    assert!(
        matches!(err, NeutrinoError::AccessDenied { .. }),
        "got: {err:?}"
    );
}
