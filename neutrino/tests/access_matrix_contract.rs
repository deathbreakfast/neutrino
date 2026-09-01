//! Access matrix contract (T17 subset): published rows match enforced behavior.

#![cfg(feature = "rbac-tests")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod gauge_test_wiring;

use std::sync::Arc;

use neutrino::{
    create_vault_secret, list_vault_secrets, reveal_vault_secret, store_from_valence_for_request,
    NeutrinoError, VaultAccessContext,
};
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

async fn wired_valence() -> Valence {
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
    let system = Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(router_key(
            gauge::embedded_surreal::LOGICAL_NAME,
            MEM_ENGINE_ID,
        ))
        .with_actor(Actor::System {
            operation: "access_matrix".to_string(),
        })
        .build()
        .expect("valence");
    gauge_test_wiring::wire_neutrino_gauge_groups(&system).await;
    gauge_test_wiring::seed_default_vault_users(&system).await;
    system.with_actor(Actor::User {
        user_id: "alice".into(),
    })
}

#[tokio::test]
async fn matrix_authenticated_user_browses_all_secrets_happy() {
    let v = wired_valence().await;
    let alice_store = store_from_valence_for_request(v.clone(), "user:alice");
    let row = create_vault_secret(
        &alice_store,
        "m1".into(),
        "/m1".into(),
        "password".into(),
        "pt".into(),
        "user:alice".into(),
    )
    .await
    .expect("create");
    let bob_list = list_vault_secrets(&v, &VaultAccessContext::owner_only("user:bob"))
        .await
        .expect("list");
    assert!(bob_list.iter().any(|r| r.id == row.id));
}

#[tokio::test]
async fn matrix_stranger_reveal_denied_sad() {
    let v = wired_valence().await;
    let alice_store = store_from_valence_for_request(v.clone(), "user:alice");
    let row = create_vault_secret(
        &alice_store,
        "m2".into(),
        "/m2".into(),
        "password".into(),
        "pt".into(),
        "user:alice".into(),
    )
    .await
    .expect("create");
    let bob_store = store_from_valence_for_request(v.clone(), "user:bob");
    let err = reveal_vault_secret(
        &bob_store,
        row.id,
        &VaultAccessContext::owner_only("user:bob"),
    )
    .await
    .expect_err("stranger reveal");
    assert!(matches!(err, NeutrinoError::AccessDenied { .. }));
}

#[tokio::test]
async fn matrix_creator_reveal_after_put_happy() {
    let v = wired_valence().await;
    let store = store_from_valence_for_request(v, "user:alice");
    let row = create_vault_secret(
        &store,
        "m3".into(),
        "/m3".into(),
        "password".into(),
        "pt".into(),
        "user:alice".into(),
    )
    .await
    .expect("create");
    let revealed = reveal_vault_secret(
        &store,
        row.id,
        &VaultAccessContext::owner_only("user:alice"),
    )
    .await
    .expect("creator reveal via owners group seed");
    assert!(!revealed.plaintext_b64.is_empty());
}
