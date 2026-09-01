//! Per-secret authz, list filter, and audit attribution contracts.

#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod gauge_test_wiring;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use neutrino::generated::NeutrinoSecretAuditEvent;
use neutrino::vault::{
    create_vault_secret, delete_vault_secret, list_vault_secrets, reveal_vault_secret,
    store_from_valence_for_request, VaultAccessContext,
};
use neutrino::NeutrinoError;
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter,
    RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

fn test_master_key_hex() -> String {
    "0".repeat(64)
}

fn prepare_test_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    unsafe {
        std::env::set_var("NEUTRINO_MASTER_KEY", test_master_key_hex());
        if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
            std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
        }
    }
}

async fn test_valence() -> Valence {
    prepare_test_env();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(
        SqliteBackend::connect_memory()
            .await
            .expect("SqliteBackend::connect_memory"),
    );
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        backend,
        neutrino::embedded_surreal::EMBEDDED_SURREAL_LOGICAL_NAMES,
        RegisterBackendLogicalNamesOptions::default(),
    );

    let v = Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(router_key(
            neutrino::embedded_surreal::LOGICAL_NAME,
            SQLITE_ENGINE_ID,
        ))
        .with_actor(Actor::System {
            operation: "system_vault_orm".to_string(),
        })
        .build()
        .expect("build valence");
    gauge_test_wiring::wire_neutrino_gauge_groups(&v).await;
    gauge_test_wiring::seed_default_vault_users(&v).await;
    v
}

#[tokio::test]
async fn reveal_denied_for_non_owner_without_scope_prefix_sad() {
    let v = test_valence().await;
    let store = store_from_valence_for_request(v, "user:alice");
    let created = create_vault_secret(
        &store,
        "alice_secret".into(),
        "/team-a/db".into(),
        "password".into(),
        "alice-pt".into(),
        "user:alice".into(),
    )
    .await
    .expect("create");

    let bob = VaultAccessContext::owner_only("user:bob");
    let err = reveal_vault_secret(&store, created.id.clone(), &bob)
        .await
        .expect_err("bob must not reveal alice secret");
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
async fn reveal_allowed_with_matching_scope_prefix_happy_path() {
    let v = test_valence().await;
    let store = store_from_valence_for_request(v, "user:alice");
    let created = create_vault_secret(
        &store,
        "scoped".into(),
        "/gluon/provider_account/1".into(),
        "token".into(),
        "scoped-pt".into(),
        "user:alice".into(),
    )
    .await
    .expect("create");

    let ops = VaultAccessContext {
        actor_label: "user:ops".into(),
        allowed_scope_prefixes: vec!["/gluon".into()],
    };
    let revealed = reveal_vault_secret(&store, created.id, &ops)
        .await
        .expect("ops with matching scope prefix");
    let got = B64.decode(revealed.plaintext_b64.as_bytes()).expect("b64");
    assert_eq!(got.as_slice(), b"scoped-pt");
}

#[tokio::test]
async fn list_returns_all_secrets_without_owner_filter_happy_path() {
    let v = test_valence().await;
    let store = store_from_valence_for_request(v.clone(), "user:alice");
    let alice_row = create_vault_secret(
        &store,
        "a".into(),
        "/alice/scope".into(),
        "password".into(),
        "a-pt".into(),
        "user:alice".into(),
    )
    .await
    .expect("create alice");
    let bob_row = create_vault_secret(
        &store,
        "b".into(),
        "/bob/scope".into(),
        "password".into(),
        "b-pt".into(),
        "user:bob".into(),
    )
    .await
    .expect("create bob");

    let alice_list = list_vault_secrets(&v, &VaultAccessContext::owner_only("user:alice"))
        .await
        .expect("list alice");
    assert!(alice_list.iter().any(|r| r.id == alice_row.id));
    assert!(
        alice_list.iter().any(|r| r.id == bob_row.id),
        "browsable list includes foreign secrets"
    );
    assert!(
        !alice_list.iter().any(|r| r.id.contains("owner_subject")),
        "list DTO must not expose owner_subject_json"
    );
}

#[tokio::test]
async fn reveal_audit_attributes_request_actor_not_system_happy_path() {
    let v = test_valence().await;
    let store = store_from_valence_for_request(v.clone(), "user:alice");
    let created = create_vault_secret(
        &store,
        "audit_target".into(),
        "/scope/audit".into(),
        "password".into(),
        "audit-pt".into(),
        "user:alice".into(),
    )
    .await
    .expect("create");

    reveal_vault_secret(
        &store,
        created.id.clone(),
        &VaultAccessContext::owner_only("user:alice"),
    )
    .await
    .expect("reveal");

    let events = NeutrinoSecretAuditEvent::query(&v)
        .await
        .expect("query audit");
    let get_or_reveal = events
        .into_iter()
        .filter(|e| e.secret_id() == &created.id)
        .filter(|e| e.action() == "get" || e.action() == "reveal")
        .collect::<Vec<_>>();
    assert!(
        !get_or_reveal.is_empty(),
        "expected get/reveal audit rows for secret"
    );
    for ev in &get_or_reveal {
        assert_eq!(
            ev.actor(),
            "user:alice",
            "audit must attribute request actor, not system ORM actor"
        );
        assert!(!ev.actor().contains("system_vault_orm"));
    }
}

#[tokio::test]
async fn delete_denied_for_non_owner_sad() {
    let v = test_valence().await;
    let store = store_from_valence_for_request(v, "user:alice");
    let created = create_vault_secret(
        &store,
        "del".into(),
        "/scope/del".into(),
        "password".into(),
        "del-pt".into(),
        "user:alice".into(),
    )
    .await
    .expect("create");

    let err = delete_vault_secret(
        &store,
        created.id,
        &VaultAccessContext::owner_only("user:bob"),
    )
    .await
    .expect_err("bob delete");
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
