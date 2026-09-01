//! Named happy/sad contracts for product-local vault CRUD.
//!
//! Covers the same domain surface as `neutrino-app` server fns
//! (`create_vault_secret` / `list_vault_secrets` / `reveal_vault_secret` /
//! `rotate_vault_secret` / `delete_vault_secret` / `neutrino_vault_ping`),
//! which are thin wrappers over [`neutrino::vault`].
//!
//! Tests never log or format plaintext secret values into error strings.

#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod gauge_test_wiring;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use neutrino::vault::{
    create_vault_secret, delete_vault_secret, list_vault_secrets, neutrino_vault_ping,
    reveal_vault_secret, rotate_vault_secret, store_from_valence, VaultAccessContext,
};
use neutrino::ValenceSealedStore;
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
    // SAFETY: test harness only; OnceLock reads this before first ownership get.
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
            operation: "neutrino_vault_crud_contract".to_string(),
        })
        .build()
        .expect("build valence");
    gauge_test_wiring::wire_neutrino_gauge_groups(&v).await;
    gauge_test_wiring::seed_default_vault_users(&v).await;
    v
}

fn store(v: Valence) -> ValenceSealedStore {
    store_from_valence(v)
}

fn access(actor: &str) -> VaultAccessContext {
    VaultAccessContext::owner_only(actor)
}

fn decode_plaintext_b64(b64: &str) -> Vec<u8> {
    B64.decode(b64.as_bytes())
        .expect("valid base64 from reveal")
}

fn assert_not_found_or_pending(msg: &str) {
    let lower = msg.to_lowercase();
    assert!(
        lower.contains("not found") || lower.contains("pending deletion"),
        "expected not-found or pending-deletion, got: {msg}"
    );
}

#[tokio::test]
async fn neutrino_vault_ping_succeeds_happy_path() {
    let store = store(test_valence().await);
    neutrino_vault_ping(&store)
        .await
        .expect("ping should succeed for wired store");
}

#[tokio::test]
async fn create_vault_secret_returns_row_happy_path() {
    let store = store(test_valence().await);
    let row = create_vault_secret(
        &store,
        "smtp_password".into(),
        "/uf-notifications/smtp".into(),
        "password".into(),
        "correct-horse".into(),
        "test-actor".into(),
    )
    .await
    .expect("create");

    assert_ne!(row.id, "");
    assert_eq!(row.name, "smtp_password");
    assert_eq!(row.scope_path, "/uf-notifications/smtp");
    assert_eq!(row.kind, "password");
    assert_eq!(row.current_version, 1);
    assert_ne!(row.created_at, "");
}

#[tokio::test]
async fn list_vault_secrets_includes_created_happy_path() {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v.clone()),
        request_actor: Some("actor".into()),
    };
    let created = create_vault_secret(
        &store,
        "listed".into(),
        "/scope/list".into(),
        "token".into(),
        "list-pt".into(),
        "actor".into(),
    )
    .await
    .expect("create");

    let rows = list_vault_secrets(&v, &access("actor"))
        .await
        .expect("list");
    let row = rows
        .iter()
        .find(|r| r.id == created.id)
        .expect("created secret in list");
    assert_eq!(row.name, "listed");
    assert_eq!(row.scope_path, "/scope/list");
    assert_eq!(row.kind, "token");
    assert_eq!(row.current_version, 1);
}

#[tokio::test]
async fn reveal_vault_secret_round_trips_happy_path() {
    let store = store(test_valence().await);
    let plaintext = "reveal-me-once";
    let created = create_vault_secret(
        &store,
        "reveal_target".into(),
        "/scope/reveal".into(),
        "password".into(),
        plaintext.into(),
        "actor".into(),
    )
    .await
    .expect("create");

    let revealed = reveal_vault_secret(&store, created.id.clone(), &access("actor"))
        .await
        .expect("reveal");
    let got = decode_plaintext_b64(&revealed.plaintext_b64);
    assert_eq!(got.as_slice(), plaintext.as_bytes());
}

#[tokio::test]
async fn rotate_vault_secret_bumps_version_happy_path() {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v.clone()),
        request_actor: Some("actor".into()),
    };
    let created = create_vault_secret(
        &store,
        "rotate_target".into(),
        "/scope/rotate".into(),
        "password".into(),
        "version-one".into(),
        "actor".into(),
    )
    .await
    .expect("create");
    assert_eq!(created.current_version, 1);

    let rotated = rotate_vault_secret(
        &store,
        created.id.clone(),
        "version-two".into(),
        "actor",
        &access("actor"),
    )
    .await
    .expect("rotate");
    assert_eq!(rotated.id, created.id);
    assert_eq!(rotated.current_version, 2);

    let revealed = reveal_vault_secret(&store, created.id, &access("actor"))
        .await
        .expect("reveal after rotate");
    let got = decode_plaintext_b64(&revealed.plaintext_b64);
    assert_eq!(got.as_slice(), b"version-two");
}

#[tokio::test]
async fn delete_vault_secret_removes_from_list_happy_path() {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v.clone()),
        request_actor: Some("actor".into()),
    };
    let created = create_vault_secret(
        &store,
        "delete_target".into(),
        "/scope/delete".into(),
        "password".into(),
        "to-delete".into(),
        "actor".into(),
    )
    .await
    .expect("create");

    delete_vault_secret(&store, created.id.clone(), &access("actor"))
        .await
        .expect("delete");

    let rows = list_vault_secrets(&v, &access("actor"))
        .await
        .expect("list");
    assert!(
        rows.iter().all(|r| r.id != created.id),
        "deleted secret must not appear in list"
    );

    let reveal_err = reveal_vault_secret(&store, created.id, &access("actor"))
        .await
        .expect_err("reveal after delete");
    assert_not_found_or_pending(&reveal_err.to_string());
}

#[tokio::test]
async fn vault_crud_workflow_create_list_reveal_rotate_delete_happy_path() {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v.clone()),
        request_actor: Some("actor".into()),
    };
    let access = access("actor");

    neutrino_vault_ping(&store).await.expect("ping");

    let created = create_vault_secret(
        &store,
        "workflow".into(),
        "/scope/workflow".into(),
        "password".into(),
        "wf-v1".into(),
        "actor".into(),
    )
    .await
    .expect("create");

    let listed = list_vault_secrets(&v, &access).await.expect("list");
    assert!(listed.iter().any(|r| r.id == created.id));

    let revealed = reveal_vault_secret(&store, created.id.clone(), &access)
        .await
        .expect("reveal");
    assert_eq!(
        decode_plaintext_b64(&revealed.plaintext_b64).as_slice(),
        b"wf-v1"
    );

    let rotated = rotate_vault_secret(&store, created.id.clone(), "wf-v2".into(), "actor", &access)
        .await
        .expect("rotate");
    assert_eq!(rotated.current_version, 2);

    let revealed2 = reveal_vault_secret(&store, created.id.clone(), &access)
        .await
        .expect("reveal after rotate");
    assert_eq!(
        decode_plaintext_b64(&revealed2.plaintext_b64).as_slice(),
        b"wf-v2"
    );

    delete_vault_secret(&store, created.id.clone(), &access)
        .await
        .expect("delete");

    let after = list_vault_secrets(&v, &access)
        .await
        .expect("list after delete");
    assert!(after.iter().all(|r| r.id != created.id));

    let reveal_err = reveal_vault_secret(&store, created.id, &access)
        .await
        .expect_err("reveal after delete");
    assert_not_found_or_pending(&reveal_err.to_string());
}

#[tokio::test]
async fn create_vault_secret_blank_name_rejected_sad() {
    let store = store(test_valence().await);
    let err = create_vault_secret(
        &store,
        "   ".into(),
        "/scope".into(),
        "kind".into(),
        "pt".into(),
        "actor".into(),
    )
    .await
    .expect_err("blank name");
    let msg = err.to_string();
    assert!(msg.contains("Name is required"), "got: {msg}");
}

#[tokio::test]
async fn create_vault_secret_blank_scope_rejected_sad() {
    let store = store(test_valence().await);
    let err = create_vault_secret(
        &store,
        "n".into(),
        String::new(),
        "kind".into(),
        "pt".into(),
        "actor".into(),
    )
    .await
    .expect_err("blank scope");
    assert!(err.to_string().contains("Scope path is required"));
}

#[tokio::test]
async fn create_vault_secret_blank_kind_rejected_sad() {
    let store = store(test_valence().await);
    let err = create_vault_secret(
        &store,
        "n".into(),
        "/s".into(),
        " ".into(),
        "pt".into(),
        "actor".into(),
    )
    .await
    .expect_err("blank kind");
    assert!(err.to_string().contains("Kind is required"));
}

#[tokio::test]
async fn create_vault_secret_empty_plaintext_rejected_sad() {
    let store = store(test_valence().await);
    let err = create_vault_secret(
        &store,
        "n".into(),
        "/s".into(),
        "k".into(),
        String::new(),
        "actor".into(),
    )
    .await
    .expect_err("empty plaintext");
    let msg = err.to_string();
    assert!(msg.contains("Plaintext is required"), "got: {msg}");
    // Error path must not echo secret material (none here; guard the message shape).
    assert!(!msg.contains("password="));
}

#[tokio::test]
async fn reveal_vault_secret_blank_id_rejected_sad() {
    let store = store(test_valence().await);
    let err = reveal_vault_secret(&store, "  ".into(), &access("actor"))
        .await
        .expect_err("blank id");
    assert!(err.to_string().contains("Secret id is required"));
}

#[tokio::test]
async fn reveal_vault_secret_unknown_id_not_found_sad() {
    let store = store(test_valence().await);
    let err = reveal_vault_secret(&store, "missing-secret-id".into(), &access("actor"))
        .await
        .expect_err("unknown id");
    assert_not_found_or_pending(&err.to_string());
}

#[tokio::test]
async fn delete_vault_secret_unknown_id_not_found_sad() {
    let store = store(test_valence().await);
    let err = delete_vault_secret(&store, "missing-secret-id".into(), &access("actor"))
        .await
        .expect_err("unknown id");
    assert_not_found_or_pending(&err.to_string());
}

#[tokio::test]
async fn rotate_vault_secret_empty_plaintext_rejected_sad() {
    let store = store(test_valence().await);
    let created = create_vault_secret(
        &store,
        "rot_sad".into(),
        "/scope/rot_sad".into(),
        "password".into(),
        "initial".into(),
        "actor".into(),
    )
    .await
    .expect("create");

    let err = rotate_vault_secret(&store, created.id, String::new(), "actor", &access("actor"))
        .await
        .expect_err("empty new plaintext");
    assert!(err.to_string().contains("New plaintext is required"));
}

#[tokio::test]
async fn rotate_vault_secret_unknown_id_not_found_sad() {
    let store = store(test_valence().await);
    let err = rotate_vault_secret(
        &store,
        "missing-secret-id".into(),
        "new-pt".into(),
        "actor",
        &access("actor"),
    )
    .await
    .expect_err("unknown id");
    assert_not_found_or_pending(&err.to_string());
}
