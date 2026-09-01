//! Deny-allow contracts for archived reveal and audit-append failure modes.

#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod gauge_test_wiring;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use neutrino::instrumentation::set_audit_append_fail_for_tests;
use neutrino::secret_store::{PutSecretRequest, SecretId, SecretStore};
use neutrino::vault::{
    create_vault_secret, delete_vault_secret, reveal_vault_secret, rotate_vault_secret,
    store_from_valence, VaultAccessContext,
};
use neutrino::{NeutrinoError, ValenceSealedStore};
use tokio::sync::{Mutex, MutexGuard};
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter,
    RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

/// Serialize tests that flip the process-wide audit-append fail hook.
static AUDIT_HOOK_TEST_LOCK: Mutex<()> = Mutex::const_new(());

fn test_master_key_hex() -> String {
    "0".repeat(64)
}

async fn prepare_test_env() -> MutexGuard<'static, ()> {
    let guard = AUDIT_HOOK_TEST_LOCK.lock().await;
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    set_audit_append_fail_for_tests(false);
    // SAFETY: test harness only; OnceLock reads this before first ownership get.
    unsafe {
        std::env::set_var("NEUTRINO_MASTER_KEY", test_master_key_hex());
        if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
            std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
        }
    }
    guard
}

async fn test_valence() -> (Valence, MutexGuard<'static, ()>) {
    let guard = prepare_test_env().await;
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
            operation: "neutrino_vault_security_remediation".to_string(),
        })
        .build()
        .expect("build valence");
    gauge_test_wiring::wire_neutrino_gauge_groups(&v).await;
    gauge_test_wiring::seed_default_vault_users(&v).await;
    (v, guard)
}

fn store(v: Valence) -> ValenceSealedStore {
    store_from_valence(v)
}

fn access(actor: &str) -> VaultAccessContext {
    VaultAccessContext::owner_only(actor)
}

#[tokio::test]
async fn reveal_at_version_archived_denied_active_allowed() {
    let (v, _audit_hook_guard) = test_valence().await;
    let store = store(v);
    let created = create_vault_secret(
        &store,
        "archived_pin".into(),
        "/scope/archived".into(),
        "password".into(),
        "version-one".into(),
        "actor".into(),
    )
    .await
    .expect("create");

    rotate_vault_secret(
        &store,
        created.id.clone(),
        "version-two".into(),
        "actor",
        &access("actor"),
    )
    .await
    .expect("rotate");

    let archived_err = store
        .reveal_at_version(&SecretId(created.id.clone()), 1)
        .await
        .expect_err("archived version must be denied");
    assert!(
        matches!(
            &archived_err,
            NeutrinoError::Validation { field: "version", message }
            if message.contains("archived")
        ),
        "got: {archived_err:?}"
    );

    let current = store
        .reveal_at_version(&SecretId(created.id.clone()), 2)
        .await
        .expect("active version reveal");
    assert_eq!(current.plaintext.as_slice(), b"version-two");

    let via_vault = reveal_vault_secret(&store, created.id, &access("actor"))
        .await
        .expect("current via vault API");
    let got = B64
        .decode(via_vault.plaintext_b64.as_bytes())
        .expect("valid b64");
    assert_eq!(got.as_slice(), b"version-two");
}

#[tokio::test]
async fn vault_mutate_denied_when_audit_append_fails() {
    let (v, _audit_hook_guard) = test_valence().await;
    let store = store(v);
    set_audit_append_fail_for_tests(true);

    let put_err = create_vault_secret(
        &store,
        "audit_fail_put".into(),
        "/scope/audit".into(),
        "password".into(),
        "secret".into(),
        "actor".into(),
    )
    .await
    .expect_err("put must fail closed when audit append fails");
    assert!(
        put_err
            .to_string()
            .contains("audit append disabled for test"),
        "got: {put_err}"
    );

    set_audit_append_fail_for_tests(false);
    let created = create_vault_secret(
        &store,
        "audit_fail_delete".into(),
        "/scope/audit".into(),
        "password".into(),
        "secret".into(),
        "actor".into(),
    )
    .await
    .expect("create with audit enabled");

    set_audit_append_fail_for_tests(true);
    let delete_err = delete_vault_secret(&store, created.id.clone(), &access("actor"))
        .await
        .expect_err("delete must fail closed when audit append fails");
    assert!(delete_err
        .to_string()
        .contains("audit append disabled for test"));

    let still_there = reveal_vault_secret(&store, created.id.clone(), &access("actor"))
        .await
        .expect("secret must remain when delete audit fails");
    assert!(!still_there.plaintext_b64.is_empty());

    set_audit_append_fail_for_tests(false);
    let rotate_err = rotate_vault_secret(
        &store,
        created.id.clone(),
        "rotated".into(),
        "actor",
        &access("actor"),
    )
    .await;
    assert!(rotate_err.is_ok(), "rotate with audit restored");

    set_audit_append_fail_for_tests(true);
    let rotate_fail = rotate_vault_secret(
        &store,
        created.id,
        "rotated-again".into(),
        "actor",
        &access("actor"),
    )
    .await
    .expect_err("rotate must fail closed when audit append fails");
    assert!(rotate_fail
        .to_string()
        .contains("audit append disabled for test"));
}

#[tokio::test]
async fn vault_read_allowed_when_audit_append_fails() {
    let (v, _audit_hook_guard) = test_valence().await;
    let store = store(v);
    let created = create_vault_secret(
        &store,
        "audit_fail_read".into(),
        "/scope/read".into(),
        "password".into(),
        "readable".into(),
        "actor".into(),
    )
    .await
    .expect("create");

    set_audit_append_fail_for_tests(true);
    let revealed = reveal_vault_secret(&store, created.id.clone(), &access("actor"))
        .await
        .expect("read should remain available when audit append fails");
    let got = B64
        .decode(revealed.plaintext_b64.as_bytes())
        .expect("valid b64");
    assert_eq!(got.as_slice(), b"readable");

    let direct = store
        .get(&SecretId(created.id))
        .await
        .expect("store get should succeed when audit append fails");
    assert_eq!(direct.plaintext.as_slice(), b"readable");
}

#[tokio::test]
async fn put_or_reuse_denied_when_audit_append_fails() {
    let (v, _audit_hook_guard) = test_valence().await;
    let store = store(v);
    set_audit_append_fail_for_tests(true);

    let err = store
        .put(PutSecretRequest {
            name: "direct_put".into(),
            scope_path: "/scope/direct".into(),
            kind: "password".into(),
            plaintext: b"secret".to_vec(),
            owner_actor: "actor".into(),
        })
        .await
        .expect_err("direct put must fail closed");
    assert!(err.to_string().contains("audit append disabled for test"));
}
