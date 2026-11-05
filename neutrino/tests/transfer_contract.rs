#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Moving a vault between hosts: sealed rows and the audit chain transfer verbatim.

mod gauge_test_wiring;

use std::sync::Arc;

use neutrino::secret_store::{PutSecretRequest, SecretStore};
use neutrino::transfer::{
    export_bundle, generate_master_key_hex, import_bundle, purge_exported, verify_bundle,
};
use neutrino::{clear_master_key_cache, resolve_master_key, SecretId, ValenceSealedStore};
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter,
    RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

/// Env and the Valence registry are process-global; run the tests one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn host_valence(label: &str) -> Valence {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    // SAFETY: test harness only; the key is set before any store operation.
    unsafe {
        if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
            std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
        }
    }
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
            operation: format!("neutrino_transfer_test_{label}"),
        })
        .build()
        .expect("build valence");
    gauge_test_wiring::wire_neutrino_gauge_groups(&v).await;
    gauge_test_wiring::seed_user("test-actor", "test-actor@example.test", &v).await;
    v
}

fn put_req(name: &str, plaintext: &[u8]) -> PutSecretRequest {
    PutSecretRequest {
        name: name.to_string(),
        scope_path: "/provider".to_string(),
        kind: "credential".to_string(),
        plaintext: plaintext.to_vec(),
        owner_actor: "test-actor".to_string(),
    }
}

/// Installer seals tokens, the bundle moves to the cell, the cell resolves them and verifies the
/// chain, then the installer purges its copy and its key stops loading.
#[tokio::test]
async fn sealed_token_resolves_on_cell_then_installer_copy_is_gone() {
    let _guard = SERIAL.lock().await;
    let key = generate_master_key_hex();
    // SAFETY: test harness only; this is the only test in the binary that reads the key.
    unsafe { std::env::set_var("NEUTRINO_MASTER_KEY", key.as_str()) };
    clear_master_key_cache();

    let installer = Arc::new(host_valence("installer").await);
    let store = ValenceSealedStore {
        valence: installer.clone(),
        request_actor: None,
    };
    let token = store.put(put_req("cf_token", b"tok-1")).await.unwrap();
    let other = store.put(put_req("dns_token", b"tok-2")).await.unwrap();
    store
        .rotate(&token.id, b"tok-1b".to_vec(), "test-actor")
        .await
        .unwrap();
    store.get(&other.id).await.unwrap();

    let bundle = export_bundle(&installer).await.unwrap();
    assert_eq!(bundle.secrets.len(), 2);
    assert_eq!(bundle.versions.len(), 3);
    assert!(
        bundle.audit_events.len() >= 3,
        "events: {:?}",
        bundle
            .audit_events
            .iter()
            .map(|e| (&e.action, &e.outcome))
            .collect::<Vec<_>>()
    );
    verify_bundle(&bundle).unwrap();

    // Ship the bundle as bytes, as the handoff does.
    let wire = serde_json::to_vec(&bundle).unwrap();
    let received: neutrino::transfer::TransferBundle = serde_json::from_slice(&wire).unwrap();

    let cell = Arc::new(host_valence("cell").await);
    let report = import_bundle(&cell, &received, "test-actor").await.unwrap();
    assert_eq!(report.secrets, 2);
    assert_eq!(report.versions, 3);
    assert_eq!(report.audit_events, bundle.audit_events.len());

    let cell_store = ValenceSealedStore {
        valence: cell.clone(),
        request_actor: None,
    };
    let got = cell_store.get(&token.id).await.unwrap();
    assert_eq!(&**got.plaintext, b"tok-1b");
    let got = cell_store.get(&other.id).await.unwrap();
    assert_eq!(&**got.plaintext, b"tok-2");

    // Chain rows copied verbatim: the cell's rows still verify, now with its own reads appended.
    let on_cell = export_bundle(&cell).await.unwrap();
    verify_bundle(&on_cell).unwrap();
    for e in &bundle.audit_events {
        assert!(
            on_cell.audit_events.iter().any(|c| c == e),
            "event {} kept",
            e.id
        );
    }

    // Re-importing is a no-op.
    import_bundle(&cell, &received, "test-actor").await.unwrap();
    assert_eq!(export_bundle(&cell).await.unwrap().secrets.len(), 2);

    // Wrong key on the cell cannot open the rows.
    let v = bundle.versions.first().unwrap();
    let salt = format!("{}|v{}", v.secret_id, v.version_num);
    let nonce = base64_decode(&v.nonce_b64);
    let ct = base64_decode(&v.sealed_payload_b64);
    assert!(neutrino::crypto::unseal(&[7u8; 32], salt.as_bytes(), &nonce, &ct).is_err());

    // Finalize: the installer's rows go and its key no longer loads.
    purge_exported(&installer, &bundle).await.unwrap();
    assert!(export_bundle(&installer).await.unwrap().secrets.is_empty());
    assert!(store.get(&SecretId(token.id.0.clone())).await.is_err());
    // SAFETY: test harness only.
    unsafe { std::env::remove_var("NEUTRINO_MASTER_KEY") };
    clear_master_key_cache();
    assert!(resolve_master_key().await.is_err());
}

#[tokio::test]
async fn import_rejects_tampered_chain_and_writes_nothing() {
    let _guard = SERIAL.lock().await;
    let key = generate_master_key_hex();
    // SAFETY: test harness only.
    unsafe { std::env::set_var("NEUTRINO_MASTER_KEY", key.as_str()) };
    let installer = Arc::new(host_valence("installer_t").await);
    let store = ValenceSealedStore {
        valence: installer.clone(),
        request_actor: None,
    };
    store.put(put_req("cf_token", b"tok")).await.unwrap();
    let mut bundle = export_bundle(&installer).await.unwrap();
    bundle.audit_events[0].actor = "mallory".to_string();

    let cell = host_valence("cell_t").await;
    assert!(import_bundle(&cell, &bundle, "test-actor").await.is_err());
    assert!(export_bundle(&cell).await.unwrap().secrets.is_empty());
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
