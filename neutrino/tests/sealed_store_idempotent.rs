#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Idempotent `put_or_reuse` for [`neutrino::ValenceSealedStore`].

mod gauge_test_wiring;

use std::sync::Arc;

use neutrino::secret_store::{PutSecretRequest, SecretStore};
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
    // SAFETY: test harness only; OnceLock / env key read before store ops.
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
            operation: "neutrino_sealed_store_idempotent_test".to_string(),
        })
        .build()
        .expect("build valence");
    gauge_test_wiring::wire_neutrino_gauge_groups(&v).await;
    gauge_test_wiring::seed_user("test-actor", "test-actor@example.test", &v).await;
    v
}

fn put_req(name: &str, scope: &str, plaintext: &[u8]) -> PutSecretRequest {
    PutSecretRequest {
        name: name.to_string(),
        scope_path: scope.to_string(),
        kind: "test_kind".to_string(),
        plaintext: plaintext.to_vec(),
        owner_actor: "test-actor".to_string(),
    }
}

#[tokio::test]
async fn put_or_reuse_same_plaintext_reuses_id() -> anyhow::Result<()> {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v),
        request_actor: None,
    };
    let r1 = store
        .put_or_reuse(put_req(
            "n1",
            "/s1",
            b"{\"user\":\"a\",\"password\":\"p1\"}",
        ))
        .await?;
    let r2 = store
        .put_or_reuse(put_req(
            "n1",
            "/s1",
            b"{\"user\":\"a\",\"password\":\"p1\"}",
        ))
        .await?;
    assert_eq!(r1.id.0, r2.id.0);
    assert_eq!(r1.version, r2.version);
    let rows = neutrino::generated::NeutrinoSecret::query(store.valence.as_ref())
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let n1_count = rows
        .into_iter()
        .filter(|r| r.name() == "n1" && r.scope_path() == "/s1")
        .count();
    assert_eq!(n1_count, 1, "expected single row for (name, scope_path)");
    Ok(())
}

#[tokio::test]
async fn put_or_reuse_different_plaintext_rotates() -> anyhow::Result<()> {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v),
        request_actor: None,
    };
    let r1 = store
        .put_or_reuse(put_req(
            "n2",
            "/s2",
            b"{\"user\":\"a\",\"password\":\"old\"}",
        ))
        .await?;
    let r2 = store
        .put_or_reuse(put_req(
            "n2",
            "/s2",
            b"{\"user\":\"a\",\"password\":\"new\"}",
        ))
        .await?;
    assert_eq!(r1.id.0, r2.id.0);
    assert!(r2.version > r1.version);
    Ok(())
}
