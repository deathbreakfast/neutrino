#![cfg(feature = "ssr")]
#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Lease + extend_grace contracts for [`neutrino::ValenceSealedStore`].

mod gauge_test_wiring;

use std::sync::Arc;
use std::time::Duration;

use neutrino::generated::{NeutrinoSecretVersion, NeutrinoSecretVersionStatus};
use neutrino::secret_store::{LeaseRequest, PutSecretRequest, SecretId, SecretStore};
use neutrino::ValenceSealedStore;
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter, RecordId,
    RecordPredicate, RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

fn test_master_key_hex() -> String {
    "0".repeat(64)
}

fn prepare_test_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    // SAFETY: test harness only.
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
            operation: "neutrino_lease_grace_test".to_string(),
        })
        .build()
        .expect("build valence");
    gauge_test_wiring::wire_neutrino_gauge_groups(&v).await;
    gauge_test_wiring::seed_user("test-actor", "test-actor@example.test", &v).await;
    v
}

fn put_req(plaintext: &[u8]) -> PutSecretRequest {
    PutSecretRequest {
        name: "db-pass".to_string(),
        scope_path: "/nucleus/cells/c1/scoped_creds/chronon/default".to_string(),
        kind: "password".to_string(),
        plaintext: plaintext.to_vec(),
        owner_actor: "test-actor".to_string(),
    }
}

#[tokio::test]
async fn lease_ttl_and_plaintext_happy() -> anyhow::Result<()> {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v),
        request_actor: None,
    };
    let cref = store.put(put_req(b"secret-plain-v1")).await?;
    let before = chrono::Utc::now();
    let lease = store
        .lease(LeaseRequest {
            secret_id: cref.id.clone(),
            version: None,
            leased_to: "gluon-agent-c1".into(),
            ttl: Duration::from_secs(300),
        })
        .await?;
    assert_eq!(lease.version, cref.version);
    assert_eq!(&*lease.plaintext, b"secret-plain-v1");
    assert_eq!(lease.leased_to, "gluon-agent-c1");
    assert!(!lease.lease_id.is_empty());
    assert!(lease.expires_at > before + chrono::Duration::seconds(250));
    Ok(())
}

#[tokio::test]
async fn lease_archived_sad() -> anyhow::Result<()> {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v),
        request_actor: None,
    };
    let cref = store.put(put_req(b"v1")).await?;
    let _ = store.rotate(&cref.id, b"v2".to_vec(), "test-actor").await?;
    // Force prior version archived (rotate leaves grace; apply success path would archive).
    let secret_rid = RecordId::new("neutrino_secret", cref.id.0.as_str());
    let rows = NeutrinoSecretVersion::query(
        store.valence.as_ref(),
        valence::use_!(r"**Test:** When we **write that secret into the vault**, we **save one sealed version**: the **encrypted secret** plus what is needed to unlock it later. The vault **encrypts the secret with the master key** before this save; later, only callers who are allowed can **unlock it in memory on the server**—not other tenants, and not as a downloadable plaintext file in this step."),
    )
    .where_secret_id(RecordPredicate::Equals(secret_rid))
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let prior = rows
        .into_iter()
        .find(|r| *r.version_num() == cref.version)
        .expect("prior version");
    prior
        .get_mutable(
            store.valence.as_ref(),
            valence::use_!(r"**Test:** In **Neutrino sealed vault**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **Neutrino sealed vault** use the updated data; this is not a public export of unrelated fields."),
        )
        .set_status(NeutrinoSecretVersionStatus::Archived)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .commit()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let err = store
        .lease(LeaseRequest {
            secret_id: cref.id.clone(),
            version: Some(cref.version),
            leased_to: "gluon-agent-c1".into(),
            ttl: Duration::from_secs(60),
        })
        .await
        .expect_err("archived version must not lease");
    let msg = err.to_string();
    assert!(
        msg.contains("archived") || msg.contains("version"),
        "unexpected: {msg}"
    );
    Ok(())
}

#[tokio::test]
async fn lease_not_found_sad() -> anyhow::Result<()> {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v),
        request_actor: None,
    };
    let err = store
        .lease(LeaseRequest {
            secret_id: SecretId("missing-secret".into()),
            version: None,
            leased_to: "gluon-agent-c1".into(),
            ttl: Duration::from_secs(60),
        })
        .await
        .expect_err("missing secret");
    assert!(
        matches!(err, neutrino::NeutrinoError::NotFound { .. })
            || matches!(err, neutrino::NeutrinoError::AccessDenied { .. }),
        "got {err}"
    );
    Ok(())
}

#[tokio::test]
async fn extend_grace_status_happy() -> anyhow::Result<()> {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v),
        request_actor: None,
    };
    let cref = store.put(put_req(b"old")).await?;
    let rotated = store
        .rotate(&cref.id, b"new".to_vec(), "test-actor")
        .await?;
    assert!(rotated.version > cref.version);

    // Archive prior, then extend_grace should revive to Grace and allow lease.
    let secret_rid = RecordId::new("neutrino_secret", cref.id.0.as_str());
    let rows = NeutrinoSecretVersion::query(
        store.valence.as_ref(),
        valence::use_!(r"**Test:** When we **write that secret into the vault**, we **save one sealed version**: the **encrypted secret** plus what is needed to unlock it later. The vault **encrypts the secret with the master key** before this save; later, only callers who are allowed can **unlock it in memory on the server**—not other tenants, and not as a downloadable plaintext file in this step."),
    )
    .where_secret_id(RecordPredicate::Equals(secret_rid.clone()))
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let prior = rows
        .into_iter()
        .find(|r| *r.version_num() == cref.version)
        .expect("prior");
    prior
        .get_mutable(
            store.valence.as_ref(),
            valence::use_!(r"**Test:** In **Neutrino sealed vault**, we **update this data** so later steps see the latest values for this workflow. Callers allowed for **Neutrino sealed vault** use the updated data; this is not a public export of unrelated fields."),
        )
        .set_status(NeutrinoSecretVersionStatus::Archived)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .commit()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    store.extend_grace(&cref.id, 86400, "test-actor").await?;

    let lease = store
        .lease(LeaseRequest {
            secret_id: cref.id.clone(),
            version: Some(cref.version),
            leased_to: "gluon-agent-c1".into(),
            ttl: Duration::from_secs(60),
        })
        .await?;
    assert_eq!(&*lease.plaintext, b"old");

    let rows = NeutrinoSecretVersion::query(
        store.valence.as_ref(),
        valence::use_!(r"**Test:** When we **write that secret into the vault**, we **save one sealed version**: the **encrypted secret** plus what is needed to unlock it later. The vault **encrypts the secret with the master key** before this save; later, only callers who are allowed can **unlock it in memory on the server**—not other tenants, and not as a downloadable plaintext file in this step."),
    )
    .where_secret_id(RecordPredicate::Equals(secret_rid))
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let status = rows
        .iter()
        .find(|r| *r.version_num() == cref.version)
        .map(|r| r.status().clone())
        .expect("prior row");
    assert_eq!(status, NeutrinoSecretVersionStatus::Grace);
    Ok(())
}

#[tokio::test]
async fn extend_grace_missing_sad() -> anyhow::Result<()> {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v),
        request_actor: None,
    };
    let err = store
        .extend_grace(&SecretId("no-such".into()), 60, "test-actor")
        .await
        .expect_err("missing");
    assert!(matches!(err, neutrino::NeutrinoError::NotFound { .. }));
    Ok(())
}

#[tokio::test]
async fn extend_grace_no_prior_version_sad() -> anyhow::Result<()> {
    let v = test_valence().await;
    let store = ValenceSealedStore {
        valence: Arc::new(v),
        request_actor: None,
    };
    let cref = store.put(put_req(b"only")).await?;
    let err = store
        .extend_grace(&cref.id, 60, "test-actor")
        .await
        .expect_err("v1 has no prior");
    assert!(matches!(err, neutrino::NeutrinoError::InvalidState { .. }));
    Ok(())
}
