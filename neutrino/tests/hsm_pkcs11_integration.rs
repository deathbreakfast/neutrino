//! Env-gated SoftHSM PKCS#11 integration tests.
//!
//! Enable with `NEUTRINO_PKCS11_INTEGRATION=1` and the env vars documented in
//! `docs/hsm-local-setup.md`. Skips cleanly when the gate is unset.

#![cfg(feature = "hsm-pkcs11")]

use neutrino::hsm_sources::pkcs11::Pkcs11KeySource;
use neutrino::{clear_master_key_cache, resolve_master_key, KeySource, MasterKeyError};

fn integration_enabled() -> bool {
    std::env::var("NEUTRINO_PKCS11_INTEGRATION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[tokio::test]
async fn pkcs11_softhsm_unwrap_happy() {
    if !integration_enabled() {
        eprintln!("skip: set NEUTRINO_PKCS11_INTEGRATION=1 (see docs/hsm-local-setup.md)");
        return;
    }
    clear_master_key_cache();
    std::env::set_var("NEUTRINO_KEY_SOURCE", "pkcs11");
    let src = Pkcs11KeySource::from_env().expect("from_env");
    let resolved = src.resolve().await.expect("pkcs11 resolve");
    assert_eq!(resolved.len(), 32);
    assert_eq!(resolved.provenance().source_label(), "hsm");
    let via_resolve = resolve_master_key().await.expect("resolve_master_key");
    assert_eq!(via_resolve.as_slice(), resolved.as_slice());
}

#[tokio::test]
async fn pkcs11_softhsm_bad_label_sad() {
    if !integration_enabled() {
        eprintln!("skip: set NEUTRINO_PKCS11_INTEGRATION=1 (see docs/hsm-local-setup.md)");
        return;
    }
    clear_master_key_cache();
    let module = std::env::var("NEUTRINO_PKCS11_MODULE").expect("module");
    let pin = std::env::var("NEUTRINO_PKCS11_PIN").expect("pin");
    let slot = std::env::var("NEUTRINO_PKCS11_SLOT")
        .ok()
        .and_then(|s| s.parse().ok());
    let wrapped = neutrino::key_source::wrapped_master_key_from_env_kind("pkcs11").expect("wrap");
    use neutrino::hsm_sources::pkcs11::Pkcs11CryptokiDecryptClient;
    use std::sync::Arc;
    let src = Pkcs11KeySource::with_client(
        "no-such-neutrino-key-label",
        wrapped,
        Arc::new(Pkcs11CryptokiDecryptClient::new(module, pin, slot)),
    );
    let err = src.resolve().await.expect_err("bad label");
    assert!(matches!(
        err,
        MasterKeyError::Provider {
            provider: "pkcs11",
            operation: "Decrypt",
        }
    ));
    assert!(!err.to_string().contains("no-such-neutrino-key-label"));
}
