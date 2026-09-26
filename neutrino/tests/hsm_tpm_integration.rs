//! Env-gated swtpm TPM 2.0 integration tests.
//!
//! Enable with `NEUTRINO_TPM_INTEGRATION=1` and the env vars documented in
//! `docs/hsm-local-setup.md`. Skips cleanly when the gate is unset.

#![cfg(feature = "hsm-tpm")]

use neutrino::hsm_sources::tpm::{TpmEsapiDecryptClient, TpmKeySource};
use neutrino::{clear_master_key_cache, resolve_master_key, KeySource, MasterKeyError};
use std::sync::Arc;

fn integration_enabled() -> bool {
    std::env::var("NEUTRINO_TPM_INTEGRATION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[tokio::test]
async fn tpm_swtpm_unwrap_happy() {
    if !integration_enabled() {
        eprintln!("skip: set NEUTRINO_TPM_INTEGRATION=1 (see docs/hsm-local-setup.md)");
        return;
    }
    clear_master_key_cache();
    std::env::set_var("NEUTRINO_KEY_SOURCE", "tpm");
    let src = TpmKeySource::from_env().expect("from_env");
    let resolved = src.resolve().await.expect("tpm resolve");
    assert_eq!(resolved.len(), 32);
    assert_eq!(resolved.provenance().source_label(), "hsm");
    let via_resolve = resolve_master_key().await.expect("resolve_master_key");
    assert_eq!(via_resolve.as_slice(), resolved.as_slice());
}

#[tokio::test]
async fn tpm_swtpm_bad_handle_sad() {
    if !integration_enabled() {
        eprintln!("skip: set NEUTRINO_TPM_INTEGRATION=1 (see docs/hsm-local-setup.md)");
        return;
    }
    clear_master_key_cache();
    let tcti = std::env::var("NEUTRINO_TPM_TCTI").expect("tcti");
    let wrapped = neutrino::key_source::wrapped_master_key_from_env_kind("tpm").expect("wrap");
    let src = TpmKeySource::with_client(
        "0x8100DEAD",
        wrapped,
        Arc::new(TpmEsapiDecryptClient::new(tcti)),
    );
    let err = src.resolve().await.expect_err("bad handle");
    assert!(matches!(
        err,
        MasterKeyError::Provider {
            provider: "tpm",
            operation: "Decrypt",
        } | MasterKeyError::Unavailable { provider: "tpm" }
    ));
    assert!(!err.to_string().contains("DEAD"));
}
