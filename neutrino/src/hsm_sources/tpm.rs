//! TPM 2.0-backed master key unwrap (RSA-OAEP decrypt of wrapped MEK).

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::key_source::{
    wrapped_master_key_from_env_kind, HsmBackend, KeySource, MasterKeyError, ResolvedMasterKey,
    WrappedKeyDecryptor,
};

use super::{log_provider_err, require_env, resolved_hsm};

const PROVIDER: &str = "tpm";

/// TPM 2.0-backed [`KeySource`].
pub struct TpmKeySource {
    key_handle: String,
    wrapped: Vec<u8>,
    client: Arc<dyn WrappedKeyDecryptor>,
}

impl std::fmt::Debug for TpmKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmKeySource")
            .field("key_handle", &self.key_handle)
            .field("wrapped_len", &self.wrapped.len())
            .finish_non_exhaustive()
    }
}

impl TpmKeySource {
    /// Build from env: TCTI, persistent key handle, wrapped blob.
    ///
    /// Required: `NEUTRINO_MASTER_KEY_WRAPPED`, `NEUTRINO_TPM_TCTI`,
    /// `NEUTRINO_TPM_KEY_HANDLE` (hex, e.g. `0x81000001`).
    ///
    /// # Errors
    ///
    /// [`MasterKeyError::Config`] when required env vars are missing/invalid.
    pub fn from_env() -> Result<Self, MasterKeyError> {
        let tcti = require_env("NEUTRINO_TPM_TCTI", PROVIDER)?;
        let key_handle = require_env("NEUTRINO_TPM_KEY_HANDLE", PROVIDER)?;
        let wrapped = wrapped_master_key_from_env_kind(PROVIDER)?;
        Ok(Self::with_client(
            key_handle,
            wrapped,
            Arc::new(TpmEsapiDecryptClient::new(tcti)),
        ))
    }

    /// Construct with an injectable decrypt client (tests).
    #[must_use]
    pub fn with_client(
        key_handle: impl Into<String>,
        wrapped: Vec<u8>,
        client: Arc<dyn WrappedKeyDecryptor>,
    ) -> Self {
        Self {
            key_handle: key_handle.into(),
            wrapped,
            client,
        }
    }
}

#[async_trait]
impl KeySource for TpmKeySource {
    async fn resolve(&self) -> Result<ResolvedMasterKey, MasterKeyError> {
        let plaintext = self.client.decrypt(&self.wrapped, &self.key_handle).await?;
        resolved_hsm(plaintext, HsmBackend::Tpm, self.key_handle.clone())
    }
}

/// Live tss-esapi decrypt client (RSA-OAEP SHA-256).
pub struct TpmEsapiDecryptClient {
    tcti: String,
}

impl TpmEsapiDecryptClient {
    /// Create a client that opens a TPM context on first decrypt.
    #[must_use]
    pub fn new(tcti: impl Into<String>) -> Self {
        Self { tcti: tcti.into() }
    }

    fn decrypt_blocking(
        &self,
        ciphertext: &[u8],
        key_handle_str: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
        use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::{Data, HashScheme, PublicKeyRsa, RsaDecryptionScheme};
        use tss_esapi::tcti_ldr::TctiNameConf;
        use tss_esapi::Context;

        let tcti = TctiNameConf::from_str(&self.tcti).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "unavailable");
            MasterKeyError::Unavailable { provider: PROVIDER }
        })?;
        let mut context = Context::new(tcti).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "unavailable");
            MasterKeyError::Unavailable { provider: PROVIDER }
        })?;

        let handle_u32 = parse_tpm_handle(key_handle_str)?;
        let persistent = PersistentTpmHandle::new(handle_u32).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "provider");
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        })?;
        let object_handle = context
            .tr_from_tpm_public(TpmHandle::Persistent(persistent))
            .map_err(|_| {
                log_provider_err(PROVIDER, "Decrypt", "provider");
                MasterKeyError::Provider {
                    provider: PROVIDER,
                    operation: "Decrypt",
                }
            })?;
        let key_handle = KeyHandle::from(object_handle);

        let cipher = PublicKeyRsa::try_from(ciphertext.to_vec()).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "provider");
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        })?;
        let scheme = RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256));
        let label = Data::default();

        let plaintext = context
            .execute_with_nullauth_session(|ctx| {
                ctx.rsa_decrypt(key_handle, cipher.clone(), scheme, label.clone())
            })
            .map_err(|_| {
                log_provider_err(PROVIDER, "Decrypt", "provider");
                MasterKeyError::Provider {
                    provider: PROVIDER,
                    operation: "Decrypt",
                }
            })?;

        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

fn parse_tpm_handle(raw: &str) -> Result<u32, MasterKeyError> {
    let t = raw.trim();
    let parsed = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        t.parse::<u32>()
    };
    parsed.map_err(|_| MasterKeyError::Config {
        source_kind: PROVIDER,
        field: "NEUTRINO_TPM_KEY_HANDLE",
    })
}

#[async_trait]
impl WrappedKeyDecryptor for TpmEsapiDecryptClient {
    async fn decrypt(
        &self,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
        let ciphertext = ciphertext.to_vec();
        let key_id = key_id.to_string();
        let tcti = self.tcti.clone();
        tokio::task::spawn_blocking(move || {
            let client = Self { tcti };
            client.decrypt_blocking(&ciphertext, &key_id)
        })
        .await
        .map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "unavailable");
            MasterKeyError::Unavailable { provider: PROVIDER }
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockOk {
        plaintext: Vec<u8>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl WrappedKeyDecryptor for MockOk {
        async fn decrypt(
            &self,
            _ciphertext: &[u8],
            _key_id: &str,
        ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(self.plaintext.clone()))
        }
    }

    struct MockFail;

    #[async_trait]
    impl WrappedKeyDecryptor for MockFail {
        async fn decrypt(
            &self,
            _ciphertext: &[u8],
            _key_id: &str,
        ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
            Err(MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            })
        }
    }

    #[tokio::test]
    async fn tpm_mock_decrypt_happy() {
        let plaintext = vec![9u8; 32];
        let mock = Arc::new(MockOk {
            plaintext: plaintext.clone(),
            calls: AtomicUsize::new(0),
        });
        let src = TpmKeySource::with_client("0x81000001", vec![1, 2, 3], mock.clone());
        let resolved = src.resolve().await.expect("resolve");
        assert_eq!(resolved.as_slice(), plaintext.as_slice());
        assert_eq!(resolved.provenance().key_id(), "0x81000001");
        assert_eq!(resolved.provenance().source_label(), "hsm");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tpm_mock_decrypt_sad() {
        let src = TpmKeySource::with_client("0x81000001", vec![1], Arc::new(MockFail));
        let err = src.resolve().await.expect_err("denied");
        assert_eq!(
            err,
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        );
        assert!(!err.to_string().contains("0x81000001"));
    }

    #[test]
    fn parse_tpm_handle_happy_and_sad() {
        assert_eq!(parse_tpm_handle("0x81000001").unwrap(), 0x8100_0001);
        assert_eq!(parse_tpm_handle("2164260865").unwrap(), 0x8100_0001);
        assert!(matches!(
            parse_tpm_handle("not-a-handle"),
            Err(MasterKeyError::Config {
                field: "NEUTRINO_TPM_KEY_HANDLE",
                ..
            })
        ));
    }

    #[test]
    fn tpm_from_env_missing_config_sad() {
        std::env::remove_var("NEUTRINO_TPM_TCTI");
        std::env::remove_var("NEUTRINO_TPM_KEY_HANDLE");
        std::env::remove_var("NEUTRINO_MASTER_KEY_WRAPPED");
        let err = match TpmKeySource::from_env() {
            Ok(_) => panic!("expected config error"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            MasterKeyError::Config {
                source_kind: "tpm",
                ..
            }
        ));
    }
}
