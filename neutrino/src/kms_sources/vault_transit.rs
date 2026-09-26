//! HashiCorp Vault Transit unwrap for the Neutrino process master key.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use zeroize::Zeroizing;

use crate::key_source::{
    wrapped_master_key_string_from_env, KeySource, MasterKeyError, ResolvedMasterKey,
};

use super::{log_provider_err, require_env, resolved_kms, WrappedKeyDecryptor};

const PROVIDER: &str = "vault-transit";

/// Vault Transit-backed [`KeySource`].
pub struct VaultTransitKeySource {
    key_name: String,
    /// Transit ciphertext string (`vault:v1:…`), held as UTF-8 bytes for the trait.
    wrapped_cipher: String,
    client: Arc<dyn WrappedKeyDecryptor>,
}

impl VaultTransitKeySource {
    /// Build from env: `NEUTRINO_MASTER_KEY_WRAPPED` (Transit ciphertext),
    /// `NEUTRINO_VAULT_ADDR`, `NEUTRINO_VAULT_TOKEN`, `NEUTRINO_VAULT_TRANSIT_KEY`.
    ///
    /// # Errors
    ///
    /// [`MasterKeyError::Config`] when required env vars are missing/invalid.
    pub fn from_env() -> Result<Self, MasterKeyError> {
        let key_name = require_env("NEUTRINO_VAULT_TRANSIT_KEY", PROVIDER)?;
        let wrapped_cipher = wrapped_master_key_string_from_env()?;
        let addr = require_env("NEUTRINO_VAULT_ADDR", PROVIDER)?;
        let token = require_env("NEUTRINO_VAULT_TOKEN", PROVIDER)?;
        Ok(Self::with_client(
            key_name,
            wrapped_cipher,
            Arc::new(VaultTransitHttpClient::new(addr, token)),
        ))
    }

    /// Construct with an injectable decrypt client (tests).
    #[must_use]
    pub fn with_client(
        key_name: impl Into<String>,
        wrapped_cipher: impl Into<String>,
        client: Arc<dyn WrappedKeyDecryptor>,
    ) -> Self {
        Self {
            key_name: key_name.into(),
            wrapped_cipher: wrapped_cipher.into(),
            client,
        }
    }
}

#[async_trait]
impl KeySource for VaultTransitKeySource {
    async fn resolve(&self) -> Result<ResolvedMasterKey, MasterKeyError> {
        let plaintext = self
            .client
            .decrypt(self.wrapped_cipher.as_bytes(), &self.key_name)
            .await?;
        Ok(resolved_kms(plaintext, self.key_name.clone()))
    }
}

/// Vault Transit HTTP decrypt client.
pub struct VaultTransitHttpClient {
    addr: String,
    token: String,
    http: reqwest::Client,
}

impl VaultTransitHttpClient {
    /// Create a client for `addr` (e.g. `https://vault.example:8200`) with a token.
    #[must_use]
    pub fn new(addr: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            addr: addr.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl WrappedKeyDecryptor for VaultTransitHttpClient {
    async fn decrypt(
        &self,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
        let cipher_str = std::str::from_utf8(ciphertext).map_err(|_| MasterKeyError::Config {
            source_kind: PROVIDER,
            field: "NEUTRINO_MASTER_KEY_WRAPPED",
        })?;
        let url = format!("{}/v1/transit/decrypt/{}", self.addr, key_id);
        let body = serde_json::json!({ "ciphertext": cipher_str });
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()
            .await
            .map_err(|_| {
                log_provider_err(PROVIDER, "Decrypt", "unavailable");
                MasterKeyError::Unavailable { provider: PROVIDER }
            })?;
        if !resp.status().is_success() {
            log_provider_err(PROVIDER, "Decrypt", "provider");
            return Err(MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            });
        }
        let json: serde_json::Value = resp.json().await.map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "provider");
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        })?;
        let b64 = json
            .pointer("/data/plaintext")
            .and_then(|v| v.as_str())
            .ok_or(MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            })?;
        // Vault Transit returns base64 of the plaintext.
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            })?;
        Ok(Zeroizing::new(bytes))
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
    async fn vault_transit_mock_decrypt_happy() {
        let plaintext = vec![3u8; 32];
        let mock = Arc::new(MockOk {
            plaintext: plaintext.clone(),
            calls: AtomicUsize::new(0),
        });
        let src = VaultTransitKeySource::with_client("neutrino", "vault:v1:deadbeef", mock.clone());
        let resolved = src.resolve().await.expect("resolve");
        assert_eq!(resolved.as_slice(), plaintext.as_slice());
        assert_eq!(resolved.provenance().key_id(), "neutrino");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn vault_transit_mock_decrypt_sad() {
        let src = VaultTransitKeySource::with_client("neutrino", "vault:v1:x", Arc::new(MockFail));
        let err = src.resolve().await.expect_err("denied");
        assert_eq!(
            err,
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        );
        assert!(!err.to_string().contains("vault:v1"));
        assert!(!err.to_string().contains("Token"));
    }
}
