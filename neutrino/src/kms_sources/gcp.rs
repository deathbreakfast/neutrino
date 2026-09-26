//! Google Cloud KMS envelope unwrap for the Neutrino process master key.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use zeroize::Zeroizing;

use crate::key_source::{
    wrapped_master_key_from_env, KeySource, MasterKeyError, ResolvedMasterKey,
};

use super::{log_provider_err, require_env, resolved_kms, WrappedKeyDecryptor};

const PROVIDER: &str = "gcp-kms";

/// GCP Cloud KMS-backed [`KeySource`].
pub struct GcpKmsKeySource {
    key_name: String,
    wrapped: Vec<u8>,
    client: Arc<dyn WrappedKeyDecryptor>,
}

impl GcpKmsKeySource {
    /// Build from env: `NEUTRINO_MASTER_KEY_WRAPPED`, `NEUTRINO_GCP_KMS_KEY_NAME`,
    /// and `NEUTRINO_GCP_ACCESS_TOKEN` (Bearer from ADC / workload identity / `gcloud`).
    ///
    /// # Errors
    ///
    /// [`MasterKeyError::Config`] when required env vars are missing/invalid.
    pub fn from_env() -> Result<Self, MasterKeyError> {
        let key_name = require_env("NEUTRINO_GCP_KMS_KEY_NAME", PROVIDER)?;
        let wrapped = wrapped_master_key_from_env()?;
        let token = require_env("NEUTRINO_GCP_ACCESS_TOKEN", PROVIDER)?;
        Ok(Self::with_client(
            key_name,
            wrapped,
            Arc::new(GcpRestDecryptClient::new(token)),
        ))
    }

    /// Construct with an injectable decrypt client (tests).
    #[must_use]
    pub fn with_client(
        key_name: impl Into<String>,
        wrapped: Vec<u8>,
        client: Arc<dyn WrappedKeyDecryptor>,
    ) -> Self {
        Self {
            key_name: key_name.into(),
            wrapped,
            client,
        }
    }
}

#[async_trait]
impl KeySource for GcpKmsKeySource {
    async fn resolve(&self) -> Result<ResolvedMasterKey, MasterKeyError> {
        let plaintext = self.client.decrypt(&self.wrapped, &self.key_name).await?;
        Ok(resolved_kms(plaintext, self.key_name.clone()))
    }
}

/// Cloud KMS REST `:decrypt` client using a Bearer access token.
pub struct GcpRestDecryptClient {
    token: String,
    http: reqwest::Client,
}

impl GcpRestDecryptClient {
    /// Create a REST client with the given Bearer token.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl WrappedKeyDecryptor for GcpRestDecryptClient {
    async fn decrypt(
        &self,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:decrypt",
            key_id.trim_start_matches('/')
        );
        let body = serde_json::json!({
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(ciphertext),
        });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
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
        let b64 =
            json.get("plaintext")
                .and_then(|v| v.as_str())
                .ok_or(MasterKeyError::Provider {
                    provider: PROVIDER,
                    operation: "Decrypt",
                })?;
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
            Err(MasterKeyError::Unavailable { provider: PROVIDER })
        }
    }

    #[tokio::test]
    async fn gcp_kms_mock_decrypt_happy() {
        let plaintext = vec![9u8; 32];
        let mock = Arc::new(MockOk {
            plaintext: plaintext.clone(),
            calls: AtomicUsize::new(0),
        });
        let src = GcpKmsKeySource::with_client(
            "projects/p/locations/g/keyRings/r/cryptoKeys/k",
            vec![4, 5],
            mock,
        );
        let resolved = src.resolve().await.expect("resolve");
        assert_eq!(resolved.as_slice(), plaintext.as_slice());
        assert!(resolved.provenance().key_id().contains("cryptoKeys"));
    }

    #[tokio::test]
    async fn gcp_kms_mock_decrypt_sad() {
        let src = GcpKmsKeySource::with_client("projects/p/key", vec![1], Arc::new(MockFail));
        let err = src.resolve().await.expect_err("unavailable");
        assert_eq!(err, MasterKeyError::Unavailable { provider: PROVIDER });
        assert!(!err.to_string().contains("Bearer"));
    }
}
