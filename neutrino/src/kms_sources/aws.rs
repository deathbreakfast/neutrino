//! AWS KMS envelope unwrap for the Neutrino process master key.

use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::key_source::{
    wrapped_master_key_from_env, KeySource, MasterKeyError, ResolvedMasterKey,
};

use super::{log_provider_err, require_env, resolved_kms, WrappedKeyDecryptor};

const PROVIDER: &str = "aws-kms";

/// AWS KMS-backed [`KeySource`].
pub struct AwsKmsKeySource {
    key_id: String,
    wrapped: Vec<u8>,
    client: Arc<dyn WrappedKeyDecryptor>,
}

impl AwsKmsKeySource {
    /// Build from env: `NEUTRINO_MASTER_KEY_WRAPPED`, `NEUTRINO_AWS_KMS_KEY_ID`.
    ///
    /// Uses the AWS default credential chain via [`AwsSdkDecryptClient`].
    ///
    /// # Errors
    ///
    /// [`MasterKeyError::Config`] when required env vars are missing/invalid.
    pub fn from_env() -> Result<Self, MasterKeyError> {
        let key_id = require_env("NEUTRINO_AWS_KMS_KEY_ID", PROVIDER)?;
        let wrapped = wrapped_master_key_from_env()?;
        Ok(Self::with_client(
            key_id,
            wrapped,
            Arc::new(AwsSdkDecryptClient::new()),
        ))
    }

    /// Construct with an injectable decrypt client (tests).
    #[must_use]
    pub fn with_client(
        key_id: impl Into<String>,
        wrapped: Vec<u8>,
        client: Arc<dyn WrappedKeyDecryptor>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            wrapped,
            client,
        }
    }
}

#[async_trait]
impl KeySource for AwsKmsKeySource {
    async fn resolve(&self) -> Result<ResolvedMasterKey, MasterKeyError> {
        let plaintext = self.client.decrypt(&self.wrapped, &self.key_id).await?;
        Ok(resolved_kms(plaintext, self.key_id.clone()))
    }
}

/// Live AWS SDK decrypt client (default credential chain).
pub struct AwsSdkDecryptClient {
    // Lazily built on first decrypt to keep `from_env` sync.
    inner: tokio::sync::OnceCell<aws_sdk_kms::Client>,
}

impl AwsSdkDecryptClient {
    /// Create a client that loads AWS config on first decrypt.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: tokio::sync::OnceCell::new(),
        }
    }

    async fn client(&self) -> &aws_sdk_kms::Client {
        self.inner
            .get_or_init(|| async {
                let conf = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                aws_sdk_kms::Client::new(&conf)
            })
            .await
    }
}

impl Default for AwsSdkDecryptClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WrappedKeyDecryptor for AwsSdkDecryptClient {
    async fn decrypt(
        &self,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
        let client = self.client().await;
        let out = client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
            .send()
            .await
            .map_err(|e| {
                let unavailable = matches!(
                    &e,
                    aws_sdk_kms::error::SdkError::TimeoutError(_)
                        | aws_sdk_kms::error::SdkError::DispatchFailure(_)
                        | aws_sdk_kms::error::SdkError::ResponseError(_)
                );
                let class = if unavailable {
                    "unavailable"
                } else {
                    "provider"
                };
                log_provider_err(PROVIDER, "Decrypt", class);
                if unavailable {
                    MasterKeyError::Unavailable { provider: PROVIDER }
                } else {
                    MasterKeyError::Provider {
                        provider: PROVIDER,
                        operation: "Decrypt",
                    }
                }
            })?;
        let blob = out.plaintext().ok_or(MasterKeyError::Provider {
            provider: PROVIDER,
            operation: "Decrypt",
        })?;
        Ok(Zeroizing::new(blob.as_ref().to_vec()))
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
    async fn aws_kms_mock_decrypt_happy() {
        let plaintext = vec![7u8; 32];
        let mock = Arc::new(MockOk {
            plaintext: plaintext.clone(),
            calls: AtomicUsize::new(0),
        });
        let src = AwsKmsKeySource::with_client("alias/neutrino", vec![1, 2, 3], mock.clone());
        let resolved = src.resolve().await.expect("resolve");
        assert_eq!(resolved.as_slice(), plaintext.as_slice());
        assert_eq!(resolved.provenance().key_id(), "alias/neutrino");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
        assert!(!resolved.provenance().source_label().contains("secret"));
    }

    #[tokio::test]
    async fn aws_kms_mock_decrypt_sad() {
        let src = AwsKmsKeySource::with_client("alias/neutrino", vec![1], Arc::new(MockFail));
        let err = src.resolve().await.expect_err("denied");
        assert_eq!(
            err,
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        );
        assert!(!err.to_string().contains("alias"));
    }
}
