//! PKCS#11-backed master key unwrap (RSA-OAEP decrypt of wrapped MEK).

use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::key_source::{
    wrapped_master_key_from_env_kind, HsmBackend, KeySource, MasterKeyError, ResolvedMasterKey,
    WrappedKeyDecryptor,
};

use super::{log_provider_err, require_env, resolved_hsm};

const PROVIDER: &str = "pkcs11";

/// PKCS#11-backed [`KeySource`].
pub struct Pkcs11KeySource {
    key_label: String,
    wrapped: Vec<u8>,
    client: Arc<dyn WrappedKeyDecryptor>,
}

impl std::fmt::Debug for Pkcs11KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11KeySource")
            .field("key_label", &self.key_label)
            .field("wrapped_len", &self.wrapped.len())
            .finish_non_exhaustive()
    }
}

impl Pkcs11KeySource {
    /// Build from env: module, PIN, key label, optional slot, wrapped blob.
    ///
    /// Required: `NEUTRINO_MASTER_KEY_WRAPPED`, `NEUTRINO_PKCS11_MODULE`,
    /// `NEUTRINO_PKCS11_PIN`, `NEUTRINO_PKCS11_KEY_LABEL`.
    /// Optional: `NEUTRINO_PKCS11_SLOT` (decimal slot id). SoftHSM + OpenSSL wraps
    /// often need `NEUTRINO_PKCS11_OAEP_HASH=sha1`; production HSMs keep SHA-256.
    ///
    /// # Errors
    ///
    /// [`MasterKeyError::Config`] when required env vars are missing/invalid.
    pub fn from_env() -> Result<Self, MasterKeyError> {
        let module = require_env("NEUTRINO_PKCS11_MODULE", PROVIDER)?;
        let pin = require_env("NEUTRINO_PKCS11_PIN", PROVIDER)?;
        let key_label = require_env("NEUTRINO_PKCS11_KEY_LABEL", PROVIDER)?;
        let slot = match std::env::var("NEUTRINO_PKCS11_SLOT") {
            Ok(raw) => {
                let t = raw.trim();
                if t.is_empty() {
                    None
                } else {
                    Some(t.parse::<u64>().map_err(|_| MasterKeyError::Config {
                        source_kind: PROVIDER,
                        field: "NEUTRINO_PKCS11_SLOT",
                    })?)
                }
            }
            Err(_) => None,
        };
        let wrapped = wrapped_master_key_from_env_kind(PROVIDER)?;
        Ok(Self::with_client(
            key_label,
            wrapped,
            Arc::new(Pkcs11CryptokiDecryptClient::new(module, pin, slot)),
        ))
    }

    /// Construct with an injectable decrypt client (tests).
    #[must_use]
    pub fn with_client(
        key_label: impl Into<String>,
        wrapped: Vec<u8>,
        client: Arc<dyn WrappedKeyDecryptor>,
    ) -> Self {
        Self {
            key_label: key_label.into(),
            wrapped,
            client,
        }
    }
}

#[async_trait]
impl KeySource for Pkcs11KeySource {
    async fn resolve(&self) -> Result<ResolvedMasterKey, MasterKeyError> {
        let plaintext = self.client.decrypt(&self.wrapped, &self.key_label).await?;
        resolved_hsm(plaintext, HsmBackend::Pkcs11, self.key_label.clone())
    }
}

/// Live cryptoki decrypt client (RSA-OAEP; SHA-256 default, SHA-1 for SoftHSM/openssl wraps).
pub struct Pkcs11CryptokiDecryptClient {
    module_path: String,
    pin: Zeroizing<String>,
    slot: Option<u64>,
    /// `sha256` (default) or `sha1` (`NEUTRINO_PKCS11_OAEP_HASH`).
    oaep_hash: &'static str,
}

impl Pkcs11CryptokiDecryptClient {
    /// Create a client that loads the PKCS#11 module on first decrypt.
    #[must_use]
    pub fn new(module_path: impl Into<String>, pin: impl Into<String>, slot: Option<u64>) -> Self {
        Self {
            module_path: module_path.into(),
            pin: Zeroizing::new(pin.into()),
            slot,
            oaep_hash: oaep_hash_from_env(),
        }
    }

    fn decrypt_blocking(
        &self,
        ciphertext: &[u8],
        key_label: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
        use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
        use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
        use cryptoki::mechanism::{Mechanism, MechanismType};
        use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
        use cryptoki::session::UserType;
        use cryptoki::types::AuthPin;

        let pkcs11 = Pkcs11::new(&self.module_path).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "unavailable");
            MasterKeyError::Unavailable { provider: PROVIDER }
        })?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|_| {
                log_provider_err(PROVIDER, "Decrypt", "unavailable");
                MasterKeyError::Unavailable { provider: PROVIDER }
            })?;

        let slots = pkcs11.get_slots_with_token().map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "unavailable");
            MasterKeyError::Unavailable { provider: PROVIDER }
        })?;
        let slot = if let Some(want) = self.slot {
            slots.into_iter().find(|s| s.id() == want).ok_or_else(|| {
                log_provider_err(PROVIDER, "Decrypt", "unavailable");
                MasterKeyError::Unavailable { provider: PROVIDER }
            })?
        } else {
            slots.into_iter().next().ok_or_else(|| {
                log_provider_err(PROVIDER, "Decrypt", "unavailable");
                MasterKeyError::Unavailable { provider: PROVIDER }
            })?
        };

        let session = pkcs11.open_rw_session(slot).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "unavailable");
            MasterKeyError::Unavailable { provider: PROVIDER }
        })?;

        let pin = AuthPin::new(self.pin.as_str().into());
        session.login(UserType::User, Some(&pin)).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "provider");
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        })?;

        let template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ];
        let handles = session.find_objects(&template).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "provider");
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        })?;
        let key = handles.into_iter().next().ok_or_else(|| {
            log_provider_err(PROVIDER, "Decrypt", "provider");
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        })?;

        // Confirm the object is decrypt-capable when the attribute is readable.
        let _ = session.get_attributes(key, &[AttributeType::Decrypt]);

        let (hash_alg, mgf) = match self.oaep_hash {
            "sha1" => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
            _ => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
        };
        let oaep = PkcsOaepParams::new(hash_alg, mgf, PkcsOaepSource::empty());
        let mechanism = Mechanism::RsaPkcsOaep(oaep);
        let plaintext = session.decrypt(&mechanism, key, ciphertext).map_err(|_| {
            log_provider_err(PROVIDER, "Decrypt", "provider");
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        })?;
        Ok(Zeroizing::new(plaintext))
    }
}

fn oaep_hash_from_env() -> &'static str {
    match std::env::var("NEUTRINO_PKCS11_OAEP_HASH") {
        Ok(v) if v.trim().eq_ignore_ascii_case("sha1") => "sha1",
        _ => "sha256",
    }
}

#[async_trait]
impl WrappedKeyDecryptor for Pkcs11CryptokiDecryptClient {
    async fn decrypt(
        &self,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
        let ciphertext = ciphertext.to_vec();
        let key_id = key_id.to_string();
        let module_path = self.module_path.clone();
        let pin = self.pin.clone();
        let slot = self.slot;
        let oaep_hash = self.oaep_hash;
        tokio::task::spawn_blocking(move || {
            let client = Self {
                module_path,
                pin,
                slot,
                oaep_hash,
            };
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
    async fn pkcs11_mock_decrypt_happy() {
        let plaintext = vec![7u8; 32];
        let mock = Arc::new(MockOk {
            plaintext: plaintext.clone(),
            calls: AtomicUsize::new(0),
        });
        let src = Pkcs11KeySource::with_client("neutrino-mek", vec![1, 2, 3], mock.clone());
        let resolved = src.resolve().await.expect("resolve");
        assert_eq!(resolved.as_slice(), plaintext.as_slice());
        assert_eq!(resolved.provenance().key_id(), "neutrino-mek");
        assert_eq!(resolved.provenance().source_label(), "hsm");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pkcs11_mock_decrypt_sad() {
        let src = Pkcs11KeySource::with_client("neutrino-mek", vec![1], Arc::new(MockFail));
        let err = src.resolve().await.expect_err("denied");
        assert_eq!(
            err,
            MasterKeyError::Provider {
                provider: PROVIDER,
                operation: "Decrypt",
            }
        );
        assert!(!err.to_string().contains("neutrino-mek"));
        assert!(!err.to_string().contains("pin"));
    }

    #[tokio::test]
    async fn pkcs11_mock_wrong_len_sad() {
        let mock = Arc::new(MockOk {
            plaintext: vec![1u8; 16],
            calls: AtomicUsize::new(0),
        });
        let src = Pkcs11KeySource::with_client("neutrino-mek", vec![1], mock);
        let err = src.resolve().await.expect_err("len");
        assert!(matches!(
            err,
            MasterKeyError::Provider {
                provider: "pkcs11",
                operation: "Decrypt",
            }
        ));
    }

    #[test]
    fn pkcs11_from_env_missing_config_sad() {
        std::env::remove_var("NEUTRINO_PKCS11_MODULE");
        std::env::remove_var("NEUTRINO_PKCS11_PIN");
        std::env::remove_var("NEUTRINO_PKCS11_KEY_LABEL");
        std::env::remove_var("NEUTRINO_MASTER_KEY_WRAPPED");
        let err = match Pkcs11KeySource::from_env() {
            Ok(_) => panic!("expected config error"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            MasterKeyError::Config {
                source_kind: "pkcs11",
                ..
            }
        ));
        assert!(!err.to_string().contains("secret"));
    }
}
