//! Master key material resolution (`NEUTRINO_MASTER_KEY` and optional KMS/HSM unwrap).
//!
//! Default source is process env. With `kms-aws` / `kms-gcp` / `kms-vault-transit` /
//! `hsm-pkcs11` / `hsm-tpm`, set `NEUTRINO_KEY_SOURCE` to unwrap a wrapped master key
//! via the matching provider. Customer secrets stay in Valence; KMS/HSM only protect
//! the process master key.

use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine;
use zeroize::Zeroizing;

fn allow_weak_master_key() -> bool {
    std::env::var("NEUTRINO_ALLOW_WEAK_MASTER_KEY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Failure resolving master key material.
///
/// Distinct variants keep configuration and provider mistakes inspectable at the
/// library boundary before they collapse into vault/`anyhow` errors. Messages never
/// include key bytes, wrapped blobs, or cloud tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterKeyError {
    /// `NEUTRINO_MASTER_KEY` is unset.
    NotSet,
    /// `NEUTRINO_MASTER_KEY` is present but empty/whitespace.
    Empty,
    /// Hex decode of a 64-character candidate failed.
    InvalidHex,
    /// Non-hex UTF-8 key without `NEUTRINO_ALLOW_WEAK_MASTER_KEY=1`.
    WeakKeyRejected,
    /// Missing or invalid key-source configuration (selector, wrapped blob, key id).
    Config {
        /// Selected source kind (`env`, `aws-kms`, …).
        source_kind: &'static str,
        /// Missing or invalid field name (safe to log).
        field: &'static str,
    },
    /// KMS / Vault / HSM provider returned an application-level failure.
    Provider {
        /// Provider label (`aws-kms`, `gcp-kms`, `vault-transit`, `pkcs11`, `tpm`).
        provider: &'static str,
        /// Operation label (`Decrypt`).
        operation: &'static str,
    },
    /// Network / timeout / transport / device failure talking to the provider.
    Unavailable {
        /// Provider label.
        provider: &'static str,
    },
    /// `NEUTRINO_KEY_SOURCE` selected a provider whose Cargo feature is not enabled.
    FeatureDisabled {
        /// Selected source kind.
        source_kind: &'static str,
    },
}

impl fmt::Display for MasterKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSet => write!(f, "NEUTRINO_MASTER_KEY is not set"),
            Self::Empty => write!(f, "NEUTRINO_MASTER_KEY is empty"),
            Self::InvalidHex => write!(f, "NEUTRINO_MASTER_KEY hex decode failed"),
            Self::WeakKeyRejected => write!(
                f,
                "NEUTRINO_MASTER_KEY must be 64 hex characters (256-bit); \
                 set NEUTRINO_ALLOW_WEAK_MASTER_KEY=1 only for non-production UTF-8 keys"
            ),
            Self::Config { source_kind, field } => write!(
                f,
                "master key config invalid for source {source_kind}: {field}"
            ),
            Self::Provider {
                provider,
                operation,
            } => write!(f, "master key {operation} failed via {provider}"),
            Self::Unavailable { provider } => {
                write!(f, "master key provider {provider} unavailable")
            }
            Self::FeatureDisabled { source_kind } => write!(
                f,
                "NEUTRINO_KEY_SOURCE={source_kind} requires the matching Cargo feature"
            ),
        }
    }
}

impl std::error::Error for MasterKeyError {}

/// HSM backend label (safe to persist / log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmBackend {
    /// PKCS#11 token.
    Pkcs11,
    /// TPM 2.0.
    Tpm,
}

impl HsmBackend {
    /// Stable label for meta / telemetry (`pkcs11` or `tpm`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pkcs11 => "pkcs11",
            Self::Tpm => "tpm",
        }
    }
}

/// Where the resolved master key came from (for meta / telemetry; never holds key bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterKeyProvenance {
    /// Plaintext master key from `NEUTRINO_MASTER_KEY`.
    Env,
    /// Unwrapped via KMS / Vault Transit; `key_id` is an opaque provider key name/ARN.
    Kms {
        /// Opaque KMS / Transit key identifier (safe to persist).
        key_id: String,
    },
    /// Unwrapped via PKCS#11 or TPM; `key_id` is an opaque label or handle string.
    Hsm {
        /// Which HSM backend performed the unwrap.
        backend: HsmBackend,
        /// Opaque key label / handle (safe to persist).
        key_id: String,
    },
}

impl MasterKeyProvenance {
    /// Valence `NeutrinoMasterKeyMeta.source` enum value (`env`, `kms`, or `hsm`).
    #[must_use]
    pub const fn source_label(&self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Kms { .. } => "kms",
            Self::Hsm { .. } => "hsm",
        }
    }

    /// Opaque key id when provenance is KMS or HSM; empty for env.
    #[must_use]
    pub const fn key_id(&self) -> &str {
        match self {
            Self::Env => "",
            Self::Kms { key_id } | Self::Hsm { key_id, .. } => key_id.as_str(),
        }
    }
}

/// Master key bytes plus provenance from [`resolve_master_key`].
#[derive(Debug, Clone)]
pub struct ResolvedMasterKey {
    bytes: Zeroizing<Vec<u8>>,
    provenance: MasterKeyProvenance,
}

impl ResolvedMasterKey {
    /// Build a resolved key (crate and tests).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Zeroizing::new is not const
    pub fn new(bytes: Zeroizing<Vec<u8>>, provenance: MasterKeyProvenance) -> Self {
        Self { bytes, provenance }
    }

    /// Master key byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the key is empty (should not occur for a successful resolve).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow key bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume into zeroizing key bytes.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }

    /// Provenance for meta / telemetry.
    #[must_use]
    pub const fn provenance(&self) -> &MasterKeyProvenance {
        &self.provenance
    }
}

impl AsRef<[u8]> for ResolvedMasterKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Pluggable master-key material source.
#[async_trait]
pub trait KeySource: Send + Sync {
    /// Resolve master key bytes (and provenance).
    async fn resolve(&self) -> Result<ResolvedMasterKey, MasterKeyError>;
}

/// Injectable decrypt seam for KMS/HSM unit tests (ciphertext → plaintext master key bytes).
#[async_trait]
pub trait WrappedKeyDecryptor: Send + Sync {
    /// Decrypt wrapped master-key ciphertext.
    async fn decrypt(
        &self,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MasterKeyError>;
}

/// Env-backed [`KeySource`] (`NEUTRINO_MASTER_KEY`).
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvKeySource;

impl EnvKeySource {
    /// Parse `NEUTRINO_MASTER_KEY` synchronously (same rules as [`master_key_from_env`]).
    pub fn resolve_sync(&self) -> Result<ResolvedMasterKey, MasterKeyError> {
        let bytes = master_key_from_env()?;
        Ok(ResolvedMasterKey::new(bytes, MasterKeyProvenance::Env))
    }
}

#[async_trait]
impl KeySource for EnvKeySource {
    async fn resolve(&self) -> Result<ResolvedMasterKey, MasterKeyError> {
        self.resolve_sync()
    }
}

/// Read master key bytes from the environment.
///
/// Production requires a 64-character hex string (256-bit). Arbitrary UTF-8 keys
/// are rejected unless `NEUTRINO_ALLOW_WEAK_MASTER_KEY=1` (NU-10; non-production
/// escape hatch only).
///
/// Prefer [`resolve_master_key`] when the process may use a KMS-backed source.
///
/// # Errors
///
/// Returns [`MasterKeyError`] when the env var is missing, empty, not valid hex,
/// or a weak UTF-8 key without the escape hatch.
pub fn master_key_from_env() -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
    let raw = std::env::var("NEUTRINO_MASTER_KEY").map_err(|_| MasterKeyError::NotSet)?;
    let t = raw.trim();
    if t.is_empty() {
        return Err(MasterKeyError::Empty);
    }
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = vec![0u8; 32];
        for (i, chunk) in t.as_bytes().chunks(2).enumerate() {
            if chunk.len() != 2 {
                return Err(MasterKeyError::InvalidHex);
            }
            let s = std::str::from_utf8(chunk).map_err(|_| MasterKeyError::InvalidHex)?;
            out[i] = u8::from_str_radix(s, 16).map_err(|_| MasterKeyError::InvalidHex)?;
        }
        return Ok(Zeroizing::new(out));
    }
    if !allow_weak_master_key() {
        return Err(MasterKeyError::WeakKeyRejected);
    }
    Ok(Zeroizing::new(t.as_bytes().to_vec()))
}

/// `NEUTRINO_KEY_SOURCE` selector values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySourceKind {
    /// `env` (default).
    Env,
    /// `aws-kms` (requires `kms-aws`).
    AwsKms,
    /// `gcp-kms` (requires `kms-gcp`).
    GcpKms,
    /// `vault-transit` (requires `kms-vault-transit`).
    VaultTransit,
    /// `pkcs11` (requires `hsm-pkcs11`).
    Pkcs11,
    /// `tpm` (requires `hsm-tpm`).
    Tpm,
}

impl KeySourceKind {
    /// Parse selector string (case-insensitive). Empty / unset → [`Self::Env`].
    ///
    /// # Errors
    ///
    /// [`MasterKeyError::Config`] when the value is unrecognized.
    pub fn parse(raw: &str) -> Result<Self, MasterKeyError> {
        let t = raw.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("env") {
            return Ok(Self::Env);
        }
        if t.eq_ignore_ascii_case("aws-kms") {
            return Ok(Self::AwsKms);
        }
        if t.eq_ignore_ascii_case("gcp-kms") {
            return Ok(Self::GcpKms);
        }
        if t.eq_ignore_ascii_case("vault-transit") {
            return Ok(Self::VaultTransit);
        }
        if t.eq_ignore_ascii_case("pkcs11") {
            return Ok(Self::Pkcs11);
        }
        if t.eq_ignore_ascii_case("tpm") {
            return Ok(Self::Tpm);
        }
        Err(MasterKeyError::Config {
            source_kind: "unknown",
            field: "NEUTRINO_KEY_SOURCE",
        })
    }

    /// Stable label for telemetry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::AwsKms => "aws-kms",
            Self::GcpKms => "gcp-kms",
            Self::VaultTransit => "vault-transit",
            Self::Pkcs11 => "pkcs11",
            Self::Tpm => "tpm",
        }
    }
}

fn key_source_kind_from_env() -> Result<KeySourceKind, MasterKeyError> {
    match std::env::var("NEUTRINO_KEY_SOURCE") {
        Ok(v) => KeySourceKind::parse(&v),
        Err(_) => Ok(KeySourceKind::Env),
    }
}

static RESOLVED_CACHE: Mutex<Option<ResolvedMasterKey>> = Mutex::new(None);

/// Clear the process-local master-key cache (tests / rare rotate-of-MEK).
pub fn clear_master_key_cache() {
    if let Ok(mut guard) = RESOLVED_CACHE.lock() {
        *guard = None;
    }
}

fn cache_get() -> Option<ResolvedMasterKey> {
    RESOLVED_CACHE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(Clone::clone))
}

fn cache_set(resolved: ResolvedMasterKey) -> ResolvedMasterKey {
    if let Ok(mut guard) = RESOLVED_CACHE.lock() {
        *guard = Some(resolved.clone());
    }
    resolved
}

fn log_resolve(source: &str, outcome: &str) {
    log::info!(target: "neutrino.master_key.resolve", "source={source} outcome={outcome}");
}

/// Resolve the process master key using `NEUTRINO_KEY_SOURCE` (default `env`).
///
/// Successful results are cached in-process for the lifetime of the process (or until
/// [`clear_master_key_cache`]). KMS/HSM paths unwrap `NEUTRINO_MASTER_KEY_WRAPPED` via the
/// selected provider; see crate docs for env vars.
///
/// # Errors
///
/// Returns [`MasterKeyError`] for missing config, disabled features, or provider failure.
pub async fn resolve_master_key() -> Result<ResolvedMasterKey, MasterKeyError> {
    if let Some(cached) = cache_get() {
        return Ok(cached);
    }

    let kind = key_source_kind_from_env()?;
    let result = resolve_master_key_uncached(kind).await;
    match &result {
        Ok(_) => log_resolve(kind.as_str(), "ok"),
        Err(_) => log_resolve(kind.as_str(), "err"),
    }
    let resolved = result?;
    Ok(cache_set(resolved))
}

async fn resolve_master_key_uncached(
    kind: KeySourceKind,
) -> Result<ResolvedMasterKey, MasterKeyError> {
    match kind {
        KeySourceKind::Env => EnvKeySource.resolve().await,
        KeySourceKind::AwsKms => {
            #[cfg(feature = "kms-aws")]
            {
                crate::kms_sources::aws::AwsKmsKeySource::from_env()?
                    .resolve()
                    .await
            }
            #[cfg(not(feature = "kms-aws"))]
            {
                Err(MasterKeyError::FeatureDisabled {
                    source_kind: "aws-kms",
                })
            }
        }
        KeySourceKind::GcpKms => {
            #[cfg(feature = "kms-gcp")]
            {
                crate::kms_sources::gcp::GcpKmsKeySource::from_env()?
                    .resolve()
                    .await
            }
            #[cfg(not(feature = "kms-gcp"))]
            {
                Err(MasterKeyError::FeatureDisabled {
                    source_kind: "gcp-kms",
                })
            }
        }
        KeySourceKind::VaultTransit => {
            #[cfg(feature = "kms-vault-transit")]
            {
                crate::kms_sources::vault_transit::VaultTransitKeySource::from_env()?
                    .resolve()
                    .await
            }
            #[cfg(not(feature = "kms-vault-transit"))]
            {
                Err(MasterKeyError::FeatureDisabled {
                    source_kind: "vault-transit",
                })
            }
        }
        KeySourceKind::Pkcs11 => {
            #[cfg(feature = "hsm-pkcs11")]
            {
                crate::hsm_sources::pkcs11::Pkcs11KeySource::from_env()?
                    .resolve()
                    .await
            }
            #[cfg(not(feature = "hsm-pkcs11"))]
            {
                Err(MasterKeyError::FeatureDisabled {
                    source_kind: "pkcs11",
                })
            }
        }
        KeySourceKind::Tpm => {
            #[cfg(feature = "hsm-tpm")]
            {
                crate::hsm_sources::tpm::TpmKeySource::from_env()?
                    .resolve()
                    .await
            }
            #[cfg(not(feature = "hsm-tpm"))]
            {
                Err(MasterKeyError::FeatureDisabled { source_kind: "tpm" })
            }
        }
    }
}

/// Decode `NEUTRINO_MASTER_KEY_WRAPPED` as standard base64 (KMS/HSM binary ciphertext).
///
/// # Errors
///
/// [`MasterKeyError::Config`] when unset, empty, or not valid base64.
pub fn wrapped_master_key_from_env() -> Result<Vec<u8>, MasterKeyError> {
    wrapped_master_key_from_env_kind("kms")
}

/// Decode `NEUTRINO_MASTER_KEY_WRAPPED` as standard base64 with a source-kind label for errors.
///
/// # Errors
///
/// [`MasterKeyError::Config`] when unset, empty, or not valid base64.
pub fn wrapped_master_key_from_env_kind(
    source_kind: &'static str,
) -> Result<Vec<u8>, MasterKeyError> {
    let raw = std::env::var("NEUTRINO_MASTER_KEY_WRAPPED").map_err(|_| MasterKeyError::Config {
        source_kind,
        field: "NEUTRINO_MASTER_KEY_WRAPPED",
    })?;
    let t = raw.trim();
    if t.is_empty() {
        return Err(MasterKeyError::Config {
            source_kind,
            field: "NEUTRINO_MASTER_KEY_WRAPPED",
        });
    }
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|_| MasterKeyError::Config {
            source_kind,
            field: "NEUTRINO_MASTER_KEY_WRAPPED",
        })
}

/// Raw `NEUTRINO_MASTER_KEY_WRAPPED` string (Vault Transit ciphertext `vault:v1:…`).
///
/// # Errors
///
/// [`MasterKeyError::Config`] when unset or empty.
pub fn wrapped_master_key_string_from_env() -> Result<String, MasterKeyError> {
    let raw = std::env::var("NEUTRINO_MASTER_KEY_WRAPPED").map_err(|_| MasterKeyError::Config {
        source_kind: "kms",
        field: "NEUTRINO_MASTER_KEY_WRAPPED",
    })?;
    let t = raw.trim();
    if t.is_empty() {
        return Err(MasterKeyError::Config {
            source_kind: "kms",
            field: "NEUTRINO_MASTER_KEY_WRAPPED",
        });
    }
    Ok(t.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        clear_master_key_cache, master_key_from_env, resolve_master_key, KeySourceKind,
        MasterKeyError, MasterKeyProvenance,
    };
    use std::sync::Mutex;

    static MASTER_KEY_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_master_key_env<R>(
        value: Option<&str>,
        allow_weak: Option<&str>,
        key_source: Option<&str>,
        f: impl FnOnce() -> R,
    ) -> R {
        let _g = MASTER_KEY_ENV_LOCK.lock().unwrap();
        clear_master_key_cache();
        let prev = std::env::var("NEUTRINO_MASTER_KEY").ok();
        let prev_weak = std::env::var("NEUTRINO_ALLOW_WEAK_MASTER_KEY").ok();
        let prev_source = std::env::var("NEUTRINO_KEY_SOURCE").ok();
        match value {
            Some(v) => std::env::set_var("NEUTRINO_MASTER_KEY", v),
            None => std::env::remove_var("NEUTRINO_MASTER_KEY"),
        }
        match allow_weak {
            Some(v) => std::env::set_var("NEUTRINO_ALLOW_WEAK_MASTER_KEY", v),
            None => std::env::remove_var("NEUTRINO_ALLOW_WEAK_MASTER_KEY"),
        }
        match key_source {
            Some(v) => std::env::set_var("NEUTRINO_KEY_SOURCE", v),
            None => std::env::remove_var("NEUTRINO_KEY_SOURCE"),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var("NEUTRINO_MASTER_KEY", v),
            None => std::env::remove_var("NEUTRINO_MASTER_KEY"),
        }
        match prev_weak {
            Some(v) => std::env::set_var("NEUTRINO_ALLOW_WEAK_MASTER_KEY", v),
            None => std::env::remove_var("NEUTRINO_ALLOW_WEAK_MASTER_KEY"),
        }
        match prev_source {
            Some(v) => std::env::set_var("NEUTRINO_KEY_SOURCE", v),
            None => std::env::remove_var("NEUTRINO_KEY_SOURCE"),
        }
        clear_master_key_cache();
        out
    }

    #[test]
    fn master_key_hex64_happy_path() {
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        with_master_key_env(Some(hex64), None, None, || {
            let key = master_key_from_env().expect("hex key");
            assert_eq!(key.len(), 32);
        });
    }

    #[test]
    fn master_key_utf8_rejected_without_escape_sad() {
        with_master_key_env(Some("dev-utf8-master"), None, None, || {
            let err = master_key_from_env().expect_err("weak key");
            assert_eq!(err, MasterKeyError::WeakKeyRejected);
            assert!(err.to_string().contains("64 hex"));
        });
    }

    #[test]
    fn master_key_utf8_allowed_with_escape_happy_path() {
        with_master_key_env(Some("dev-utf8-master"), Some("1"), None, || {
            let key = master_key_from_env().expect("utf8 key");
            assert_eq!(&*key, b"dev-utf8-master");
        });
    }

    #[test]
    fn master_key_empty_or_missing_sad() {
        with_master_key_env(Some(""), None, None, || {
            assert_eq!(master_key_from_env(), Err(MasterKeyError::Empty));
        });
        with_master_key_env(None, None, None, || {
            assert_eq!(master_key_from_env(), Err(MasterKeyError::NotSet));
        });
    }

    #[test]
    fn master_key_error_display_and_source() {
        let err = MasterKeyError::NotSet;
        assert_eq!(err.to_string(), "NEUTRINO_MASTER_KEY is not set");
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(
            MasterKeyError::InvalidHex.to_string(),
            "NEUTRINO_MASTER_KEY hex decode failed"
        );
        let config = MasterKeyError::Config {
            source_kind: "aws-kms",
            field: "NEUTRINO_AWS_KMS_KEY_ID",
        };
        assert!(config.to_string().contains("NEUTRINO_AWS_KMS_KEY_ID"));
        assert!(!config.to_string().contains("arn:"));
    }

    #[test]
    fn key_source_kind_parse_happy_and_sad() {
        assert_eq!(KeySourceKind::parse("").unwrap(), KeySourceKind::Env);
        assert_eq!(KeySourceKind::parse("env").unwrap(), KeySourceKind::Env);
        assert_eq!(
            KeySourceKind::parse("aws-kms").unwrap(),
            KeySourceKind::AwsKms
        );
        assert_eq!(
            KeySourceKind::parse("pkcs11").unwrap(),
            KeySourceKind::Pkcs11
        );
        assert_eq!(KeySourceKind::parse("tpm").unwrap(), KeySourceKind::Tpm);
        let err = KeySourceKind::parse("bogus").unwrap_err();
        assert!(matches!(
            err,
            MasterKeyError::Config {
                field: "NEUTRINO_KEY_SOURCE",
                ..
            }
        ));
    }

    #[test]
    fn resolve_hsm_without_feature_sad() {
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        with_master_key_env(Some(hex64), None, Some("pkcs11"), || {
            let err = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt")
                .block_on(resolve_master_key())
                .expect_err("feature or config");
            #[cfg(not(feature = "hsm-pkcs11"))]
            {
                assert_eq!(
                    err,
                    MasterKeyError::FeatureDisabled {
                        source_kind: "pkcs11",
                    }
                );
            }
            #[cfg(feature = "hsm-pkcs11")]
            {
                assert!(matches!(err, MasterKeyError::Config { .. }));
            }
        });
        with_master_key_env(Some(hex64), None, Some("tpm"), || {
            let err = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt")
                .block_on(resolve_master_key())
                .expect_err("feature or config");
            #[cfg(not(feature = "hsm-tpm"))]
            {
                assert_eq!(err, MasterKeyError::FeatureDisabled { source_kind: "tpm" });
            }
            #[cfg(feature = "hsm-tpm")]
            {
                assert!(matches!(err, MasterKeyError::Config { .. }));
            }
        });
    }

    #[test]
    fn resolve_master_key_defaults_to_env_happy() {
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        with_master_key_env(Some(hex64), None, None, || {
            let key = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt")
                .block_on(resolve_master_key())
                .expect("resolve");
            assert_eq!(key.len(), 32);
            assert_eq!(key.provenance(), &MasterKeyProvenance::Env);
        });
    }

    #[test]
    fn resolve_master_key_unknown_source_sad() {
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        with_master_key_env(Some(hex64), None, Some("nope"), || {
            let err = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt")
                .block_on(resolve_master_key())
                .expect_err("bad source");
            assert!(matches!(
                err,
                MasterKeyError::Config {
                    field: "NEUTRINO_KEY_SOURCE",
                    ..
                }
            ));
        });
    }

    #[test]
    fn resolve_kms_without_feature_sad() {
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        with_master_key_env(Some(hex64), None, Some("aws-kms"), || {
            let err = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt")
                .block_on(resolve_master_key())
                .expect_err("feature or config");
            #[cfg(not(feature = "kms-aws"))]
            {
                assert_eq!(
                    err,
                    MasterKeyError::FeatureDisabled {
                        source_kind: "aws-kms",
                    }
                );
            }
            #[cfg(feature = "kms-aws")]
            {
                assert!(matches!(err, MasterKeyError::Config { .. }));
            }
        });
    }
}
