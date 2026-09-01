//! Master key material resolution (`NEUTRINO_MASTER_KEY`).

use std::fmt;

use zeroize::Zeroizing;

fn allow_weak_master_key() -> bool {
    std::env::var("NEUTRINO_ALLOW_WEAK_MASTER_KEY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Failure resolving [`master_key_from_env`].
///
/// Distinct variants keep configuration mistakes inspectable at the library
/// boundary before they collapse into vault/`anyhow` errors.
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
        }
    }
}

impl std::error::Error for MasterKeyError {}

/// Read master key bytes from the environment.
///
/// Production requires a 64-character hex string (256-bit). Arbitrary UTF-8 keys
/// are rejected unless `NEUTRINO_ALLOW_WEAK_MASTER_KEY=1` (NU-10; non-production
/// escape hatch only).
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

#[cfg(test)]
mod tests {
    use super::{master_key_from_env, MasterKeyError};
    use std::sync::Mutex;

    static MASTER_KEY_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_master_key_env<R>(
        value: Option<&str>,
        allow_weak: Option<&str>,
        f: impl FnOnce() -> R,
    ) -> R {
        let _g = MASTER_KEY_ENV_LOCK.lock().unwrap();
        let prev = std::env::var("NEUTRINO_MASTER_KEY").ok();
        let prev_weak = std::env::var("NEUTRINO_ALLOW_WEAK_MASTER_KEY").ok();
        match value {
            Some(v) => std::env::set_var("NEUTRINO_MASTER_KEY", v),
            None => std::env::remove_var("NEUTRINO_MASTER_KEY"),
        }
        match allow_weak {
            Some(v) => std::env::set_var("NEUTRINO_ALLOW_WEAK_MASTER_KEY", v),
            None => std::env::remove_var("NEUTRINO_ALLOW_WEAK_MASTER_KEY"),
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
        out
    }

    #[test]
    fn master_key_hex64_happy_path() {
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        with_master_key_env(Some(hex64), None, || {
            let key = master_key_from_env().expect("hex key");
            assert_eq!(key.len(), 32);
        });
    }

    #[test]
    fn master_key_utf8_rejected_without_escape_sad() {
        with_master_key_env(Some("dev-utf8-master"), None, || {
            let err = master_key_from_env().expect_err("weak key");
            assert_eq!(err, MasterKeyError::WeakKeyRejected);
            assert!(err.to_string().contains("64 hex"));
        });
    }

    #[test]
    fn master_key_utf8_allowed_with_escape_happy_path() {
        with_master_key_env(Some("dev-utf8-master"), Some("1"), || {
            let key = master_key_from_env().expect("utf8 key");
            assert_eq!(&*key, b"dev-utf8-master");
        });
    }

    #[test]
    fn master_key_empty_or_missing_sad() {
        with_master_key_env(Some(""), None, || {
            assert_eq!(master_key_from_env(), Err(MasterKeyError::Empty));
        });
        with_master_key_env(None, None, || {
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
    }
}
