//! XChaCha20-Poly1305 sealing with Argon2id-derived subkeys from `NEUTRINO_MASTER_KEY`.

use argon2::Argon2;
use argon2::Params;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::error::{NeutrinoError, NeutrinoResult};

const ARGON_M_COST: u32 = 19456;
const ARGON_T_COST: u32 = 2;
const ARGON_P_COST: u32 = 1;

/// Derive a 32-byte key for a specific secret version using master key + salt.
///
/// # Errors
///
/// Returns [`NeutrinoError::Crypto`] when Argon2 params or hashing fail.
pub fn derive_data_key(master: &[u8], salt: &[u8]) -> NeutrinoResult<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(32)).map_err(|e| {
        NeutrinoError::crypto("derive_data_key", anyhow::anyhow!("argon2 params: {e}"))
    })?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(master, salt, &mut *out)
        .map_err(|e| NeutrinoError::crypto("derive_data_key", anyhow::anyhow!("argon2id: {e}")))?;
    Ok(out)
}

/// Seal plaintext; returns (nonce 24 bytes, ciphertext).
///
/// # Errors
///
/// Returns [`NeutrinoError::Crypto`] on key derivation or encrypt failure.
pub fn seal(master: &[u8], salt: &[u8], plaintext: &[u8]) -> NeutrinoResult<(Vec<u8>, Vec<u8>)> {
    let key = derive_data_key(master, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|e| NeutrinoError::crypto("seal", anyhow::anyhow!("chacha key: {e}")))?;
    let mut nonce = [0u8; 24];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let nonce = XNonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| NeutrinoError::crypto("seal", anyhow::anyhow!("encrypt: {e}")))?;
    Ok((nonce.to_vec(), ct))
}

/// Reverse of [`seal`]: derive the same key from `master`/`salt` and decrypt
/// `ciphertext` using the given 24-byte XChaCha20-Poly1305 `nonce`.
///
/// # Errors
///
/// Returns [`NeutrinoError::Crypto`] on invalid nonce length, key derivation, or decrypt failure.
pub fn unseal(
    master: &[u8],
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> NeutrinoResult<Zeroizing<Vec<u8>>> {
    if nonce.len() != 24 {
        return Err(NeutrinoError::crypto(
            "unseal",
            anyhow::anyhow!("invalid xchacha nonce length"),
        ));
    }
    let key = derive_data_key(master, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|e| NeutrinoError::crypto("unseal", anyhow::anyhow!("chacha key: {e}")))?;
    let nonce = XNonce::from_slice(nonce);
    let pt = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| NeutrinoError::crypto("unseal", anyhow::anyhow!("decrypt: {e}")))?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let master = b"test-master-key-material!!";
        let salt = b"sixteen-byte-salt";
        let (nonce, ct) = seal(master, salt, b"secret").expect("seal");
        assert_eq!(nonce.len(), 24);
        let pt = unseal(master, salt, &nonce, &ct).expect("unseal");
        assert_eq!(&*pt, b"secret");
    }

    #[test]
    fn unseal_rejects_bad_nonce_len() {
        let err = unseal(
            b"master-key-material!!!!!",
            b"sixteen-byte-salt",
            &[0u8; 8],
            b"x",
        );
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("unseal") || msg.contains("nonce"));
    }
}
