//! Optional hardware-backed master key sources (stubs until a concrete integration lands).

#[cfg(feature = "hsm-pkcs11")]
pub mod pkcs11 {
    //! PKCS#11 token integration (stub).

    /// Placeholder for a future PKCS#11 hardware token `KeySource`.
    #[derive(Debug, Default)]
    pub struct Pkcs11KeySourceStub;
}

#[cfg(feature = "hsm-tpm")]
pub mod tpm {
    //! TPM 2.0 integration (stub).

    /// Placeholder for a future TPM 2.0-backed `KeySource`.
    #[derive(Debug, Default)]
    pub struct TpmKeySourceStub;
}
