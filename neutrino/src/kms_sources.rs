//! Optional KMS-backed master key sources (stubs until a concrete integration lands).
//!
//! Enable one of the Cargo features below when wiring a concrete [`crate::key_source`] integration.

#[cfg(feature = "kms-aws")]
pub mod aws {
    //! AWS KMS envelope (stub).

    /// Placeholder for a future AWS KMS-backed `KeySource`.
    #[derive(Debug, Default)]
    pub struct AwsKmsKeySourceStub;
}

#[cfg(feature = "kms-gcp")]
pub mod gcp {
    //! Google Cloud KMS envelope (stub).

    /// Placeholder for a future Google Cloud KMS-backed `KeySource`.
    #[derive(Debug, Default)]
    pub struct GcpKmsKeySourceStub;
}

#[cfg(feature = "kms-vault-transit")]
pub mod vault_transit {
    //! HashiCorp Vault Transit engine (stub).

    /// Placeholder for a future HashiCorp Vault Transit-backed `KeySource`.
    #[derive(Debug, Default)]
    pub struct VaultTransitKeySourceStub;
}
