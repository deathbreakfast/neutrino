//! Host-side request context for Unified Field server functions.
//!
//! Depends on [`uf_identity`] only — no product identity schemas. Concrete auth
//! backends and Valence user models are wired via **`lepton-host-adapter`**.

#[cfg(feature = "ssr")]
pub mod ssr;

#[cfg(feature = "ssr")]
pub use ssr::{
    current_operation, data_plane, host_ctx, with_operation, DataPlaneCtx, HostRequestCtx, SDb,
};
