//! Force-link trait inventory only.
//!
//! Entity schemas (`neutrino_secret`, versions, master key meta, audit events) are
//! registered by `generated_models.rs` (build.rs / valence-codegen) with trait fields
//! already merged. Do **not** also `include!` the `valence_schema!` sources here, or
//! inventory submits a second [`valence::SchemaMetadataInit`] and panics under Valence
//! duplicate registration rules.

// No trait-only overlays yet for Neutrino entities.
