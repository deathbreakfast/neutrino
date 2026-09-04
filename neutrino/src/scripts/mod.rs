//! Neutrino Chronon scripts (feature `chronon`).
//!
//! # Job catalog
//!
//! | Job name | Script module | Default schedule | Notes |
//! |----------|---------------|------------------|-------|
//! | `revoke-neutrino-secret-umbrella-grants` | [`revoke_neutrino_secret_umbrella_grants`](crate::scripts::revoke_neutrino_secret_umbrella_grants) | run once | Clears standing `neutrino_secret.*` grants left by bundles ensured before [`UmbrellaPolicy::None`](gauge::resource_permissions::UmbrellaPolicy::None) |

pub mod revoke_neutrino_secret_umbrella_grants;

#[doc(inline)]
pub use revoke_neutrino_secret_umbrella_grants::{
    revoke_neutrino_secret_umbrella_grants, revoke_neutrino_secret_umbrella_grants_script,
};
