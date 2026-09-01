//! Abstract auth/session identity surface for host crates.
//!
//! Concrete Valence user models live in **`lepton-identity`**; adapters implement
//! [`SessionIdentity`] and register session metadata for [`uf_host`].

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Stable session user identifier (typically a Surreal record id string).
pub type SessionUserId = String;

/// Minimal authenticated session snapshot for host/request layers.
///
/// Host middleware (e.g. `lepton-host-adapter`) populates this in Axum extensions
/// so crates like `higgs` can build Valence actors without importing concrete user models.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub user_id: SessionUserId,
    pub auth_hash: Vec<u8>,
}

impl SessionSnapshot {
    pub fn new(user_id: impl Into<SessionUserId>, auth_hash: impl AsRef<[u8]>) -> Self {
        Self {
            user_id: user_id.into(),
            auth_hash: auth_hash.as_ref().to_vec(),
        }
    }
}

/// Adapter-facing identity contract (implemented in product repos, not here).
#[async_trait]
pub trait SessionIdentity: Send + Sync {
    fn session_user_id(&self) -> &SessionUserId;
    fn session_auth_hash(&self) -> &[u8];

    fn to_snapshot(&self) -> SessionSnapshot {
        SessionSnapshot::new(self.session_user_id(), self.session_auth_hash())
    }
}
