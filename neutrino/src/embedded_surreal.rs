//! Logical database name for Neutrino Valence tables (aligns with permission / RBAC data).

use valence::{Database, DatabaseFromEngine, SQLITE_ENGINE_ID};

/// Logical database name Neutrino schemas are registered under.
///
/// Shares the `permissions` logical name so secret metadata can be joined
/// with RBAC data in the same embedded/test database.
pub const LOGICAL_NAME: &str = "permissions";

/// [`DatabaseFromEngine`] pointing at [`LOGICAL_NAME`] on the embedded SQLite engine.
pub const DEFAULT_STORAGE: DatabaseFromEngine =
    Database::from_engine(LOGICAL_NAME, SQLITE_ENGINE_ID);

/// Logical names test/server routers should link for Neutrino models to resolve.
pub const EMBEDDED_SURREAL_LOGICAL_NAMES: &[&str] = &[LOGICAL_NAME];
