//! Logical database name for Neutrino Valence tables.
//!
//! Neutrino tables live on their own `neutrino` logical, apart from Gauge's
//! `gauge` logical, so a host can keep sealed secret metadata and permission
//! data on separate backends. Hosts call [`register_storage`] once per router;
//! it registers the backend under the backend's own engine id and under
//! [`SCHEMA_ENGINE_ID`], the engine the schemas declare.

use std::sync::Arc;

use valence::{
    router_key, Database, DatabaseBackend, DatabaseFromEngine, DatabaseRouter, SQLITE_ENGINE_ID,
};

/// Logical database name Neutrino schemas are registered under.
pub const LOGICAL_NAME: &str = "neutrino";

/// Engine id every Neutrino schema declares in its `database:` storage.
pub const SCHEMA_ENGINE_ID: &str = SQLITE_ENGINE_ID;

/// [`DatabaseFromEngine`] pointing at [`LOGICAL_NAME`] on the embedded SQLite engine.
pub const DEFAULT_STORAGE: DatabaseFromEngine =
    Database::from_engine(LOGICAL_NAME, SCHEMA_ENGINE_ID);

/// Logical names test/server routers should link for Neutrino models to resolve.
pub const EMBEDDED_SURREAL_LOGICAL_NAMES: &[&str] = &[LOGICAL_NAME];

/// Router key Neutrino schemas resolve through ([`SCHEMA_ENGINE_ID`]:[`LOGICAL_NAME`]).
#[must_use]
pub fn schema_router_key() -> String {
    router_key(LOGICAL_NAME, SCHEMA_ENGINE_ID)
}

/// Route every Neutrino schema to `backend`.
///
/// Registers [`LOGICAL_NAME`] under `backend.engine_id()` and under
/// [`SCHEMA_ENGINE_ID`]. Without the second key Valence falls back to the
/// router's default backend and secret metadata lands in the host's default
/// database.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use valence::{DatabaseBackend, DatabaseRouter, InMemoryBackend};
///
/// let backend: Arc<dyn DatabaseBackend> = Arc::new(InMemoryBackend::new());
/// let mut router = DatabaseRouter::new();
/// neutrino::embedded_surreal::register_storage(&mut router, backend);
/// assert!(router
///     .resolve(&neutrino::embedded_surreal::schema_router_key())
///     .is_ok());
/// ```
pub fn register_storage(router: &mut DatabaseRouter, backend: Arc<dyn DatabaseBackend>) {
    router.register(
        router_key(LOGICAL_NAME, backend.engine_id()),
        Arc::clone(&backend),
    );
    router.register(schema_router_key(), backend);
}

#[cfg(test)]
mod tests {
    use super::*;
    use valence::{InMemoryBackend, MEM_ENGINE_ID};

    #[test]
    fn register_storage_adds_backend_and_schema_engine_keys_happy_path() {
        let backend: Arc<dyn DatabaseBackend> = Arc::new(InMemoryBackend::new());
        let mut router = DatabaseRouter::new();
        register_storage(&mut router, Arc::clone(&backend));

        let via_schema = router.resolve(&schema_router_key()).expect("schema key");
        let via_engine = router
            .resolve(&router_key(LOGICAL_NAME, MEM_ENGINE_ID))
            .expect("engine key");
        assert!(Arc::ptr_eq(&via_schema, &backend));
        assert!(Arc::ptr_eq(&via_engine, &backend));
    }

    #[test]
    fn gauge_neutrino_distinct_logicals() {
        assert_ne!(LOGICAL_NAME, gauge::embedded_surreal::LOGICAL_NAME);
        assert_ne!(
            schema_router_key(),
            gauge::embedded_surreal::schema_router_key()
        );
        assert_ne!(LOGICAL_NAME, "permissions");
    }
}
