//! In-memory backend that treats unique-index DDL as success, so Lepton's
//! `service_user_account` table can be created in tests.

#![allow(dead_code)]

use async_trait::async_trait;
use valence::{CompiledQuery, DatabaseBackend, InMemoryBackend, RecordId, Result};

/// Wraps [`InMemoryBackend`] and treats unsupported unique-index DDL as success.
#[derive(Debug)]
pub struct TolerantMemBackend {
    inner: InMemoryBackend,
}

impl TolerantMemBackend {
    pub fn new() -> Self {
        Self {
            inner: InMemoryBackend::new(),
        }
    }
}

#[async_trait]
impl DatabaseBackend for TolerantMemBackend {
    fn engine_id(&self) -> &'static str {
        self.inner.engine_id()
    }

    fn capabilities(&self) -> valence::BackendCapabilities {
        self.inner.capabilities()
    }

    async fn use_namespace(&self, ns: &str, db_name: &str) -> Result<()> {
        self.inner.use_namespace(ns, db_name).await
    }

    async fn execute_compiled_query(
        &self,
        compiled: &CompiledQuery,
    ) -> Result<Vec<serde_json::Value>> {
        self.inner.execute_compiled_query(compiled).await
    }

    async fn ensure_schemaless_table(&self, table: &str) -> Result<()> {
        self.inner.ensure_schemaless_table(table).await
    }

    async fn get_record(&self, table: &str, id: &str) -> Result<Option<serde_json::Value>> {
        self.inner.get_record(table, id).await
    }

    async fn create_record(
        &self,
        table: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.create_record(table, content).await
    }

    async fn update_record(
        &self,
        table: &str,
        id: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.update_record(table, id, content).await
    }

    async fn merge_record(
        &self,
        table: &str,
        id: &str,
        patch: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.merge_record(table, id, patch).await
    }

    async fn upsert_record(
        &self,
        table: &str,
        id: &str,
        content: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner.upsert_record(table, id, content).await
    }

    async fn delete_record(&self, table: &str, id: &str) -> Result<()> {
        self.inner.delete_record(table, id).await
    }

    async fn relate_edge(&self, from: &RecordId, edge_table: &str, to: &RecordId) -> Result<()> {
        self.inner.relate_edge(from, edge_table, to).await
    }

    async fn unrelate_edge(&self, from: &RecordId, edge_table: &str, to: &RecordId) -> Result<()> {
        self.inner.unrelate_edge(from, edge_table, to).await
    }

    async fn get_edge_targets(&self, from: &RecordId, edge_table: &str) -> Result<Vec<RecordId>> {
        self.inner.get_edge_targets(from, edge_table).await
    }

    async fn define_unique_index(&self, table: &str, field: &str) -> Result<()> {
        match self.inner.define_unique_index(table, field).await {
            Ok(()) => Ok(()),
            Err(valence::Error::Internal(msg))
                if msg.contains("define_unique_index")
                    || msg.contains("unique indexes not supported") =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn ttl_capability(&self) -> valence::ttl::BackendTtlCapability {
        self.inner.ttl_capability()
    }

    async fn apply_ttl_policy(
        &self,
        table: &str,
        policy: &valence::ttl::SchemaTtlPolicy,
    ) -> Result<()> {
        self.inner.apply_ttl_policy(table, policy).await
    }
}
