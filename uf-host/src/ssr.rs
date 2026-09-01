//! SSR helpers: extract DB + router + optional [`uf_identity::SessionSnapshot`].

use axum::extract::Extension;
use leptos::prelude::ServerFnError;
use leptos_axum::extract;
use std::sync::Arc;
use uf_identity::SessionSnapshot;
use valence::{Actor, DatabaseRouter};

pub type SDb = surrealdb::Surreal<surrealdb::engine::local::Db>;

tokio::task_local! {
    static CURRENT_OPERATION: Option<&'static str>;
}

/// Database plane extracted from Axum extensions (no auth).
#[derive(Clone)]
pub struct DataPlaneCtx {
    pub db: SDb,
    pub database_router: Arc<DatabaseRouter>,
}

/// Full host request context including optional session snapshot.
#[derive(Clone)]
pub struct HostRequestCtx {
    pub db: SDb,
    pub database_router: Arc<DatabaseRouter>,
    pub session: Option<SessionSnapshot>,
}

impl HostRequestCtx {
    pub fn session_user_id(&self) -> Option<&str> {
        self.session.as_ref().map(|s| s.user_id.as_str())
    }

    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    pub fn db(&self) -> &SDb {
        &self.db
    }

    pub fn actor(&self) -> Actor {
        match self.session.as_ref() {
            Some(s) => Actor::User {
                user_id: s.user_id.clone(),
            },
            None => Actor::Anonymous,
        }
    }
}

/// Extract DB + router only.
pub async fn data_plane() -> Result<DataPlaneCtx, ServerFnError> {
    let Extension(db): Extension<SDb> = extract().await?;
    let Extension(database_router): Extension<Arc<DatabaseRouter>> = extract().await?;
    Ok(DataPlaneCtx {
        db,
        database_router,
    })
}

/// Extract DB, router, and optional [`SessionSnapshot`] extension.
///
/// Auth middleware in `lepton-host-adapter` should insert `Extension<SessionSnapshot>`
/// when a user is authenticated.
pub async fn host_ctx() -> Result<HostRequestCtx, ServerFnError> {
    let Extension(db): Extension<SDb> = extract().await?;
    let Extension(database_router): Extension<Arc<DatabaseRouter>> = extract().await?;
    let session: Option<Extension<SessionSnapshot>> = extract().await.ok();
    Ok(HostRequestCtx {
        db,
        database_router,
        session: session.map(|Extension(s)| s),
    })
}

pub fn current_operation() -> Option<&'static str> {
    CURRENT_OPERATION.try_with(|op| *op).ok().flatten()
}

pub async fn with_operation<F, R>(operation: &'static str, fut: F) -> R
where
    F: std::future::Future<Output = R>,
{
    CURRENT_OPERATION.scope(Some(operation), fut).await
}
