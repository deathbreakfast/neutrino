//! Neutrino vault host: bootstrap seed → role gate → rotate → reveal under `/secrets`.
//!
//! Copy surfaces for product hosts: this package's `Cargo.toml` + `main.rs`,
//! plus the product-mount dependency / Leptos sketches in the host README.
//! Oneshot path `/secrets` matches Orbital app id/path `secrets` / `/secrets`
//! (see JSON `inventory`).
//!
//! ## When to use
//! Smoke sealed-store bootstrap and authz without mounting `NeutrinoRoutes`.
//!
//! ## Command
//! ```bash
//! export CARGO_BUILD_JOBS=1
//! export CARGO_TARGET_DIR=target-neutrino
//! cargo run -p vault-host
//! ```
//!
//! ## Success
//! Stdout prints `vault_host: OK — bootstrap → role gate → rotate/reveal`.
//!
//! ## Look next
//! Mount `<NeutrinoRoutes />` from `neutrino-app`; gate UI with Gauge permissions.

#![allow(clippy::print_stdout, clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs)]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use gauge::touch_schema_inventory;
use http_body_util::BodyExt;
use neutrino::bootstrap_seeder::seed_bootstrap_secrets_with;
use neutrino::create_initial_neutrino_groups;
use neutrino::vault::{
    create_vault_secret, reveal_vault_secret, rotate_vault_secret, store_from_valence_for_request,
    VaultAccessContext,
};
use tower::ServiceExt;
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter, Model,
    RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

#[derive(Clone)]
struct DemoSession {
    user_id: String,
}

#[derive(Clone)]
struct HostState {
    secret_id: String,
    version: i64,
    revealed: String,
}

async fn require_session(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    if req.extensions().get::<DemoSession>().is_some() {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn inject_demo_session(mut req: Request<Body>, next: Next) -> Response {
    if let Some(user) = req
        .headers()
        .get("x-demo-user")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
    {
        req.extensions_mut().insert(DemoSession { user_id: user });
    }
    next.run(req).await
}

fn prepare_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    unsafe {
        std::env::set_var("NEUTRINO_MASTER_KEY", "0".repeat(64));
        if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
            std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
        }
    }
}

async fn test_valence() -> Valence {
    prepare_env();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(
        SqliteBackend::connect_memory()
            .await
            .expect("SqliteBackend::connect_memory"),
    );
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        backend,
        neutrino::embedded_surreal::EMBEDDED_SURREAL_LOGICAL_NAMES,
        RegisterBackendLogicalNamesOptions::default(),
    );
    Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(router_key(
            neutrino::embedded_surreal::LOGICAL_NAME,
            SQLITE_ENGINE_ID,
        ))
        .with_actor(Actor::System {
            operation: "vault-host".into(),
        })
        .build()
        .expect("build valence")
}

async fn seed_user(id: &str, v: &Valence) {
    let now = Utc::now();
    let user = lepton::generated::User::new(
        Some(lepton::generated::UserUserType::Person),
        Some("demo-password-hash".to_string()),
        Some(lepton::generated::UserStatus::Active),
        None,
        None,
        Some(now),
        None,
        None,
        now,
        now,
    )
    .expect("build user");
    lepton::generated::User::upsert(id, user, v)
        .await
        .expect("upsert user");
}

async fn add_user_to_creators_group(user_id: &str, v: &Valence) {
    let group = gauge::generated::PermissionGroup::get("neutrino.secret.creators", v)
        .await
        .expect("get creators group")
        .expect("neutrino.secret.creators");
    let user = lepton::generated::User::get(user_id, v)
        .await
        .expect("get user")
        .expect("user row");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{user_id}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("user id").clone(),
            user_id.to_string(),
        )
        .expect("principal"),
        v,
    )
    .await
    .expect("upsert principal");
    group
        .relate_to_member_record(principal.id().expect("principal id"), v)
        .await
        .expect("relate member");
}

/// Host boot: Gauge Neutrino groups + `CreateNeutrinoSecrets` for alice.
async fn wire_vault_host(v: &Valence) {
    touch_schema_inventory();
    create_initial_neutrino_groups(v)
        .await
        .expect("create_initial_neutrino_groups");
    seed_user("alice", v).await;
    seed_user("bob", v).await;
    add_user_to_creators_group("alice", v).await;
}

async fn bootstrap_vault() -> HostState {
    let v = test_valence().await;
    wire_vault_host(&v).await;
    let store = store_from_valence_for_request(v, "user:alice");

    let seeded = seed_bootstrap_secrets_with(&store, "user:alice", Some("bootstrap-hmac-demo"))
        .await
        .expect("bootstrap seed");
    assert!(seeded.seeded_any, "expected bootstrap secret seeded");

    let created = create_vault_secret(
        &store,
        "demo_db_password".into(),
        "/demo/db".into(),
        "password".into(),
        "old-secret".into(),
        "user:alice".into(),
    )
    .await
    .expect("create");

    let bob = VaultAccessContext::owner_only("user:bob");
    let denied = reveal_vault_secret(&store, created.id.clone(), &bob)
        .await
        .expect_err("bob must be role-gated");
    assert!(
        matches!(
            denied,
            neutrino::NeutrinoError::AccessDenied {
                operation: "access this secret"
            }
        ),
        "got: {denied:?}"
    );

    let alice = VaultAccessContext::owner_only("user:alice");
    let rotated = rotate_vault_secret(
        &store,
        created.id.clone(),
        "new-secret".into(),
        "user:alice",
        &alice,
    )
    .await
    .expect("rotate");
    assert!(rotated.current_version > created.current_version);

    let revealed = reveal_vault_secret(&store, created.id.clone(), &alice)
        .await
        .expect("reveal");
    let plaintext = B64.decode(revealed.plaintext_b64.as_bytes()).expect("b64");
    assert_eq!(plaintext.as_slice(), b"new-secret");

    HostState {
        secret_id: created.id,
        version: rotated.current_version,
        revealed: String::from_utf8(plaintext).expect("utf8"),
    }
}

async fn secrets_api(
    Extension(session): Extension<DemoSession>,
    Extension(state): Extension<HostState>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "path": "/secrets",
        "user": session.user_id,
        "secret_id": state.secret_id,
        "version": state.version,
        "revealed": state.revealed,
        "flow": ["bootstrap", "role_gate", "rotate", "reveal"],
        // Matches neutrino-app `uf_app!` / NeutrinoPermission (Orbital route).
        "inventory": {
            "app_id": "secrets",
            "route_path": "/secrets",
            "read_permission": "SecretsRead",
            "reveal_permission": "SecretsReveal",
        },
    }))
}

fn app(state: HostState) -> Router {
    Router::new()
        .route("/secrets", get(secrets_api))
        .route_layer(from_fn(require_session))
        .layer(Extension(state))
        .layer(from_fn(inject_demo_session))
}

#[tokio::main]
async fn main() {
    let state = bootstrap_vault().await;

    let denied = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/secrets")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot")
        .status();
    assert_eq!(denied, StatusCode::UNAUTHORIZED);

    let response = app(state)
        .oneshot(
            Request::builder()
                .uri("/secrets")
                .header("x-demo-user", "demo-ops")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["path"], "/secrets");
    assert_eq!(body["revealed"], "new-secret");
    assert_eq!(body["inventory"]["app_id"], "secrets");
    assert_eq!(body["inventory"]["route_path"], "/secrets");
    assert_eq!(body["inventory"]["read_permission"], "SecretsRead");
    assert_eq!(body["inventory"]["reveal_permission"], "SecretsReveal");

    println!("vault_host: OK — bootstrap → role gate → rotate/reveal");
}
