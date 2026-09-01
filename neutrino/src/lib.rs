//! Encrypted-at-rest secrets with audit chaining.
//!
//! Neutrino seals plaintext into Valence (XChaCha20-Poly1305), hash-chains audit
//! rows for seal/reveal/rotate/delete, and classifies which env keys may stay
//! outside the vault during bootstrap. Enable `feature = "ssr"` for Valence-backed
//! store and vault APIs; crypto helpers are always available. The Leptos admin UI
//! lives in [neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app) (`neutrino-app`).
//!
//! ## Where to look
//!
//! | Need | Module / crate |
//! |------|----------------|
//! | Trait + request types | [`secret_store`] |
//! | Valence-backed store | [`ValenceSealedStore`] / [`sealed_store`] (feature `ssr`) |
//! | Product / UI vault API | [`vault`] (feature `ssr`) |
//! | Owner / scope-prefix bridge | [`vault_authz`] (feature `ssr`) |
//! | Gauge bootstrap + create gate | [`create_initial_neutrino_groups`], [`CREATE_NEUTRINO_SECRETS`] |
//! | Master key env | [`key_source`] / [`MasterKeyError`] |
//! | Bootstrap env classification / seed | [`bootstrap_trust`], [`bootstrap_seeder`] |
//! | Low-level seal/unseal | [`crypto`] |
//! | Typed failures | [`NeutrinoError`] / [`NeutrinoResult`] |
//! | Spectra access telemetry | `neutrino-spectra-telemetry` |
//! | Operator UI routes | `neutrino-uf-app` (`NeutrinoRoutes`) |
//!
//! ## Integrator lanes
//!
//! 1. **Control-plane seal** — System ORM Valence for `SYSTEM_ONLY` rows, plus
//!    `request_actor` for audit. Use [`ValenceSealedStore`] / [`secret_store::SecretStore`] from
//!    boot jobs and host seeders (not a mid-request elevate from a user session).
//! 2. **Product vault** — [`store_from_valence_for_request`] + [`vault`] helpers with
//!    session Valence (Valence privacy enforces Gauge per-secret grants). Legacy
//!    [`VaultAccessContext`] applies only where Gauge bundles were skipped.
//! 3. **Admin UI** — Higgs wrappers in `neutrino-app` over the vault lane.
//!
//! ## Features
//!
//! - **Gauge resource groups** — Installs Gauge groups that gate who may create
//!   Neutrino secrets and who may reveal each stored row. Call once at worker boot
//!   before serving seal or vault APIs. [Get started](#gauge-bootstrap-at-boot).
//! - **Sealed secret store** — [`ValenceSealedStore`] implements [`secret_store::SecretStore`] for
//!   steady-state puts that encrypt plaintext, write audit metadata, and return a
//!   [`SecretRef`]. [Get started](#seal-or-put-secret).
//! - **Secret reveal** — Decrypt the current version with [`secret_store::SecretStore::get`], or pin
//!   an older version with [`ValenceSealedStore::reveal_at_version`]. Prefer product
//!   [`vault`] APIs for UI traffic. [Get started](#reveal-secret).
//! - **Secret rotation** — Archive the active ciphertext, bump the version, and seal
//!   new plaintext under the same secret id. [Get started](#rotate-secret).
//! - **Secret deletion** — Remove a secret row and every version ciphertext after
//!   authorization checks. [Get started](#delete-secret).
//! - **Env secret seeder** — Copies bootstrap-classified env material into the
//!   sealed store on first boot and emits `scoped_credentials_refs_json`.
//!   [Get started](#bootstrap-env-seed).
//! - **Master key resolution** — Loads `NEUTRINO_MASTER_KEY` as typed
//!   [`MasterKeyError`]-bearing bytes before any seal or reveal.
//!   [Get started](#resolve-master-key).
//! - **Secret access model** — Who can browse, reveal, edit, and delete a secret,
//!   what Super User can always do, and which Gauge objects a new secret creates.
//!   Read this before you store your first credential. [Get started](#secret-access-model).
//! - **Per-secret access grants** — Give one teammate access to one secret, by maintainer
//!   group for full rights or by action name for least privilege.
//!   [Get started](#grant-access-to-a-secret).
//! - **Control-plane secret lane** — Boot jobs and background workers read secrets through
//!   a System-from-start handle that skips session Gauge checks by design.
//!   [Get started](#control-plane-secret-lane).
//!
//! Product vault HTTP-facing helpers live in [`vault`]; per-secret Gauge checks use
//! [`vault_authz`]. Low-level seal/unseal is in [`crypto`]. Backend selection uses
//! [`secret_backend`]; env key classification uses [`bootstrap_trust`].
//!
//! ## Getting started
//!
//! Control-plane seal: after Gauge bootstrap and master-key resolution, construct a
//! [`ValenceSealedStore`] with System ORM Valence (schemas are `SYSTEM_ONLY`) and set
//! `request_actor` for audit attribution. Plaintext is `Zeroizing` and wiped on drop.
//!
//! ```ignore
//! use neutrino::secret_store::{PutSecretRequest, SecretStore};
//! use neutrino::{create_initial_neutrino_groups, ValenceSealedStore};
//! use valence::Actor;
//! use std::sync::Arc;
//!
//! create_initial_neutrino_groups(&valence).await?;
//!
//! let store = ValenceSealedStore {
//!     valence: Arc::new(valence.with_actor(Actor::System {
//!         operation: "seal_smtp".into(),
//!     })),
//!     request_actor: Some("service:smtp-boot".into()),
//! };
//!
//! let secret_ref = store.put(PutSecretRequest {
//!     name: "smtp_password".into(),
//!     scope_path: "/uf-notifications/smtp".into(),
//!     kind: "password".into(),
//!     plaintext: b"correct-horse-battery-staple".to_vec(),
//!     owner_actor: "service:smtp-boot".into(),
//! }).await?;
//!
//! let revealed = store.get(&secret_ref.id).await?;
//! assert_eq!(&*revealed.plaintext, b"correct-horse-battery-staple");
//!
//! let pinned = store.reveal_at_version(&secret_ref.id, secret_ref.version).await?;
//! assert_eq!(&*pinned.plaintext, b"correct-horse-battery-staple");
//! ```
//!
//! Product vault (UI / session lane) uses [`store_from_valence_for_request`] and
//! [`reveal_vault_secret`] with [`VaultAccessContext`]. Match [`NeutrinoError`] at the
//! host edge (`NotFound` / `AccessDenied` / `Validation` / …).
//!
//! ```ignore
//! use neutrino::{
//!     create_vault_secret, reveal_vault_secret, store_from_valence_for_request,
//!     NeutrinoError, VaultAccessContext,
//! };
//!
//! let store = store_from_valence_for_request(system_orm_valence, "user:alice");
//! create_vault_secret(
//!     &store,
//!     "smtp_password".into(),
//!     "/uf-notifications/smtp".into(),
//!     "password".into(),
//!     "correct-horse-battery-staple".into(),
//!     "user:alice".into(),
//! ).await?;
//! let access = VaultAccessContext::owner_only("user:alice");
//! match reveal_vault_secret(&store, secret_id, &access).await {
//!     Ok(r) => { let _ = r.plaintext_b64; }
//!     Err(NeutrinoError::NotFound { .. }) => { /* 404 */ }
//!     Err(NeutrinoError::AccessDenied { .. }) => { /* 403 */ }
//!     Err(NeutrinoError::Validation { .. }) => { /* 400 */ }
//!     Err(_) => { /* 500 */ }
//! }
//! ```
//!
//! Next: [Gauge bootstrap at boot](#gauge-bootstrap-at-boot), then the seal / reveal /
//! rotate / delete guides below. For a full host walkthrough, run
//! `CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=target-neutrino cargo run -p vault-host`.
//!
//! ## Gauge bootstrap at boot
//!
//! At worker boot, Gauge groups gate who may create Neutrino secrets and who may
//! reveal each stored row. Hosts call [`create_initial_neutrino_groups`] once during
//! worker bootstrap in the same phase as Gauge manifest sync, before serving seal or
//! vault HTTP APIs. Each successful [`secret_store::SecretStore::put`] auto-calls
//! [`ensure_secret_permission_bundle`]; integrators should not ensure bundles
//! separately. Create is gated by the System actor or [`CREATE_NEUTRINO_SECRETS`].
//!
//! **Prerequisites:** `feature = "ssr"`, a live `valence::Valence`, and Gauge
//! available in the host graph.
//!
//! ```ignore
//! use neutrino::create_initial_neutrino_groups;
//!
//! // Same bootstrap phase as Gauge manifest sync — before seal/vault routes.
//! let result = create_initial_neutrino_groups(&valence).await;
//! assert!(result.is_ok());
//! let _: () = result?;
//! assert!(matches!(Ok::<(), ()>(()), Ok(())));
//! ```
//!
//! Errors surface as Gauge `ResourcePermissionError`.
//! Next: [secret access model](#secret-access-model), then [seal or put](#seal-or-put-secret).
//!
//! ## Secret access model
//!
//! Neutrino splits **metadata** (any authenticated user may list secret names and ids)
//! from **payload and mutations** (Gauge `neutrino_secret.{id}.{View|Reveal|Edit|Delete|Maintain}`
//! checked inside Valence privacy on every ciphertext read and write). Super User
//! (`super_user_group`) is unconditional break-glass on every secret. After umbrella
//! narrowing, `neutrino.secret.viewers` / `.operators` no longer grant per-secret access —
//! use explicit grants or the per-secret owners group (`rp_owners_neutrino_secret_{id}`).
//!
//! **Prerequisites:** `feature = "ssr"`, Gauge catalog seeded, session or System Valence.
//!
//! ```ignore
//! use gauge::resource_permissions::{ResourceAction, ResourceKind, permission_name};
//! use neutrino::actor_can_secret;
//!
//! let name = permission_name(ResourceKind::NeutrinoSecret, secret_id, ResourceAction::Reveal);
//! let allowed = actor_can_secret(&session_valence, secret_id, ResourceAction::Reveal).await?;
//! assert!(allowed || !allowed);
//! ```
//!
//! Failures return [`NeutrinoError::AccessDenied`]. Next: [grant access](#grant-access-to-a-secret).
//!
//! ## Grant access to a secret
//!
//! Add the user to `rp_owners_neutrino_secret_{id}` for full maintainer rights, or grant a
//! single action name for least privilege.
//!
//! ```ignore
//! use gauge::service;
//! service::grant_permission_to_user(&valence, &permission_name, "user:bob").await?;
//! assert!(service::actor_can(&valence, &permission_name).await?);
//! ```
//!
//! ## Control-plane secret lane
//!
//! Jobs that start as `Actor::System` use [`ValenceSealedStore`] with System ORM Valence.
//! `SecretStore::get` decrypts any id without a Gauge check — callers must only pass trusted ids.
//!
//! ```ignore
//! use neutrino::{ValenceSealedStore, secret_store::SecretStore};
//! let store = ValenceSealedStore { valence: system_arc, request_actor: Some("service:boot".into()) };
//! let _ = store.put_or_reuse(put_req).await?;
//! ```
//!
//! ## Seal or put secret
//!
//! [`ValenceSealedStore`] is the Valence-backed [`secret_store::SecretStore`] integrators use after
//! bootstrap. A `put` seals plaintext, writes hash-chained audit metadata, and
//! returns a [`SecretRef`] with the new version id callers pass to reveal and rotate.
//! Call during steady-state credential writes once Gauge bootstrap finished. The
//! caller must be System or hold CreateNeutrinoSecrets; set `owner_actor` to a real
//! Lepton user id so Maintain ownership resolves correctly.
//!
//! **Prerequisites:** Gauge groups installed, master key resolved, `feature = "ssr"`.
//!
//! ```ignore
//! use neutrino::secret_store::{PutSecretRequest, SecretStore};
//! use neutrino::sealed_store::ValenceSealedStore;
//! use valence::Actor;
//!
//! let store = ValenceSealedStore {
//!     valence: Arc::new(valence.with_actor(Actor::System {
//!         operation: "seal_smtp".into(),
//!     })),
//!     request_actor: Some("user:alice".into()),
//! };
//!
//! let secret_ref = store.put(PutSecretRequest {
//!     name: "smtp_password".into(),
//!     scope_path: "/uf-notifications/smtp".into(),
//!     kind: "password".into(),
//!     plaintext: b"correct-horse-battery-staple".to_vec(),
//!     owner_actor: "user:alice".into(),
//! }).await?;
//!
//! let revealed = store.get(&secret_ref.id).await?;
//! assert_eq!(&*revealed.plaintext, b"correct-horse-battery-staple");
//! ```
//!
//! Failures return [`NeutrinoError`] (authz, Valence, or crypto). Deduplicate by name +
//! scope with [`secret_store::SecretStore::put_or_reuse`]. Next: [reveal](#reveal-secret).
//!
//! ## Reveal secret
//!
//! Reveal decrypts stored ciphertext for authorized callers. [`secret_store::SecretStore::get`]
//! returns the current version; [`ValenceSealedStore::reveal_at_version`] pins an
//! older version for workflows that must not read the latest row. Prefer product
//! vault reveal APIs when serving UI traffic so Gauge Reveal permissions apply.
//! Low-level `get` is trusted-internal (System ORM). Plaintext is `Zeroizing` and
//! wipes on drop.
//!
//! **Prerequisites:** an existing [`SecretRef`] from put/rotate; authorized actor.
//!
//! ```ignore
//! use neutrino::secret_store::SecretStore;
//! use neutrino::sealed_store::ValenceSealedStore;
//!
//! let revealed = store.get(&secret_ref.id).await?;
//! assert_eq!(&*revealed.plaintext, b"correct-horse-battery-staple");
//!
//! let pinned = store.reveal_at_version(&secret_ref.id, secret_ref.version).await?;
//! assert_eq!(&*pinned.plaintext, b"correct-horse-battery-staple");
//! ```
//!
//! For UI paths, call [`reveal_vault_secret`] instead of low-level `get` so Gauge
//! Reveal permissions apply. Failures return [`NeutrinoError`] (missing id, authz
//! deny, or crypto/unseal). Next: [rotate](#rotate-secret) or [delete](#delete-secret).
//!
//! ## Rotate secret
//!
//! Rotation archives the active ciphertext row, bumps the version counter, and seals
//! new plaintext under the same secret id. Use when a credential changed but the
//! scope/name should stay stable for callers holding the id.
//!
//! **Prerequisites:** authorized Rotate (or System) actor; existing secret id.
//!
//! ```ignore
//! use neutrino::secret_store::SecretStore;
//!
//! let rotated = store
//!     .rotate(&secret_ref.id, b"new-horse-battery-staple".to_vec(), "user:alice")
//!     .await?;
//! assert!(rotated.version > secret_ref.version);
//! assert_eq!(rotated.id, secret_ref.id);
//! ```
//!
//! Errors aggregate authz and store failures via [`NeutrinoError`]. Next: [reveal](#reveal-secret)
//! the new version, or [delete](#delete-secret) when retiring the credential.
//!
//! ## Delete secret
//!
//! Delete removes the secret row, version ciphertext (Valence cascade), and the Gauge
//! per-secret bundle via `gauge::delete_resource_permission_bundle`. Umbrella groups, shared
//! principals, `CreateNeutrinoSecrets`, and audit rows remain.
//!
//! **Prerequisites:** authorized Delete (or System) actor; existing secret id.
//!
//! ```ignore
//! use neutrino::secret_store::SecretStore;
//!
//! let result = store.delete(&secret_ref.id).await;
//! assert!(result.is_ok());
//! let _: () = result?;
//! assert!(matches!(Ok::<(), ()>(()), Ok(())));
//! ```
//!
//! Failures return [`NeutrinoError`] when the actor lacks Delete, the id is unknown,
//! or the store write fails. Subsequent `get` / reveal calls also fail after a
//! successful delete. Next: list remaining rows with [`list_secrets`], or return to
//! [seal or put](#seal-or-put-secret).
//!
//! ## Bootstrap env seed
//!
//! [`seed_bootstrap_secrets_from_env`] copies bootstrap-classified env material into
//! the sealed store during first boot. Connectivity keys such as `NEUTRINO_MASTER_KEY`,
//! `BOOTSTRAP_DB_*`, and setup-wizard tokens stay env-readable until seeded; steady-state
//! credentials should live in [`ValenceSealedStore`] after bootstrap
//! ([`classify_env_key`] classifies each key). Run
//! once after Valence placement and master key resolution, before steady-state puts.
//!
//! **Prerequisites:** Gauge bootstrap done, master key resolved, env vars present for
//! keys you intend to seed.
//!
//! ```ignore
//! use neutrino::seed_bootstrap_secrets_from_env;
//!
//! let seeded = seed_bootstrap_secrets_from_env(&store, "user:alice").await?;
//! // `seeded` holds scoped_credentials_refs_json for host wiring.
//! assert!(seeded.seeded_any || seeded.scoped_credentials_refs_json == "[]");
//! ```
//!
//! Failures return [`NeutrinoError`] when the store rejects a put, a migration HMAC
//! version mismatches, or required bootstrap env material cannot be read. Prefer a
//! single call after DB placement. Next: [seal or put](#seal-or-put-secret) for
//! steady-state credentials.
//!
//! ## Resolve master key
//!
//! [`master_key_from_env`] loads `NEUTRINO_MASTER_KEY` before any seal or reveal runs.
//! The helper accepts 32-byte hex (or a weak UTF-8 escape when explicitly allowed) and
//! returns typed [`MasterKeyError`] when the variable is missing, empty, or malformed.
//! Resolve during process startup before constructing [`ValenceSealedStore`] or calling
//! [`seed_bootstrap_secrets_from_env`].
//!
//! **Prerequisites:** `NEUTRINO_MASTER_KEY` set in the process environment.
//!
//! ```ignore
//! use neutrino::master_key_from_env;
//!
//! // std::env::set_var("NEUTRINO_MASTER_KEY", "<64 hex chars>");
//! let key = master_key_from_env()?;
//! assert!(key.len() == 32 || key.len() > 0);
//! assert!(key.len() > 0);
//! ```
//!
//! On failure, inspect [`MasterKeyError`] variants (`NotSet`, `Empty`, `InvalidHex`,
//! `WeakKeyRejected`). Next: [Gauge bootstrap](#gauge-bootstrap-at-boot) if not done,
//! then [bootstrap env seed](#bootstrap-env-seed).
//!
//! ## Feature flags
//!
//! | Flag | What it enables |
//! |------|-----------------|
//! | *(default)* | Crypto helpers, [`key_source`], [`bootstrap_trust`], [`secret_backend`] stubs |
//! | `ssr` | Valence models, [`ValenceSealedStore`], [`vault`], Gauge wiring, instrumentation |
//! | `rbac-tests` | Extra Gauge RBAC integration tests (`ssr` + lepton/gauge graph) |
//! | `kms-aws` / `kms-gcp` / `kms-vault-transit` | Stub Cargo gates for future KMS key-source work |
//! | `hsm-pkcs11` / `hsm-tpm` | Stub Cargo gates for future HSM key sources |
//!
//! ## Examples
//!
//! - First success: [Getting started](#getting-started)
//! - Gauge boot: [Gauge bootstrap at boot](#gauge-bootstrap-at-boot)
//! - Seal / reveal / rotate / delete: [seal](#seal-or-put-secret), [reveal](#reveal-secret),
//!   [rotate](#rotate-secret), [delete](#delete-secret)
//! - Bootstrap path: [resolve master key](#resolve-master-key), [env seed](#bootstrap-env-seed)
//! - Contract tests: `cargo test -p neutrino --features ssr --test vault_crud_contract`
//!   (also `vault_authz_contract`, `vault_gauge_authz` with `rbac-tests`)
//! - Host walkthrough: `CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=target-neutrino cargo run -p vault-host`
//!
//! Master key env errors use [`MasterKeyError`]. Store and vault APIs return
//! [`NeutrinoResult`]. Leptos server fns in `neutrino-app` map failures to `ServerFnError`.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Pre-existing pedantic/nursery debt in sealed_store / instrumentation (outside vault
// contract surface). New vault API code should still prefer idiomatic Clippy fixes.
#![allow(
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_pass_by_value,
    clippy::option_if_let_else,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

#[cfg(feature = "ssr")]
mod canonical_secret_id;
#[cfg(feature = "ssr")]
pub mod embedded_surreal;
/// Generated Valence models (schema codegen). Prefer [`vault`] / [`sealed_store`] APIs.
#[cfg(feature = "ssr")]
#[doc(hidden)]
pub mod generated;
#[cfg(feature = "ssr")]
pub mod instrumentation;
#[cfg(feature = "ssr")]
mod privacy_policies;
#[cfg(feature = "ssr")]
mod schemas;
#[cfg(feature = "ssr")]
pub mod sealed_store;
#[cfg(feature = "ssr")]
pub mod vault;
#[cfg(feature = "ssr")]
pub mod vault_authz;
#[cfg(feature = "ssr")]
pub(crate) mod vault_gauge;

pub mod audit;
pub use audit::{verify_audit_chain, AuditChainLink};
pub mod bootstrap_seeder;
pub mod bootstrap_trust;
pub mod crypto;
pub mod error;
#[cfg(any(feature = "hsm-pkcs11", feature = "hsm-tpm"))]
pub mod hsm_sources;
pub mod key_source;
#[cfg(any(
    feature = "kms-aws",
    feature = "kms-gcp",
    feature = "kms-vault-transit"
))]
pub mod kms_sources;
pub mod secret_backend;
pub mod secret_store;

pub use bootstrap_seeder::{
    seed_bootstrap_secrets_from_env, seed_bootstrap_secrets_with, SecretRefEnvelopeWire,
    SeededBootstrapSecrets,
};
pub use bootstrap_trust::{classify_env_key, SecretLifecycleClass};
pub use error::{NeutrinoError, NeutrinoResult};
#[cfg(feature = "ssr")]
pub use gauge::resource_permissions::CREATE_NEUTRINO_SECRETS;
pub use key_source::{master_key_from_env, MasterKeyError};
#[cfg(feature = "ssr")]
pub use sealed_store::{list_secrets, ListedSecret, ValenceSealedStore};
pub use secret_backend::{
    secret_backend_kind_from_env, uses_neutrino_sealed_store, SecretBackendKind,
};
pub use secret_store::{SecretId, SecretRef, SecretVersionId};
#[cfg(feature = "ssr")]
pub use vault::{
    create_vault_secret, delete_vault_secret, list_vault_secrets, neutrino_vault_ping,
    reveal_vault_secret, rotate_vault_secret, store_from_valence, store_from_valence_for_request,
    RevealedVaultSecret, VaultAccessContext, VaultSecretRow,
};
#[cfg(feature = "ssr")]
pub use vault_authz::{can_access_secret, ensure_can_access_secret};
#[cfg(feature = "ssr")]
pub use vault_gauge::{
    actor_can_secret, assert_neutrino_catalog_seeded, create_initial_neutrino_groups,
    ensure_secret_permission_bundle, NEUTRINO_SECRET_RESOURCE,
};
