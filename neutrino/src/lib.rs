//! Encrypted-at-rest secrets with audit chaining.
//!
//! Neutrino seals plaintext into Valence (XChaCha20-Poly1305), hash-chains audit
//! rows for seal/reveal/rotate/delete, and classifies which env keys may stay
//! outside the vault during bootstrap. Enable `feature = "ssr"` for Valence-backed
//! store and vault APIs; crypto helpers are always available. The Leptos admin UI
//! lives in [neutrino-uf-app](https://github.com/unified-field-dev/neutrino-uf-app) (`neutrino-app`).
//!
//! ## Where to look
//!
//! | Need | Module / crate |
//! |------|----------------|
//! | Trait + request types | [`secret_store`] |
//! | Valence-backed store | [`ValenceSealedStore`] / [`sealed_store`] (feature `ssr`) |
//! | Product / UI vault API | [`vault`] (feature `ssr`) |
//! | Gauge per-secret authz | [`actor_can_secret`], [`ensure_secret_permission_bundle`] |
//! | Gauge bootstrap + create gate | [`create_initial_neutrino_groups`], [`CREATE_NEUTRINO_SECRETS`] |
//! | Master key env / KMS / HSM unwrap | [`key_source`] / [`resolve_master_key`] / [`MasterKeyError`] |
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
//!    session Valence (Valence privacy and Gauge per-secret grants on the request actor).
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
//! - **Master key resolution** — Loads the process master key via [`resolve_master_key`]
//!   (`NEUTRINO_MASTER_KEY` by default, or KMS/HSM unwrap when `NEUTRINO_KEY_SOURCE` and a
//!   matching `kms-*` / `hsm-*` feature are set) as typed [`MasterKeyError`]-bearing bytes
//!   before seal or reveal.
//!   [Get started](#resolve-master-key).
//! - **KMS master-key sources** — Optional AWS KMS, GCP KMS, or Vault Transit unwrap of a
//!   wrapped master key (`NEUTRINO_MASTER_KEY_WRAPPED`). Customer secrets stay in Valence;
//!   KMS only protects the process key. [Get started](#resolve-master-key).
//! - **Hardware master-key unwrap** — Resolve the process master key via PKCS#11 or TPM 2.0
//!   (`hsm-pkcs11` / `hsm-tpm`, RSA-OAEP unwrap of `NEUTRINO_MASTER_KEY_WRAPPED`).
//!   [Get started](#resolve-master-key).
//! - **Secret access model** — Who can browse, reveal, edit, and delete a secret,
//!   what Super User can always do, and which Gauge objects a new secret creates.
//!   Read this before you store your first credential. [Get started](#secret-access-model).
//! - **Scope-prefix list filter** — Optional `scope_prefix` on [`list_secrets`] /
//!   [`list_vault_secrets`] keeps the browsable metadata list but returns only rows
//!   under that path (path-segment safe). Products deep-link `/secrets?scope_prefix=…`
//!   without dumping the whole vault. [Get started](#filter-vault-list-by-scope-prefix).
//! - **Per-secret access grants** — Give one teammate access to one secret, by maintainer
//!   group for full rights or by action name for least privilege.
//!   [Get started](#grant-access-to-a-secret).
//! - **Control-plane secret lane** — Boot jobs and background workers read secrets through
//!   a System-from-start handle that skips session Gauge checks by design.
//!   [Get started](#control-plane-secret-lane).
//! - **Short-lived secret lease** — [`secret_store::SecretStore::lease`] returns
//!   Zeroizing plaintext for a TTL (Reveal-gated), for env injection on apply paths.
//!   [`secret_store::SecretStore::extend_grace`] keeps a prior version leaseable after a failed apply.
//!   [Get started](#lease-secret).
//!
//! Product vault HTTP-facing helpers live in [`vault`]; per-secret Gauge checks use
//! [`actor_can_secret`]. Low-level seal/unseal is in [`crypto`]. Backend kind selection uses
//! [`secret_backend`] (Valence sealed store by default; cloud/external kinds fail closed);
//! env key classification uses [`bootstrap_trust`].
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
//! [`reveal_vault_secret`] (authorization comes from the store's request actor). Match
//! [`NeutrinoError`] at the host edge (`NotFound` / `AccessDenied` / `Validation` / …).
//!
//! ```ignore
//! use neutrino::{
//!     create_vault_secret, reveal_vault_secret, store_from_valence_for_request,
//!     NeutrinoError,
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
//! match reveal_vault_secret(&store, secret_id).await {
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
//! Optional [`list_vault_secrets`] `scope_prefix` only narrows which metadata rows are
//! returned; it is not a Gauge View check. Callers who omit the prefix still see the full
//! browsable list.
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
//! Failures return [`NeutrinoError::AccessDenied`]. Next: [filter vault list by scope prefix](#filter-vault-list-by-scope-prefix), or [grant access](#grant-access-to-a-secret).
//!
//! ## Filter vault list by scope prefix
//!
//! Product UIs (Finance feeds, Gluon providers) deep-link the Neutrino vault with a
//! `scope_prefix` query so operators see credentials for one product path instead of
//! every secret in the cell. Pass the same prefix into [`list_vault_secrets`] (or
//! [`list_secrets`]); matching uses [`scope_path_matches_prefix`] so a prefix cannot
//! accidentally include a sibling path segment.
//!
//! **Prerequisites:** `feature = "ssr"`, session Valence, coarse `SecretsRead` on the
//! product server fn when calling through `neutrino-app`.
//!
//! ```ignore
//! use neutrino::list_vault_secrets;
//!
//! let rows = list_vault_secrets(&session_v, Some("/finance/org_abc/feeds")).await?;
//! assert!(rows.iter().all(|r| {
//!     r.scope_path == "/finance/org_abc/feeds"
//!         || r.scope_path.starts_with("/finance/org_abc/feeds/")
//! }));
//!
//! let all = list_vault_secrets(&session_v, None).await?;
//! assert!(all.len() >= rows.len());
//! ```
//!
//! Empty or whitespace prefixes behave like `None` (full list). A prefix with no matching
//! rows returns `Ok(vec![])` — not an error. Valence query failures still map to
//! [`NeutrinoError`]. Next: [seal or put](#seal-or-put-secret) under that path, or open
//! `/secrets?scope_prefix=…` in `neutrino-app`.
//!
//! ## Grant access to a secret
//!
//! Per-secret access grants let you give one teammate rights to one Neutrino
//! secret without opening the whole vault. Add them to
//! `rp_owners_neutrino_secret_{id}` for full maintainer rights, or grant a
//! single action name for least privilege.
//!
//! **Prerequisites:** `feature = "ssr"`, Gauge catalog seeded, a secret id you
//! already sealed.
//!
//! ```ignore
//! use gauge::service;
//! service::grant_permission_to_user(&valence, &permission_name, "user:bob").await?;
//! assert!(service::actor_can(&valence, &permission_name).await?);
//! ```
//!
//! ## Control-plane secret lane
//!
//! Boot jobs and background workers that start as `Actor::System` use
//! [`ValenceSealedStore`] with System ORM Valence so seal/reveal can run outside a
//! browser session. `SecretStore::get` decrypts any id without a Gauge check —
//! callers must only pass trusted ids. Call this lane at worker startup or in a
//! Chronon/Boson job after Gauge bootstrap, not mid-request from a session actor.
//!
//! **Prerequisites:** System Valence from process start, master key resolved,
//! `feature = "ssr"`.
//!
//! ```ignore
//! use neutrino::{ValenceSealedStore, secret_store::SecretStore};
//! let store = ValenceSealedStore { valence: system_arc, request_actor: Some("service:boot".into()) };
//! let secret_ref = store.put_or_reuse(put_req).await?;
//! assert!(!secret_ref.id.0.is_empty());
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
//! ## Lease secret
//!
//! A lease hands short-lived plaintext to a named consumer (`leased_to`) for env injection
//! or Parton Deploy. It is Reveal-gated like vault reveal, returns [`secret_store::SecretLease`]
//! (`Zeroizing` plaintext, `lease_id`, `expires_at`, version), and never logs the bytes.
//! After rotate, the prior version can sit in `grace` so a failed apply can still lease it
//! via [`secret_store::SecretStore::extend_grace`]. Call once when the worker applies a
//! rotate event (Boson / control-plane System); interactive UI should keep using reveal.
//!
//! **Prerequisites:** authorized Reveal (or System apply) actor; an active or grace version.
//!
//! ```ignore
//! use neutrino::secret_store::{LeaseRequest, SecretStore};
//! use std::time::Duration;
//!
//! let lease = store
//!     .lease(LeaseRequest {
//!         secret_id: secret_ref.id.clone(),
//!         version: None,
//!         leased_to: format!("gluon-agent-{cell}"),
//!         ttl: Duration::from_secs(300),
//!     })
//!     .await?;
//! assert!(!lease.plaintext.is_empty());
//! // Assemble BOOTSTRAP_DB_LOGICALS_JSON; never log plaintext.
//! ```
//!
//! When Deploy or db-ready fails after rotate, extend grace so the prior version stays
//! leaseable while operators investigate (no auto-unrotate):
//!
//! ```ignore
//! use neutrino::secret_store::{LeaseRequest, SecretId, SecretStore};
//! use std::time::Duration;
//!
//! store
//!     .extend_grace(&secret_ref.id, 86_400, "gluon.neutrino_rotation_apply")
//!     .await?;
//! let prior = store
//!     .lease(LeaseRequest {
//!         secret_id: secret_ref.id.clone(),
//!         version: Some(prior_version),
//!         leased_to: format!("gluon-agent-{cell}"),
//!         ttl: Duration::from_secs(300),
//!     })
//!     .await?;
//! assert!(!prior.plaintext.is_empty());
//! ```
//!
//! Archived-only versions and missing ids return [`NeutrinoError::InvalidState`] /
//! [`NeutrinoError::NotFound`]. After a DB-scoped vault rotate, the product app publishes
//! Photon `neutrino.secret.rotated` so Gluon can lease and Deploy updated credentials.
//! Interactive UI continues at [reveal](#reveal-secret).
//!
//! ## Delete secret
//!
//! Secret deletion is the permanent retirement path for a stored credential. It removes
//! the secret row and version ciphertext via Valence
//! [`Model::delete_now`](valence::Model::delete_now) (synchronous DAG), then tears down the
//! Gauge per-secret bundle. Umbrella groups, shared principals, `CreateNeutrinoSecrets`,
//! and audit rows remain.
//!
//! **Prerequisites:** authorized Delete (or System) actor; existing secret id.
//!
//! ```ignore
//! use neutrino::secret_store::SecretStore;
//! use gauge::resource_permissions::delete_resource_permission_bundle;
//!
//! let result = store.delete(&secret_ref.id).await;
//! assert!(result.is_ok());
//! let _: () = result?;
//! // Bundle teardown runs inside delete; callers that tear down ACL alone use:
//! // delete_resource_permission_bundle(&valence, …).await?;
//! assert!(matches!(Ok::<(), ()>(()), Ok(())));
//! ```
//!
//! Failures return [`NeutrinoError`] when the actor lacks Delete, the id is unknown,
//! or the store write fails. Subsequent `get` / reveal calls also fail after a
//! successful delete. Next: list remaining rows with [`list_secrets`] (`None` for the full
//! vault, or a `scope_prefix` — [filter vault list](#filter-vault-list-by-scope-prefix)), or
//! return to [seal or put](#seal-or-put-secret).
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
//! [`resolve_master_key`] loads the process master key before any seal or reveal.
//! Default source is `NEUTRINO_KEY_SOURCE=env` (or unset): 32-byte hex via
//! `NEUTRINO_MASTER_KEY`, or a weak UTF-8 escape when explicitly allowed. With a
//! `kms-*` or `hsm-*` Cargo feature, set `NEUTRINO_KEY_SOURCE` to `aws-kms`, `gcp-kms`,
//! `vault-transit`, `pkcs11`, or `tpm` and provide `NEUTRINO_MASTER_KEY_WRAPPED` plus
//! provider env vars — the provider unwraps the master key only; customer secrets remain
//! in Valence. Resolve during process startup before constructing [`ValenceSealedStore`]
//! or calling [`seed_bootstrap_secrets_from_env`]. [`master_key_from_env`] remains the
//! env-only helper.
//!
//! **Prerequisites:** `NEUTRINO_MASTER_KEY` set (env source), or wrapped key + provider
//! config when using a KMS or HSM source.
//!
//! ```ignore
//! use neutrino::resolve_master_key;
//!
//! // std::env::set_var("NEUTRINO_MASTER_KEY", "<64 hex chars>");
//! let key = resolve_master_key().await?;
//! assert_eq!(key.len(), 32);
//! ```
//!
//! KMS variant (`feature = "kms-aws"`): set `NEUTRINO_KEY_SOURCE=aws-kms`,
//! `NEUTRINO_MASTER_KEY_WRAPPED` (base64 ciphertext), and `NEUTRINO_AWS_KMS_KEY_ID`, then call
//! the same [`resolve_master_key`].
//!
//! ```ignore
//! // cargo build -p neutrino --features kms-aws
//! // std::env::set_var("NEUTRINO_KEY_SOURCE", "aws-kms");
//! // std::env::set_var("NEUTRINO_MASTER_KEY_WRAPPED", "<base64>");
//! // std::env::set_var("NEUTRINO_AWS_KMS_KEY_ID", "alias/neutrino");
//! use neutrino::resolve_master_key;
//!
//! let key = resolve_master_key().await?;
//! assert_eq!(key.len(), 32);
//! ```
//!
//! PKCS#11 variant (`feature = "hsm-pkcs11"`): set `NEUTRINO_KEY_SOURCE=pkcs11`,
//! `NEUTRINO_MASTER_KEY_WRAPPED` (RSA-OAEP ciphertext of a 32-byte MEK),
//! `NEUTRINO_PKCS11_MODULE`, `NEUTRINO_PKCS11_PIN`, and `NEUTRINO_PKCS11_KEY_LABEL`.
//!
//! ```ignore
//! // cargo build -p neutrino --features hsm-pkcs11
//! // std::env::set_var("NEUTRINO_KEY_SOURCE", "pkcs11");
//! // std::env::set_var("NEUTRINO_MASTER_KEY_WRAPPED", "<base64>");
//! // std::env::set_var("NEUTRINO_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so");
//! // std::env::set_var("NEUTRINO_PKCS11_PIN", "<pin>");
//! // std::env::set_var("NEUTRINO_PKCS11_KEY_LABEL", "neutrino-mek");
//! use neutrino::resolve_master_key;
//!
//! let key = resolve_master_key().await?;
//! assert_eq!(key.len(), 32);
//! assert_eq!(key.provenance().source_label(), "hsm");
//! ```
//!
//! TPM variant (`feature = "hsm-tpm"`): set `NEUTRINO_KEY_SOURCE=tpm`,
//! `NEUTRINO_MASTER_KEY_WRAPPED`, `NEUTRINO_TPM_TCTI`, and `NEUTRINO_TPM_KEY_HANDLE`.
//!
//! ```ignore
//! // cargo build -p neutrino --features hsm-tpm
//! // std::env::set_var("NEUTRINO_KEY_SOURCE", "tpm");
//! // std::env::set_var("NEUTRINO_MASTER_KEY_WRAPPED", "<base64>");
//! // std::env::set_var("NEUTRINO_TPM_TCTI", "device:/dev/tpmrm0");
//! // std::env::set_var("NEUTRINO_TPM_KEY_HANDLE", "0x81000001");
//! use neutrino::resolve_master_key;
//!
//! let key = resolve_master_key().await?;
//! assert_eq!(key.len(), 32);
//! ```
//!
//! On failure, inspect [`MasterKeyError`] variants (`NotSet`, `Empty`, `InvalidHex`,
//! `WeakKeyRejected`, `Config`, `Provider`, `Unavailable`, `FeatureDisabled`). Next:
//! [Gauge bootstrap](#gauge-bootstrap-at-boot) if not done, then
//! [bootstrap env seed](#bootstrap-env-seed).
//!
//! ## Feature flags
//!
//! | Flag | What it enables |
//! |------|-----------------|
//! | *(default)* | Crypto helpers, [`key_source`], [`bootstrap_trust`], [`secret_backend`] kind selector (Valence sealed store default; cloud kinds unsupported) |
//! | `ssr` | Valence models, [`ValenceSealedStore`], [`vault`], Gauge wiring, instrumentation |
//! | `rbac-tests` | Extra Gauge RBAC integration tests (`ssr` + lepton/gauge graph) |
//! | `kms-aws` | AWS KMS [`KeySource`] unwrap (`AwsKmsKeySource`) |
//! | `kms-gcp` | GCP Cloud KMS [`KeySource`] unwrap |
//! | `kms-vault-transit` | HashiCorp Vault Transit [`KeySource`] unwrap |
//! | `hsm-pkcs11` | PKCS#11 `KeySource` unwrap (`Pkcs11KeySource`) |
//! | `hsm-tpm` | TPM 2.0 `KeySource` unwrap (`TpmKeySource`) |
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
//! Master key errors use [`MasterKeyError`]. Store and vault APIs return
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
pub mod db_scope;
#[cfg(feature = "ssr")]
pub mod embedded_surreal;
/// Generated Valence models (schema codegen). Prefer [`vault`] / [`sealed_store`] APIs.
#[cfg(feature = "ssr")]
#[doc(hidden)]
pub mod generated;
#[cfg(feature = "ssr")]
pub mod instrumentation;
#[cfg(feature = "ssr")]
mod master_key_meta;
#[cfg(feature = "ssr")]
mod privacy_policies;
#[cfg(feature = "photon")]
pub mod rotation_event;
#[cfg(feature = "ssr")]
mod schemas;
#[cfg(feature = "ssr")]
pub mod scope_prefix;
#[cfg(feature = "chronon")]
pub mod scripts;
#[cfg(feature = "ssr")]
pub mod sealed_store;
#[cfg(feature = "ssr")]
pub mod vault;
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
pub use db_scope::is_db_scoped_creds_path;
pub use error::{NeutrinoError, NeutrinoResult};
pub use key_source::{
    clear_master_key_cache, master_key_from_env, resolve_master_key, EnvKeySource, HsmBackend,
    KeySource, KeySourceKind, MasterKeyError, MasterKeyProvenance, ResolvedMasterKey,
    WrappedKeyDecryptor,
};
#[cfg(feature = "photon")]
pub use rotation_event::{
    publish_if_db_scoped_secret_rotated, publish_neutrino_secret_rotated,
    publish_neutrino_secret_rotated_with_scope, NeutrinoSecretRotated,
};
#[cfg(feature = "ssr")]
pub use scope_prefix::scope_path_matches_prefix;
#[cfg(feature = "ssr")]
pub use sealed_store::{list_secrets, ListedSecret, ValenceSealedStore};
pub use secret_backend::{
    ensure_secret_backend_supported, secret_backend_kind_from_env, uses_neutrino_sealed_store,
    SecretBackendKind,
};
pub use secret_store::{SecretId, SecretRef, SecretVersionId};
#[cfg(feature = "ssr")]
pub use vault::{
    create_vault_secret, delete_vault_secret, list_vault_secrets, neutrino_vault_ping,
    reveal_vault_secret, rotate_vault_secret, store_from_valence, store_from_valence_for_request,
    RevealedVaultSecret, VaultSecretRow,
};
#[cfg(feature = "ssr")]
pub use vault_gauge::{
    actor_can_secret, assert_neutrino_catalog_seeded, create_initial_neutrino_groups,
    ensure_secret_permission_bundle, CREATE_NEUTRINO_SECRETS, NEUTRINO_SECRET,
    NEUTRINO_SECRET_RESOURCE,
};
