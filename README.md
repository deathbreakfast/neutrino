# Neutrino

[![CI](https://github.com/unified-field-dev/neutrino/actions/workflows/ci.yml/badge.svg)](https://github.com/unified-field-dev/neutrino/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[GitHub](https://github.com/unified-field-dev/neutrino) · `cargo doc -p neutrino --features ssr --open`

## About

Neutrino is the Unified Field **encrypted secrets vault**: seal payloads at rest in
Valence (XChaCha20-Poly1305), hash-chain audit events, bootstrap env material into
the store, and wire Gauge host permissions for create / list / reveal / rotate /
delete.

- **Domain (`neutrino`)** — `ValenceSealedStore` / `SecretStore`, product vault APIs,
  Gauge host wiring, bootstrap trust classification and seeding
- **Telemetry (`neutrino-spectra-telemetry`)** — Spectra schemas, Photon topics, and
  secret-access field helpers for host composition

Crate-root rustdoc owns the Features inventory and primary-task guides. Start at
`cargo doc -p neutrino --features ssr --open`.

Operator pages (`NeutrinoRoutes` at `/secrets`) live in
[neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app).

## Getting started

```toml
[dependencies]
# Tracks main; pin rev for reproducible production builds.
neutrino = { git = "https://github.com/unified-field-dev/neutrino", package = "neutrino", branch = "main" }
neutrino-spectra-telemetry = { git = "https://github.com/unified-field-dev/neutrino", package = "neutrino-spectra-telemetry", branch = "main" }
```

Two lanes after `create_initial_neutrino_groups`:

1. **Control-plane seal** — System ORM Valence + `request_actor` audit (`ValenceSealedStore` / `SecretStore`)
2. **Product vault** — `store_from_valence_for_request` + `vault::*` with `VaultAccessContext` (UI / session)

Control-plane seal (SSR):

```rust,ignore
use neutrino::secret_store::{PutSecretRequest, SecretStore};
use neutrino::{create_initial_neutrino_groups, ValenceSealedStore};
use valence::Actor;
use std::sync::Arc;

create_initial_neutrino_groups(&valence).await?;
let store = ValenceSealedStore {
    valence: Arc::new(valence.with_actor(Actor::System {
        operation: "seal_smtp".into(),
    })),
    request_actor: Some("service:smtp-boot".into()),
};
let secret_ref = store
    .put(PutSecretRequest {
        name: "smtp_password".into(),
        scope_path: "/uf-notifications/smtp".into(),
        kind: "password".into(),
        plaintext: b"correct-horse-battery-staple".to_vec(),
        owner_actor: "service:smtp-boot".into(),
    })
    .await?;
```

Match `NeutrinoError` at host edges (`NotFound` / `AccessDenied` / `Validation`). See crate-root
rustdoc for the product-vault example and module map.

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-neutrino
cargo test -p neutrino --features ssr --lib --test vault_crud_contract --test sealed_store_idempotent --test vault_authz_contract --test vault_security_remediation
```

## Workspace

| Crate | Role |
|-------|------|
| [`neutrino`](neutrino/) | Sealed store, vault APIs, bootstrap/trust, Gauge wiring |
| [`neutrino-spectra-telemetry`](neutrino-spectra-telemetry/) | Spectra schemas, topics, secret-access field helpers |

## Examples

| Host | When to use | Command | Success | Look next |
|------|-------------|---------|---------|-----------|
| [`vault-host`](examples/vault-host/) | Bootstrap → role gate → rotate/reveal | `CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=target-neutrino cargo run -p vault-host` | Bootstrap + gate + rotate/reveal | Mount `NeutrinoRoutes` from neutrino-uf-app |

Copy `Cargo.toml` + `main.rs` from the host README. More examples:
[`examples/README.md`](examples/README.md).

## Security

Vault authz (Gauge + `VaultAccessContext`), master-key handling, and reporting:
[`SECURITY.md`](SECURITY.md). Report vulnerabilities privately — do not open a
public issue for security-sensitive reports.

## Verify

Requires nightly (Leptos workspace deps).

GitHub Actions (`.github/workflows/ci.yml`) runs the CI subset from
[`docs/VERIFICATION.md`](docs/VERIFICATION.md): fmt, scoped clippy on `neutrino`
(+ teaching host), contract + RBAC tests, `neutrino-spectra-telemetry`, `vault-host`
check/run, and neutrino rustdoc with broken-intra-doc-link deny.

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-neutrino
cargo fmt -p neutrino -p vault-host -- --check
cargo clippy -p neutrino --features ssr --lib --test vault_crud_contract --test sealed_store_idempotent --test vault_authz_contract --test vault_security_remediation -- -D warnings
cargo clippy -p vault-host --all-targets -- -D warnings
cargo test -p neutrino --test workspace_members --test product_surface
cargo test -p neutrino --features ssr --lib --test vault_crud_contract --test sealed_store_idempotent --test vault_authz_contract --test vault_security_remediation
cargo test -p neutrino --features rbac-tests --test vault_gauge_authz --test vault_server_rbac --test security_contract --test access_matrix_contract
cargo test -p neutrino-spectra-telemetry
cargo check -p vault-host
cargo run -p vault-host
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p neutrino --features ssr --no-deps
```

Teaching host success line:
`vault_host: OK — bootstrap → role gate → rotate/reveal`.
Contribute: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## FAQ

**Is it a standalone server?** No. `neutrino` is the domain library. Mount
`NeutrinoRoutes` from [neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app)
in a composite host that already wires Valence, session chrome, and Higgs.

**Do I need the admin UI?** No. Backend hosts can depend on `neutrino` alone and call
vault / `SecretStore` APIs. Mount `NeutrinoRoutes` when operators need the UI.

**What must stay in the environment?** Only bootstrap-classified keys
(`NEUTRINO_MASTER_KEY`, `BOOTSTRAP_DB_*`, setup-wizard / Parton tokens). Everything
else should migrate into the sealed store — see crate-root rustdoc and
[`bootstrap_trust`](neutrino/src/bootstrap_trust.rs).

**How does Gauge fit in?** Call `create_initial_neutrino_groups` at host bootstrap.
Create is gated by System or `CreateNeutrinoSecrets`; list/reveal/rotate/delete prefer
per-secret Gauge permissions with `VaultAccessContext` as a scope-prefix bridge.

