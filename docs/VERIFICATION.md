# neutrino verification

Re-run after code or doc changes. This workspace is the Neutrino product
(`neutrino` sealed vault). The Leptos admin UI (`neutrino-app` / `NeutrinoRoutes`) lives
in [neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app). Layer 1
covers the product-local vault API that backs `neutrino-app` server functions
(`create_vault_secret`, `list_vault_secrets`, `reveal_vault_secret`,
`rotate_vault_secret`, `delete_vault_secret`, `neutrino_vault_ping`), plus
source-text UI surface contracts for `neutrino-app`. Playwright UI e2e lives in
the [neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app) composer
(`neutrino-uf-app-e2e`). No IsolatedLab `*-e2e` crate or cloud campaign suite is
required for this product. Tests never log plaintext secret values.

## Environment

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-neutrino
```

## Teaching host

Axum oneshot under [`examples/vault-host`](../examples/vault-host/).
Copy table + product mount sketches live in that host README.

```bash
cargo check -p vault-host
cargo run -p vault-host
```

Success line: `vault_host: OK — bootstrap → role gate → rotate/reveal`.
Hydrate/browser is out of gate for the oneshot (`cargo-leptos` + `wasm32` +
Orbital / `uf-product` belong to a composite product host).

## Rustdoc policy

Workspace `Cargo.toml` currently **allows** `rustdoc::broken_intra_doc_links` by
default. For local deny checks on the domain crate:

```bash
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p neutrino --features ssr --no-deps
```

`neutrino-app` package rustdoc remains pin-dependent on Orbital / `uf-product`
and is not required for vault-contract CI. `#![allow(missing_docs)]` on the UI
crate is intentional.

## Layer 1 — Unit + integration (CI)

GitHub Actions (`.github/workflows/ci.yml`) covers this Layer 1 subset plus the
teaching host and neutrino rustdoc gate below. It does not build `neutrino-app`
or run `--all-targets` clippy on `neutrino`.

Domain workspace (no `neutrino-app` package in this repository). `product_surface`
asserts route and permission needles against
[neutrino-app](https://github.com/deathbreakfast/neutrino-uf-app) sources without
compiling the UI graph:

```bash
cargo test -p neutrino --test workspace_members --test product_surface
```

Backend contracts (preferred path; no UI graph):

```bash
cargo fmt -p neutrino -p vault-host -- --check
cargo clippy -p neutrino --features ssr --lib --test vault_crud_contract --test sealed_store_idempotent --test vault_authz_contract --test vault_security_remediation -- -D warnings
cargo clippy -p vault-host --all-targets -- -D warnings
cargo test -p neutrino --features ssr --lib --test vault_crud_contract --test sealed_store_idempotent --test vault_authz_contract --test vault_security_remediation
cargo test -p neutrino --features rbac-tests --test vault_gauge_authz
cargo test -p neutrino --features rbac-tests --test vault_server_rbac
cargo test -p neutrino --features rbac-tests --test security_contract --test access_matrix_contract
cargo test -p neutrino-spectra-telemetry
```

`neutrino-app` (Leptos UI + Higgs `#[server]` wrappers) may fail to compile when
the `uf-product` / Orbital graph is broken upstream. Prefer the
`neutrino` crate for CI contract gates; treat UI-crate compile failures as a
separate host product issue, not a vault-domain gap. Do not run `--all-targets`
clippy on `neutrino` for the preferred CI path — older integ suites and the UI
graph are out of this gate.

Full workspace (domain + vault-host). May fail when the
`uf-product` / Leptos UI graph is broken upstream — that is a separate host
product UI compile issue, not a vault contract gap:

```bash
cargo clippy --workspace --all-targets --features ssr -- -D warnings
cargo test --workspace --features ssr
```

## Layer 2 — E2E

Domain vault CRUD happy/sad contracts stay in Layer 1 (`vault_crud_contract`,
authz/RBAC suites). Playwright UI e2e (Higgs `#[server]` + Secrets pages) runs
from the composer:

```bash
# neutrino-uf-app repo — see https://github.com/deathbreakfast/neutrino-uf-app/blob/main/docs/VERIFICATION.md
cargo leptos end-to-end --project neutrino-uf-app-e2e
```

Host listens on `127.0.0.1:3160`. Scenario catalog:
[neutrino-uf-app-e2e README](https://github.com/deathbreakfast/neutrino-uf-app/blob/main/neutrino-uf-app-e2e/README.md).
Domain `product_surface` needles are composition smoke only — they do not
substitute for composer Playwright.

## Layer 3 — Cloud campaigns + performance

**Waived.** This workspace; no cloud resources or Criterion benches.
Correctness is in-process against an embedded SQLite `:memory:` Valence
(aligned with Neutrino schema `SQLITE_ENGINE_ID`) with `NEUTRINO_MASTER_KEY`
set for the test process. Defer any soak unless a shared hot path changes.

## Notes

- Prefer `cargo test -p neutrino --features ssr --test vault_crud_contract` for
  backend contract CI when the UI dependency graph fails to compile — report
  that separately from vault contract results.
- Tests may `unwrap`/`expect`; production server fns map failures to
  `ServerFnError` (no ordinary-path unwrap).
- Sad-path assertions check message content (stronger than `is_err()` alone).
- Happy-path tests are named `*_happy_path` so audits detect them.
- Never log or format plaintext secret values in test failures or error
  messages; compare bytes/base64 only inside assertions.
- `neutrino-app` routes call the `#[server]` fns; those fns are thin Higgs
  wrappers over `neutrino::vault`.

## leptos-lints (local / CI job `leptos-lints`)

Needs `cargo-dylint` / `dylint-link` 6.0.1 and toolchain `nightly-2025-05-14`
(leptos-lints@v0.1.2 pin). Workspace metadata lives in root `Cargo.toml`.

```bash
# cargo install cargo-dylint --locked --version 6.0.1
# cargo install dylint-link --locked --version 6.0.1
# rustup toolchain install nightly-2025-05-14 --component rustc-dev,llvm-tools-preview

# neutrino-uf-app repo root:
cargo dylint --all -p neutrino-app --no-deps -- --features hydrate
```

`neutrino-app` hydrate dylint (composer workspace) may fail when `uf-product` / Orbital
duplex under the dylint nightly — same class of host-pin issue as full UI
`cargo check`. Treat as a separate UI graph issue; Layer 1 vault contracts do
not require it.