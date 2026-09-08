# neutrino verification

Re-run after code or doc changes. This workspace is the Neutrino product
(`neutrino` sealed vault). The Leptos admin UI (`neutrino-app` / `NeutrinoRoutes`) lives
in [neutrino-uf-app](https://github.com/unified-field-dev/neutrino-uf-app). Layer 1
covers the product-local vault API that backs `neutrino-app` server functions
(`create_vault_secret`, `list_vault_secrets`, `reveal_vault_secret`,
`rotate_vault_secret`, `delete_vault_secret`, `neutrino_vault_ping`), plus
source-text UI surface contracts for `neutrino-app`. Playwright UI e2e lives in
the [neutrino-uf-app](https://github.com/unified-field-dev/neutrino-uf-app) composer
(`neutrino-uf-app-e2e`). No IsolatedLab `*-e2e` crate or cloud campaign suite is
required for this product. Tests never log plaintext secret values.

## Environment

Match [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) workflow `env` and
toolchain pin:

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-neutrino
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export RUSTFLAGS="-D warnings"
rustup toolchain install nightly-2026-08-07
# Prefer this toolchain for the gates below (same pin as CI).
```

## PR CI parity

Required PR jobs in `ci.yml` and the local commands that match them:

| CI job | Local command / notes |
|--------|------------------------|
| `fmt` | `cargo fmt -p neutrino -p vault-host -- --check` on `nightly-2026-08-07` |
| `clippy` | Clippy clears `RUSTFLAGS` then `-D warnings` on the CLI; same package/test set as Layer 1 below |
| `test` | Sibling-source + vault + Gauge RBAC suites + `cargo test -p neutrino-spectra-telemetry` + vault-host check/run |
| `docs` | `RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p neutrino --features ssr --no-deps` |
| `leptos-lints` | `cargo dylint --all -p neutrino --no-deps` (dylint 6.0.1 + `nightly-2025-05-14`; see below) |

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
[neutrino-app](https://github.com/unified-field-dev/neutrino-uf-app) sources without
compiling the UI graph:

```bash
cargo test -p neutrino --test workspace_members --test product_surface
```

TM-12 step-up inventory + domain reveal/break-glass (focused):

```bash
cargo test -p neutrino --test product_surface step_up -- --nocapture
cargo test -p neutrino --test product_surface list_vault_secrets_must_not -- --nocapture
cargo test -p neutrino --features ssr --test vault_authz_contract owner_reveal -- --nocapture
cargo test -p neutrino --features ssr --test vault_authz_contract reveal_denied -- --nocapture
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

### neutrino-spectra-telemetry

Parent CI already runs `cargo test -p neutrino-spectra-telemetry`. Focused
fmt/clippy for that package (optional local slice):

```bash
cargo fmt --all --check
cargo clippy -p neutrino-spectra-telemetry --all-targets -- -D warnings
cargo test -p neutrino-spectra-telemetry
```

#### TEST_MAP

| Behavior | Level | Happy | Sad | Notes |
|----------|-------|-------|-----|-------|
| `truncate_message` / `secret_access_log_fields` | unit | short message preserved; full log JSON shape | oversize `error_message` clipped to 512 with `…` | `events::tests` |
| `sink_forward::field_str` / `field_i64` | unit | string/bool/number coercions | missing / null / array / bad parse → `""` / `0` | private helpers |
| Typed recorders / loggers | integ | `NeutrinoSecretAccessRecorder` + `NeutrinoSecretAccessLogLogger` emit | empty labels / empty logger fields accepted | no Spectra sink required; non-panic contracts |
| `sink_forward` | integ | known counter + event table | unknown name ignored; missing fields default | consumer / sink_forward |
| Topic constants | integ | `spectra.metric.*` / `spectra.event.*` with `neutrino_secret_access*` | — | Photon wire names from spectra macros |
| Field builders (integ mirror) | integ | `secret_access_log_fields` shape | truncate via public helpers | `tests/api.rs` |

Notes for this crate:

- No `*_TELEMETRY` install switch: hosts call field builders / typed recorders at
  their own interception points.
- Emit helpers under Spectra `try_*` gate assert contracts/non-panic rather than
  captured Spectra sink rows.
- Sad-path tests are named with `_sad` / `happy_and_sad` so audits detect them;
  they assert concrete defaults and truncation bounds, beyond smoke-only checks.

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
# neutrino-uf-app repo — see https://github.com/unified-field-dev/neutrino-uf-app/blob/main/docs/VERIFICATION.md
cargo leptos end-to-end --project neutrino-uf-app-e2e
```

Host listens on `127.0.0.1:3160`. Scenario catalog:
[neutrino-uf-app-e2e README](https://github.com/unified-field-dev/neutrino-uf-app/blob/main/neutrino-uf-app-e2e/README.md).
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

## leptos-lints (required PR job `leptos-lints`)

Needs `cargo-dylint` / `dylint-link` 6.0.1 and toolchain `nightly-2025-05-14`
(leptos-lints@v0.1.2 pin). Workspace metadata lives in root `Cargo.toml`.
CI runs this against the domain `neutrino` package (composer hydrate dylint lives
in neutrino-uf-app).

```bash
# cargo install cargo-dylint --locked --version 6.0.1
# cargo install dylint-link --locked --version 6.0.1
# rustup toolchain install nightly-2025-05-14 --component rustc-dev,llvm-tools-preview

export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
export RUSTFLAGS="-D warnings -Zcrate-attr=feature(stdarch_x86_avx512)"
cargo dylint --all -p neutrino --no-deps
```