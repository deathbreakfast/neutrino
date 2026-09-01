# vault-host

Encrypted vault teaching host: **bootstrap** seed → **role gate** deny → **rotate** →
**reveal**, then serve under a session-gated Axum route at **`/secrets`**.

Production Leptos hosts mount `NeutrinoRoutes` at **`/secrets`** and gate server
fns with `Secrets*` permissions. This example proves sealed-store bootstrap +
owner role gate without the SSR/WASM / Orbital graph. The oneshot path
`/secrets` matches the Orbital app id/path (`secrets` / `/secrets`).

| | |
|---|---|
| **When to use** | First smoke of Neutrino sealed-store + authz in an embedded host |
| **Command** | `CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=target-neutrino cargo run -p vault-host` |
| **Success** | Stdout: `vault_host: OK — bootstrap → role gate → rotate/reveal` |
| **Look next** | Mount guide in [neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app) rustdoc (`NeutrinoRoutes` + Gauge `Secrets*` grants) |

**Open first:** [`src/main.rs`](src/main.rs)

## Copy into your host

| File | What to take |
|------|----------------|
| This [`Cargo.toml`](Cargo.toml) | Axum oneshot shape + `neutrino` / `gauge` / `lepton` `ssr` (bootstrap + create gate) |
| [`src/main.rs`](src/main.rs) | `create_initial_neutrino_groups`, creators membership, bootstrap/rotate/reveal, protect `/secrets` |

Domain seal (Leptos-free; System ORM + request_actor audit):

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
```

At host boot, call `create_initial_neutrino_groups` before product APIs that
auto-ensure per-secret Gauge bundles. For Orbital UI mount steps (deps, hydrate,
`NeutrinoPermission` grants), use the **Mount Neutrino routes** guide in
[neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app)
(`cargo doc -p neutrino-app --features ssr`). Shell chrome (layout, fonts,
Axum + Leptos boot) can start from
[`shell-chrome-host`](https://github.com/unified-field-dev/unified-field-product/tree/main/examples/shell-chrome-host).

## Run

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-neutrino
cargo check -p vault-host
cargo run -p vault-host
```

**Success:** stdout prints `vault_host: OK — bootstrap → role gate → rotate/reveal`.

## Hydrate / browser

Out of gate for this host. Full vault UI needs a product binary with
`cargo-leptos`, `wasm32`, session chrome, and a working Orbital / `uf-product`
graph. Prefer the oneshot above.
