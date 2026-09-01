# Examples

Runnable teaching hosts for this product. Each card: when to use · command ·
success · look next. Copy `Cargo.toml` + `main.rs` into your composite host.
UI mount steps live in [neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app)
rustdoc (**Mount Neutrino routes**).

## Canonical path

### `vault-host` — bootstrap → role gate → rotate/reveal

**Teaches:** bootstrap seeding, per-secret role gate, rotate, and reveal under
protected `/secrets`. Inventory names match the `secrets` `uf_app!` id/path
(`/secrets`) and `NeutrinoPermission` (`SecretsRead`, …).

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-neutrino
cargo run -p vault-host
```

**Success:** stdout prints `vault_host: OK — bootstrap → role gate → rotate/reveal`.

**Next step:** Follow the **Mount Neutrino routes** guide in
[neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app)
(`cargo doc -p neutrino-app --features ssr`). Domain copy table:
[`vault-host/README.md`](vault-host/README.md).

| Host | When to use | Command | Success | Look next |
|------|-------------|---------|---------|-----------|
| [`vault-host`](vault-host/) | Encrypted vault happy path | `cargo run -p vault-host` | Bootstrap + gate + rotate/reveal | neutrino-uf-app mount guide |
