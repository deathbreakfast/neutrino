# Contributing to Neutrino

## Development setup

1. Clone [unified-field-dev/neutrino](https://github.com/unified-field-dev/neutrino)
2. Install Rust **nightly** (see [`rust-toolchain.toml`](rust-toolchain.toml); Leptos workspace deps require it)
3. From the repository root:

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-neutrino
cargo fmt -p neutrino -- --check
cargo test -p neutrino --features ssr --lib --test vault_crud_contract --test sealed_store_idempotent --test vault_authz_contract --test vault_security_remediation
```

Full gates: [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Security
reports: [`SECURITY.md`](SECURITY.md).

## Pull requests

- Prefer small, focused PRs.
- Update [`README.md`](README.md) when public API or UI flows change.
