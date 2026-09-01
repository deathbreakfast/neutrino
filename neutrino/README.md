# Neutrino

Encrypted-at-rest secrets with audit chaining.

Crate-root rustdoc is the discovery source of truth (Features, Getting started,
primary-task guides, Feature flags, Examples):

```bash
cargo doc -p neutrino --features ssr --open
```

- [`ValenceSealedStore`] / [`SecretStore`] — XChaCha20-Poly1305 sealed payloads in Valence
- [`seed_bootstrap_secrets_from_env`] — copy bootstrap-only env material into the vault
- [`master_key_from_env`] / [`bootstrap_trust`] — master key and env-key classification

## Documentation

- Crate-root rustdoc — Features inventory and primary-task guides
- Root product README: [`../README.md`](../README.md)
