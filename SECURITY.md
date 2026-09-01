# Security Policy

## Supported versions

Security fixes are accepted against the latest published `0.1.x` release line of this repository's `neutrino` crate. The Orbital admin UI (`neutrino-app`) lives in the [neutrino-uf-app](https://github.com/deathbreakfast/neutrino-uf-app) composer repo.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Prefer one of the following:

1. **GitHub Security Advisories** — use [Report a vulnerability](https://github.com/unified-field-dev/neutrino/security/advisories/new) on this repository when available.
2. Contact the maintainers privately via the repository owner listed at https://github.com/unified-field-dev/neutrino.

Include:

- a description of the issue and its impact
- steps to reproduce or a proof of concept when possible
- affected crate names and versions

We will acknowledge receipt as soon as practical and coordinate a fix and disclosure timeline with you.

## Scope

In scope: vulnerabilities in this repository's published crates and documentation that could cause unsafe production defaults, plus CI/supply-chain issues in this repository.

Out of scope: vulnerabilities solely in third-party dependencies unless this project mishandles them in a security-relevant way.

## Vault authorization

Gauge permissions (`SecretsRead` / `SecretsReveal` / …) are **necessary but not
sufficient** for cross-secret access. Product vault APIs enforce
[`VaultAccessContext`](neutrino/src/vault_authz.rs):

- Owner match via `owner_subject_json.actor`
- Optional principal grants in `owner_subject_json.grants` (minimal ACL scaffolding
  until a dedicated grant UI/store ships)
- Or an allowed scope prefix (Super User break-glass uses `"/"`)

Ordinary `SecretsReveal` holders without owner/grant/prefix match are **denied**
(fail closed). The ACL manage page remains a placeholder for fine-grained editing.

`put_or_reuse` on an existing `name`+`scope_path` requires Edit (Gauge) or the same
owner/grant/prefix bridge before decrypt/rotate — `CreateNeutrinoSecrets` alone
does not authorize overwriting another principal's row.

Vault `#[server]` wrappers use `Higgs::unsafe_system_valence` for Neutrino ORM
(`SYSTEM_ONLY` schemas) after the Gauge permission gate, with request-actor audit
via `store_from_valence_for_request`.

## Master key

`NEUTRINO_MASTER_KEY` must be 64 hex characters (256-bit) in production. Non-hex
UTF-8 keys require explicit `NEUTRINO_ALLOW_WEAK_MASTER_KEY=1` (non-production
only).

## Archived version reveal

[`ValenceSealedStore::reveal_at_version`](neutrino/src/sealed_store.rs) refuses
`archived` version rows (fail closed). Only `active` (and non-archived grace, if
present) ciphertext may be decrypted; callers must use the current version or an
explicitly active pin.

## Audit append on vault mutate

Hash-chained [`NeutrinoSecretAuditEvent`](neutrino/schemas/neutrino_secret_audit_event_valence_schema.rs)
rows are required for mutating vault operations (`put`, `delete`, `rotate`). If
audit append fails, the API returns an error (fail closed). Read paths (`get`,
`reveal`) log the failure and continue so availability is not blocked by audit
storage outages.

## Client reveal transport

[`RevealedVaultSecret`](neutrino/src/vault.rs) zeroizes `plaintext_b64` on drop
and redacts it from `Debug` output. The vault UI clears reveal state when the
dialog closes.

## Secret access telemetry

UC3 `neutrino_secret_access_log` events omit `scope_path` and `secret_name` to
reduce secret metadata exposure in operational logs. Correlation uses `secret_id`,
`action`, and `version_num` only.
