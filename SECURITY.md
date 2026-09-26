# Security Policy

## Supported versions

Security fixes are accepted against the latest published `0.1.x` release line of this repository's `neutrino` crate. The Orbital admin UI (`neutrino-app`) lives in the [neutrino-uf-app](https://github.com/unified-field-dev/neutrino-uf-app) composer repo.

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
sufficient** for cross-secret access. Product vault APIs enforce per-secret Gauge
grants on the store's request actor (`actor_can_secret` / Valence privacy):

- Owners-group membership from `ensure_secret_permission_bundle` after put
- Explicit per-secret action grants (`View` / `Reveal` / `Edit` / `Delete`)
- Super User (`super_user_group`) as unconditional break-glass

Ordinary `SecretsReveal` holders without a per-secret Reveal grant are **denied**
(fail closed). Operators manage fine-grained grants on `/secrets/acl`
(`AclManagePage`: list, grant, and revoke per-secret Gauge actions).

`put_or_reuse` on an existing `name`+`scope_path` requires Edit (Gauge) before
decrypt/rotate — `CreateNeutrinoSecrets` alone does not authorize overwriting
another principal's row.

Vault product server functions keep the **session Valence** after the Gauge
permission gate and drive ORM access under that actor (no mid-request
`unsafe_system_valence`). Request-actor audit labels come from
`store_from_valence_for_request`. Product-surface tests forbid System elevation
in the live vault wrappers.

### Action verification (Tier A)

`reveal_vault_secret`, `rotate_vault_secret`, `delete_vault_secret`, and
`create_vault_secret` require a recent TOTP step-up (session sudo window) via
`#[uf_product_macros::server(..., step_up)]` in addition to Gauge coarse
permissions and per-secret grants. Reveal always takes an explicit `totp_code`
and runs `verify_fresh_totp` (`step_up = "fresh"`), so a valid window alone is
not enough — including Super User break-glass. `list_vault_secrets` and
`neutrino_vault_ping` stay window-free. `list_vault_secrets` accepts an optional
`scope_prefix` that narrows browsable metadata by path; omit it for the full list.
Prefix filtering is not a Gauge View check — coarse `SecretsRead` still applies.

## Master key

By default Neutrino loads the process master key from `NEUTRINO_MASTER_KEY`
(64 hex characters / 256-bit in production). Non-hex UTF-8 keys require
`NEUTRINO_ALLOW_WEAK_MASTER_KEY=1` (non-production only).

Optional KMS or HSM unwrap (`NEUTRINO_KEY_SOURCE=aws-kms|gcp-kms|vault-transit|pkcs11|tpm`)
uses `NEUTRINO_MASTER_KEY_WRAPPED` plus provider credentials / token config. Enable the
matching Cargo feature (`kms-aws`, `kms-gcp`, `kms-vault-transit`, `hsm-pkcs11`, or
`hsm-tpm`). The provider protects the process master key only — customer secrets stay
sealed in Valence. Grant cloud IAM (or Vault policy) Decrypt-only on that single key;
for PKCS#11/TPM, wrap the MEK to the token/TPM public key offline (RSA-OAEP SHA-256).

| Source | Required env (beyond `NEUTRINO_KEY_SOURCE`) |
|--------|---------------------------------------------|
| `env` (default) | `NEUTRINO_MASTER_KEY` |
| `aws-kms` | `NEUTRINO_MASTER_KEY_WRAPPED` (base64), `NEUTRINO_AWS_KMS_KEY_ID`; AWS default credential chain |
| `gcp-kms` | `NEUTRINO_MASTER_KEY_WRAPPED` (base64), `NEUTRINO_GCP_KMS_KEY_NAME`, `NEUTRINO_GCP_ACCESS_TOKEN` |
| `vault-transit` | `NEUTRINO_MASTER_KEY_WRAPPED` (Transit ciphertext), `NEUTRINO_VAULT_ADDR`, `NEUTRINO_VAULT_TOKEN`, `NEUTRINO_VAULT_TRANSIT_KEY` |
| `pkcs11` | `NEUTRINO_MASTER_KEY_WRAPPED` (base64), `NEUTRINO_PKCS11_MODULE`, `NEUTRINO_PKCS11_PIN`, `NEUTRINO_PKCS11_KEY_LABEL`; optional `NEUTRINO_PKCS11_SLOT`, `NEUTRINO_PKCS11_OAEP_HASH` (`sha256` default, `sha1` for SoftHSM+OpenSSL) |
| `tpm` | `NEUTRINO_MASTER_KEY_WRAPPED` (base64), `NEUTRINO_TPM_TCTI`, `NEUTRINO_TPM_KEY_HANDLE` |

Local SoftHSM / swtpm setup for gated integration tests:
[`docs/hsm-local-setup.md`](docs/hsm-local-setup.md).


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

Denial-path audit rows require an **already-System** Valence sink on
[`ValenceSealedStore`](neutrino/src/sealed_store.rs) (host boot). 
`append_denial_audit_event` refuses mid-request elevation — denied session actors
cannot forge the chain via `defer_to_edge` create. Success-path audits keep the
session actor.

`ListedSecret` omits `owner_subject_json` so product list DTOs cannot leak owner
subject by field copy (`tests/no_elevate_path_gate.rs`).

## Client reveal transport

[`RevealedVaultSecret`](neutrino/src/vault.rs) zeroizes `plaintext_b64` on drop
and redacts it from `Debug` output. The vault UI clears reveal state when the
dialog closes.

## Secret access telemetry

Spectra event table `neutrino_secret_access_log` rows include `scope_path`, `secret_name`,
`secret_id`, and `caller` as hashed fingerprints (`h` + hex), not plaintext.
Rows never carry secret plaintext or ciphertext. Correlation uses hashed
`secret_id`, plus `action` and `version_num`.
