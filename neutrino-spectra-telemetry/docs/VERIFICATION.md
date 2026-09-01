# neutrino-spectra-telemetry verification

Re-run after code or doc changes. Covered by unit + integration tests below.

## Environment

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-neutrino-spectra-telemetry
```

## Unit + integration (CI)

```bash
cargo fmt --all --check
cargo clippy -p neutrino-spectra-telemetry --all-targets -- -D warnings
cargo test -p neutrino-spectra-telemetry
```

### TEST_MAP

| Behavior | Level | Happy | Sad | Notes |
|----------|-------|-------|-----|-------|
| `truncate_message` / `secret_access_log_fields` | unit | short message preserved; full log JSON shape | oversize `error_message` clipped to 512 with `…` | `events::tests` |
| `sink_forward::field_str` / `field_i64` | unit | string/bool/number coercions | missing / null / array / bad parse → `""` / `0` | private helpers |
| Typed recorders / loggers | integ | `NeutrinoSecretAccessRecorder` + `NeutrinoSecretAccessLogLogger` emit | empty labels / empty logger fields accepted | no Spectra sink required; non-panic contracts |
| `sink_forward` | integ | known counter + event table | unknown name ignored; missing fields default | consumer / sink_forward |
| Topic constants | integ | `spectra.metric.*` / `spectra.event.*` with `neutrino_secret_access*` | — | Photon wire names from spectra macros |
| Field builders (integ mirror) | integ | `secret_access_log_fields` shape | truncate via public helpers | `tests/api.rs` |

## Notes

- This crate has no `*_TELEMETRY` install switch: hosts call field builders /
  typed recorders at their own interception points.
- Emit helpers under Spectra `try_*` gate assert contracts/non-panic rather than
  captured Spectra sink rows.
- Sad-path tests are named with `_sad` / `happy_and_sad` so audits detect them;
  they assert concrete defaults and truncation bounds, beyond smoke-only checks.
