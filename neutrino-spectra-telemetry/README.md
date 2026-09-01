# neutrino-spectra-telemetry

Spectra telemetry for Neutrino secret-access events: DSL schemas, Photon topic helpers,
and field builders for host logging. Workspace member of [neutrino](../).

```toml
# Tracks main; pin rev for reproducible production builds.
neutrino-spectra-telemetry = { git = "https://github.com/unified-field-dev/neutrino", package = "neutrino-spectra-telemetry", branch = "main" }
# Or from a Neutrino checkout:
# neutrino-spectra-telemetry = { path = "neutrino-spectra-telemetry" }
```

```rust
use neutrino_spectra_telemetry::secret_access_log_fields;

let fields = secret_access_log_fields(
    "read",
    "sec-1",
    1,
    "/apps/billing",
    "api-key",
    "ok",
    "actor:alice",
    "neutrino-vault",
    "",
);
let _ = fields;
```

## About

- Spectra DSL schemas under `schemas/` (inventory-registered when linked)
- Typed Photon topic helpers for Neutrino secret-access telemetry
- `secret_access_log_fields` and `sink_forward` for host composition

Secret-identifying metadata is hashed before persist. There is no process-wide install
switch: hosts call the helpers at their own interception points (or enable Neutrino `ssr`,
which links this crate for vault instrumentation).

## Examples

Runnable smoke: [examples/README.md](examples/README.md).

## Verify

```bash
export CARGO_BUILD_JOBS=1
cargo test -p neutrino-spectra-telemetry
```

## License

MIT. See [LICENSE](../LICENSE), [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md),
and [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md).
