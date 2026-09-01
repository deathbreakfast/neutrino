# neutrino-spectra-telemetry examples

| Example | Role |
|---------|------|
| `secret_access_emit_smoke` | field builder + recorder/logger emit |

## 1. Secret access — `secret_access_emit_smoke`

```bash
CARGO_BUILD_JOBS=1 \
  cargo run -p neutrino-spectra-telemetry --example secret_access_emit_smoke
```

Success: stdout prints `secret_access_emit_smoke: OK`.

Call these helpers at your host's secret-access interception points (no env install switch).
