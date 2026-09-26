# Local HSM setup (SoftHSM + swtpm)

Operator notes for validating Neutrino PKCS#11 / TPM master-key unwrap.
Production hosts use a real HSM token or discrete TPM; SoftHSM and swtpm are
for CI and developer machines only.

Neutrino unwraps `NEUTRINO_MASTER_KEY_WRAPPED` (base64) with RSA-OAEP SHA-256.
The plaintext must be exactly 32 bytes (the process master key). Customer
secrets stay sealed in Valence.

## PKCS#11 (SoftHSM 2)

### Install

```bash
# Debian/Ubuntu
sudo apt install libsofthsm2 softhsm2 opensc
```

### Token + RSA key

```bash
mkdir -p /tmp/neutrino-softhsm/tokens
cat > /tmp/neutrino-softhsm/softhsm2.conf <<'EOF'
directories.tokendir = /tmp/neutrino-softhsm/tokens
objectstore.backend = file
EOF
export SOFTHSM2_CONF=/tmp/neutrino-softhsm/softhsm2.conf

softhsm2-util --init-token --slot 0 --label neutrino --pin 1234 --so-pin 1234

# Module path varies by distro:
#   /usr/lib/softhsm/libsofthsm2.so
#   /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
export NEUTRINO_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

pkcs11-tool --module "$NEUTRINO_PKCS11_MODULE" \
  --login --pin 1234 \
  --keypairgen --key-type rsa:2048 \
  --label neutrino-mek --id 01
```

### Wrap a 32-byte MEK

Export the public key, encrypt 32 random bytes with RSA-OAEP, base64 the
ciphertext, and set `NEUTRINO_MASTER_KEY_WRAPPED`. Keep the plaintext MEK out
of logs and VCS.

SoftHSM + OpenSSL often needs **SHA-1** OAEP for interop:

```bash
openssl pkeyutl -encrypt -pubin -inkey pub.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 \
  -in mek.bin -out mek.wrapped
```

Production HSMs should use SHA-256 (Neutrino default). For SoftHSM tests set
`NEUTRINO_PKCS11_OAEP_HASH=sha1`.

### Env for Neutrino

```bash
export NEUTRINO_KEY_SOURCE=pkcs11
export NEUTRINO_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export NEUTRINO_PKCS11_PIN=1234
export NEUTRINO_PKCS11_KEY_LABEL=neutrino-mek
export NEUTRINO_PKCS11_OAEP_HASH=sha1
# optional: export NEUTRINO_PKCS11_SLOT=<slot-id>
export NEUTRINO_MASTER_KEY_WRAPPED=<base64>
export NEUTRINO_PKCS11_INTEGRATION=1
```

### Run tests

```bash
export CARGO_TARGET_DIR=target-neutrino CARGO_BUILD_JOBS=1
cargo test -p neutrino --features hsm-pkcs11 --test hsm_pkcs11_integration
```

## TPM 2.0 (swtpm)

### System libraries

`tss-esapi` needs TPM2-TSS (`tss2-sys`, `tss2-esys`) at build and run time:

```bash
# Debian/Ubuntu
sudo apt install libtss2-dev swtpm swtpm-tools tpm2-tools
# or build tpm2-tss into ~/.local and set:
#   PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig
#   LD_LIBRARY_PATH=$HOME/.local/lib
```

### Start swtpm + create persistent RSA key

Follow tpm2-software swtpm docs to start a socket TCTI, then create an RSA
decrypt key and make it persistent (example handle `0x81000001`). Wrap the
32-byte MEK to that key's public half (RSA-OAEP SHA-256) and base64 it.

### Env for Neutrino

```bash
export NEUTRINO_KEY_SOURCE=tpm
export NEUTRINO_TPM_TCTI=swtpm:host=127.0.0.1,port=2321
export NEUTRINO_TPM_KEY_HANDLE=0x81000001
export NEUTRINO_MASTER_KEY_WRAPPED=<base64>
export NEUTRINO_TPM_INTEGRATION=1
```

### Run tests

```bash
export CARGO_TARGET_DIR=target-neutrino CARGO_BUILD_JOBS=1
export PKG_CONFIG_PATH=${PKG_CONFIG_PATH:-}
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}
cargo test -p neutrino --features hsm-tpm --test hsm_tpm_integration
```

## Security notes

- SoftHSM PINs in this doc are for local tests only. Production PINs come from
  your secret distributor and must never appear in logs or `MasterKeyError`.
- Do not commit wrapped blobs that encrypt a production MEK alongside a
  SoftHSM token directory.
- Default Neutrino builds leave `hsm-pkcs11` / `hsm-tpm` off; opt in per host.
