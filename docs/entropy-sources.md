# Entropy source selection guide

mixrand mixes entropy from multiple sources simultaneously. The cascade
is priority-ordered: lower numbers are tried first, and the **first
source that passes health checks wins** for a given generate request.
`check` and `list-sources` exercise every available source individually
so you can validate coverage before deploying.

## Default cascade

| Priority | Source     | Type     | Feature gate       | Platform     |
| -------: | ---------- | -------- | ------------------ | ------------ |
| 4        | sgx        | hardware | `sgx`              | x86_64 Linux |
| 5        | tpm2       | hardware | `tpm2`             | Linux        |
| 6        | pkcs11     | hardware | `pkcs11`           | any          |
| 6        | yubihsm    | hardware | `yubihsm-native`   | any          |
| 7        | yubikey    | hardware | `yubikey`          | Linux/macOS  |
| 7        | pcsc       | hardware | `pcsc`             | Linux/macOS  |
| 8        | gnupg      | software | `gnupg`            | any          |
| 10       | hwrng      | hardware | — (default)        | Linux        |
| 20       | cpurng     | hardware | — (default)        | x86_64/AArch64 |
| 30       | haveged    | system   | — (default)        | Linux        |
| 35       | getrandom  | system   | — (default)        | Linux/macOS  |
| 36       | urandom    | system   | — (default)        | Linux        |
| 40       | fallback   | software | — (default)        | any          |

The `check` subcommand additionally splits `cpurng` into individual CPU
instruction sources (`rdseed`, `rdrand`, `xstore`, `rndr`, `rndrrs`) so
you can validate each path.

## Selection by use case

### General-purpose server
Default cascade is sufficient. Ensure `/dev/hwrng` exists (TPM-backed on
most modern servers) and `haveged` is available as a fallback.

### Embedded / headless appliance without a TPM
Rely on cpurng + fallback. Enable the `haveged` package if you can run a
daemon.

### Air-gapped / high-assurance
Enable `--features all-sources` and deploy a TPM 2.0 alongside a PKCS#11
HSM. Keep cpurng and hwrng as secondary inputs so a single hardware
compromise cannot silently degrade output. Validate with
`mixrand check -d 5m --output-format json` before cut-over.

### HSM-backed key service
Prefer a dedicated HSM connected via PKCS#11 or YubiHSM 2. Keep TPM2 and
cpurng enabled as independent cross-checks. Set
`MIXRAND_PKCS11_PIN` / `MIXRAND_YUBIHSM_PASSWORD` via env vars, never
CLI flags — mixrand will warn about CLI-visible secrets.

### Resource-constrained / AArch64 IoT
`rndr` and `rndrrs` cover most modern AArch64 parts; `rndrrs` (reseeded)
has a measurable throughput penalty but stronger per-sample entropy.
cpurng oversample = 4 is a reasonable default under light load.

### CI / testing environment
`fallback` is always available and deterministic under test harnesses.
Use `--sources fallback` to pin reproducibility when validating CLI
behavior rather than entropy quality.

## Per-source setup notes

- **hwrng**: requires `/dev/hwrng` readable by the running user. Most
  kernel builds restrict it to root; consider `chmod 644` or a tmpfiles.d
  entry if daemon mode is not used.
- **haveged**: install the OS package, then validate
  `grep haveged /proc/*/comm` finds a running instance.
- **tpm2**: default TCTI `device:/dev/tpmrm0` needs
  `tpm2-abrmd` or in-kernel resource manager. Alternatives:
  `swtpm:path=...` for simulators, `mssim:host=...` for Intel's
  Microsoft TPM simulator.
- **pkcs11**: SoftHSM is the easiest test driver:
  `softhsm2-util --init-token --label mixrand --pin 1234 --so-pin 4321`
- **pcsc**: requires `pcscd` running; check with `pcsc_scan`.
- **yubikey**: plug in device, run `ykman list` to verify detection.
- **gnupg**: no setup beyond `gpg` on `$PATH`.
- **yubihsm**: start `yubihsm-connector -c yubihsm-connector.yaml` and
  point `connector_url` at `http://127.0.0.1:12345`.
- **sgx**: needs SGX-capable CPU with BIOS-enabled SGX and one of
  `/dev/sgx_enclave`, `/dev/sgx/enclave`, or `/dev/isgx`. Runtime lib
  `libsgx_urts.so.2` must be available when the signed enclave is loaded
  (future work).
  **⚠️ Current limitation:** the `sgx` feature today verifies SGX
  hardware presence and then reads via RDRAND from the *untrusted*
  runtime — it is **not** a true enclave-sealed source. See
  [`docs/hsm/sgx.md`](hsm/sgx.md) for the full write-up and roadmap.

## Per-backend setup guides

- [`docs/hsm/tpm2.md`](hsm/tpm2.md)
- [`docs/hsm/pkcs11.md`](hsm/pkcs11.md)
- [`docs/hsm/yubikey.md`](hsm/yubikey.md)
- [`docs/hsm/yubihsm.md`](hsm/yubihsm.md)
- [`docs/hsm/pcsc.md`](hsm/pcsc.md)
- [`docs/hsm/gnupg.md`](hsm/gnupg.md)
- [`docs/hsm/sgx.md`](hsm/sgx.md)

## Validation

```bash
# Enumerate what's available right now
mixrand list-sources

# Statistical validation against every configured source (takes ~1 min)
mixrand check -d 1m --output-format json > check-report.json

# Throughput measurement (takes --duration seconds per source)
mixrand bench -d 3s --output-format csv > bench.csv
```
