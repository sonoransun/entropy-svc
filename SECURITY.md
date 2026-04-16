# Security Policy

## Supported versions

mixrand is currently pre-1.0. Only the most recent `0.x.y` release tracks
security updates. When 1.x ships, this document will expand to cover
parallel supported branches.

| Version   | Supported          |
| --------- | ------------------ |
| 0.1.x     | :white_check_mark: |

## Reporting a vulnerability

Please report suspected vulnerabilities privately **before** filing a
public issue.

- Email: `security@example.invalid` (**TODO: maintainers — replace with
  the real disclosure address before the first public release**)
- Include: mixrand version, feature flags enabled at build time, platform
  (OS + arch), repro steps, and impact assessment.

Expect an initial acknowledgement within 72 hours. A coordinated
disclosure window of up to 90 days will be proposed unless active
exploitation is suspected.

## Threat model

### What mixrand protects against

- **Single-source compromise**: a faulty or backdoored hardware/software
  entropy source cannot silently produce predictable output *as long as at
  least one other healthy source contributes to the mix*. The mixer uses
  BLAKE2b with domain separation so one broken source can't cancel the
  others' contribution.
- **Stuck / biased sources**: NIST SP 800-90B continuous health tests
  (Repetition Count + Adaptive Proportion, implemented in
  [`src/health.rs`](src/health.rs)) detect stuck/biased sources and cause
  them to be skipped by the cascade.
- **Cold-boot / core-dump recovery**: CSPRNG internal state and input
  seeds are volatile-zeroized after use
  ([`src/csprng.rs`](src/csprng.rs)). Daemon mode `mlock()`s sensitive
  buffers and marks them `MADV_DONTDUMP`.
- **Domain confusion across mixer invocations**: inputs are length-
  prefixed and domain-tagged; KATs in `src/mixer.rs` pin the wire format
  across versions.

### What mixrand does NOT protect against

- **Physical attacker with root access**: mixrand cannot defend against
  arbitrary code running as root on the same machine. In that scenario,
  the kernel's own entropy guarantees are the relevant boundary.
- **Malicious HSM**: if every enabled source is compromised in a
  coordinated way, the mixer cannot conjure entropy from nothing.
  Defense is operational — use heterogeneous vendors.
- **Jitter-only deployments**: the timing-jitter source
  ([`src/entropy/jitter.rs`](src/entropy/jitter.rs)) provides only a
  conservative 0.5 bits/sample of min-entropy. It is safe as a
  contributing input, not as a sole source. The default cascade never
  promotes jitter to primary.
- **Side-channel leaks on shared hosts**: VM-guest entropy collection
  under a hostile hypervisor may be observable. Use hardware sources
  (TPM, hwrng device) when available.
- **Weak SGX enclave assurance** (current version): the SGX source
  currently verifies SGX device presence and delegates to RDRAND, rather
  than invoking the signed enclave ECALL. A future release will wire the
  enclave FFI; until then, the `sgx` feature gives you hardware
  *detection*, not full enclave attestation.

## Known limitations

- **CLI-visible secrets**: passing `--pkcs11-pin` or
  `--yubihsm-password` on the command line exposes the secret in
  `/proc/<pid>/cmdline` and the output of `ps`. mixrand logs a WARN in
  this case. Always prefer the `MIXRAND_PKCS11_PIN` /
  `MIXRAND_YUBIHSM_PASSWORD` env-var equivalents.
- **Daemon mode is Linux-only** by design — privilege drop, entropy pool
  ioctl, and sd_notify all depend on the Linux API surface.
- **Cross-architecture CPU RNG coverage**: x86_64 supports RDRAND /
  RDSEED / XSTORE; AArch64 supports RNDR / RNDRRS. Other ISAs skip the
  CPU-instruction paths entirely and rely on the mixed fallback.

## Cryptographic primitives

| Primitive  | Library        | Role                           |
| ---------- | -------------- | ------------------------------ |
| BLAKE2b-256| `blake2`       | mixer output, HKDF internals   |
| ChaCha20   | `rand_chacha`  | CSPRNG (deterministic output)  |

Any change to domain-separation tags or input framing must bump the
version suffix on the tag and update KATs (see `CONTRIBUTING.md`).

### Domain tag rotation history

- `mixrand-hkdf-expand-v1` → `mixrand-hkdf-expand-v2` (Unreleased). The
  v1 form used a `u8` per-block counter that wrapped at block 256,
  producing duplicate output blocks past 8160 bytes. v2 uses a u32 LE
  counter. Migration note: v1 and v2 produce different bytes for
  identical inputs — if you stored v1 output for reproducibility, pin
  a v1 build or regenerate against v2. See `CHANGELOG.md` and
  `docs/troubleshooting.md` for operator guidance.

Future tag rotations follow the same protocol: bump the numeric
suffix, re-pin the affected KATs, add a `CHANGELOG.md` entry under
Security, and add a `docs/troubleshooting.md` migration note.

## Production hardening

See [`docs/deployment.md`](docs/deployment.md) for the recommended
systemd unit, capability set, and verification procedure.

## Reproducible builds

- `Cargo.lock` is committed.
- Release binaries are built with `--features all-sources` against the
  stable Rust toolchain declared in `rust-toolchain.toml` (if present) or
  the MSRV in `clippy.toml`.
- Signed release artifacts on the GitHub releases page include a SHA-256
  checksum and are attested by the maintainer's signing key.

## Dependency audit

`cargo deny check` is wired into CI to catch advisory-db alerts and
license-list deviations. See `deny.toml` for policy.
