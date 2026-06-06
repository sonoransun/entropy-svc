# Changelog

All notable changes to mixrand will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.

## [Unreleased]

### Security / Fix

- **HKDF expand-phase counter wrap fixed.** The v1 implementation used a
  `u8` counter that wrapped at block 256, causing output past byte 8160
  to contain duplicate blocks (block 257 reproduced block 1 because
  `if counter > 1` was false after wrap). The counter is now `u32`
  encoded as 4 little-endian bytes, giving ~137 GiB of unique output —
  well above the 100 MiB CLI cap. The domain tag is bumped to
  `mixrand-hkdf-expand-v2`; v1 KATs are no longer valid, the four
  existing HKDF KATs were re-pinned, and a regression test
  (`test_hkdf_output_beyond_u8_counter_wrap_unique_blocks`) prevents
  future wraps from slipping in. Callers that stored v1 output for
  reproducibility must regenerate or retain v1 builds.
- HKDF intermediate digests (`pass1`, `prk_result`) are now zeroized
  via a local `Drop` guard, so an unwinding panic between `finalize()`
  and the explicit zeroize can no longer leave a digest on the stack.
- Daemon `write_pid_file` uses `O_CREAT|O_EXCL` for the final write.
  The race between stale-PID cleanup and write-own-PID is closed by
  the exclusive create — the losing side sees `AlreadyExists` and
  exits with the existing "another instance is running" error.

### Added

- **GPS Subframe 4/Page 17 additional-input** (`gps` feature,
  `src/entropy/gps.rs`) — folds the *public* GPS "Special Message"
  broadcast field into output as a NIST SP 800-90A personalization string
  at **0-bit entropy credit**. It is **not** an entropy source: it is
  registered in no source cascade, never wins selection, never enters
  `check` grading or the daemon self-test, and is XOR-folded with a public
  keystream so it can neither raise nor lower the real entropy's security.
  Acquired (with a hard timeout, never blocking generation) from an
  external GNSS decoder via `--gps-command`/`--gps-path`,
  `MIXRAND_GPS_*`, or `[hsm.gps]`. Off by default; in `all-sources` but
  not `hsm`. Surfaces in `list-sources`/`check` as an informational
  `additional-input` row. See `docs/gps-additional-input.md`.
- **`SensitiveBytes`** wrapper (`src/sensitive.rs`) — `Deref<Target=
  [u8]>` + `Drop`-zeroize for short-lived entropy buffers. Used by
  `main.rs`, `daemon.rs::inject_entropy`, and the daemon main loop
  replacing the prior explicit-zeroize-on-success pattern.
- **Systemd deployment artifacts** under `deploy/systemd/` — a
  notify-type `mixrand.service` with hardening (`NoNewPrivileges`,
  `ProtectSystem=strict`, `MemoryDenyWriteExecute`, minimal
  `CapabilityBoundingSet`), a `mixrand.tmpfiles.d.conf` for
  `/run/mixrand/`, and an install/verify `deploy/README.md`.
- **`--version --verbose`** prints build provenance (git commit, UTC
  build timestamp, rustc version, target triple, enabled features).
  Backed by a new `build.rs` that emits `MIXRAND_*` compile-time env
  vars and a `src/version_info.rs` module. Plain `--version` output
  is unchanged.
- **Daemon startup self-test.** Before signalling systemd `READY=1`,
  the daemon probes every built source, runs RCT+APT on the sample,
  and logs the outcome per source. If every source fails, the daemon
  returns `Error::NoEntropy` instead of entering the loop — so a
  misconfigured host cannot silently fall through to `urandom` under
  `Type=notify`. Bypass with `--no-self-test` for debugging.
- **Daemon `gen_errors` counter** — entropy-generation failures are
  now tracked separately from health-skips in the periodic heartbeat
  log line.
- **MockEntropySource** (`src/entropy/mock.rs`, gated on new `testing`
  dev-feature) — deterministic, queue- or LCG-driven source for unit
  tests. Used by daemon self-test unit tests.
- **Per-HSM setup guides** under `docs/hsm/` (tpm2, pkcs11, yubikey,
  yubihsm, pcsc, gnupg, sgx) with Overview / Requirements / Setup /
  Configuration / Verification / Troubleshooting sections each.
- **`docs/deployment.md`** consolidating production install paths,
  user creation, systemd hardening directive rationale, upgrade /
  rollback, and a production checklist.
- **~107 new tests** across the suite:
  - HKDF counter-wrap regression + block-257 KAT + unique-blocks
    property + doc updates for the framing change.
  - Daemon: self-test (3 tests), PID file O_EXCL (3 tests), daemon
    integration (6 tests; 3 opt-in via `--ignored`).
  - FIPS boundary pins (monobit 9725/9726/10274/10275; long-runs 25
    pass / 26 fail; suite-rejects-any-failing-subtest).
  - Health: RCT/APT monotonicity properties; `H=4 ⇒ cutoff=11`; APT
    window-roll-over; RCT cross-sample reset.
  - CSPRNG: reseed callback differs from no-reseed; zero-byte no-op;
    reseed-just-below-boundary.
  - Output: hex / base64 / base64url / octal / binary round-trips
    over every byte value.
  - Config: malformed-TOML is a clean error; invalid env is ignored;
    `validate` is idempotent; bool-env-var variants.
  - SensitiveBytes: 8 unit tests; MockEntropySource: 8 unit tests;
    version-info: 3 unit tests + 5 CLI integration tests.
- **New benches**: `fips_suite.rs` (individual tests + full suite) and
  `full_pipeline.rs` (mix+csprng end-to-end, gated on `testing`).
- Feature flag `testing` (dev-only) exposes `MockEntropySource`.

### Changed

- `src/entropy/cpurng.rs` CPUID inline-asm sites now carry a SAFETY
  comment explaining why the manual `push rbx` / `pop rbx` is the
  standard workaround for LLVM's `rbx` reservation (rust-lang/rust#84658).
- `src/csprng.rs::zeroize_rng` SAFETY comment now explains why writing
  `u8` over `ChaCha20Rng` is sound and why the subsequent `mem::forget`
  matters.
- `src/entropy/haveged.rs` and `src/entropy/hwrng.rs` test fixtures use
  `expect("test setup: ...")` and `unreachable!` instead of bare
  `unwrap()` / `panic!`.
- Fixed five `function_casts_as_integer` warnings in `bench.rs` and
  `daemon.rs` by casting handler fn pointers through `*const ()` first.

### Previously in Unreleased (pre-harden)

- `bench` subcommand measuring per-source throughput (bytes/s,
  samples/s, latency µs/sample) with text/JSON/CSV output.
- CPU-pipeline jitter path in `entropy::jitter` (1024-sample variant,
  complements the existing `clock_gettime` path). Documented
  0.5 bit/sample conservative entropy estimate.
- `UrandomSource` promoted to a first-class source in the generate
  cascade (priority 36, between haveged and fallback).
- `--show-config` now serializes the **full** effective Config as
  round-trippable TOML (previously only the `cpu_rng` subtree).
- CLI secret-leak detection: invoking with `--pkcs11-pin` or
  `--yubihsm-password` on the command line now logs a WARN suggesting
  the `MIXRAND_*` env-var equivalent.
- Known Answer Tests (KATs) for `mix_entropy`, `mix_entropy_hkdf`, and
  `csprng::generate` pinning current domain tags + framing.
- Property-based tests (proptest) for output format invariants.
- Integration tests under `tests/` covering CLI generate/check/
  list-sources/completions, the 4-layer config merge, and secret-leak
  warnings.
- Unit tests for `entropy::hwrng` and `entropy::haveged` (previously
  untested modules).
- Criterion microbenchmarks under `benches/` for mixer, CSPRNG, and
  health tester.
- Library target (`src/lib.rs`) exposing the internal modules to
  benches, integration tests, and embedders.
- `CONTRIBUTING.md`, `SECURITY.md`, and `docs/` (config example,
  entropy-source guidance, troubleshooting, man page).
- CI workflows (`ci.yml`, `release.yml`), `rustfmt.toml`, `clippy.toml`,
  `deny.toml` — formatting/lint/advisory-check enforced in CI.

### Changed

- Expanded `src/cli.rs` unit tests from 3 to ~28 covering every flag,
  bounds violation, mutually-exclusive pair, and subcommand.
- Added public-API doc comments across `error`, `logging`, `cli`,
  `output`, `mixer`, `csprng`, and `health`. Doc-tests on
  representative APIs.

## [0.1.0] - initial

- Multi-source entropy mixing (hwrng, cpurng, haveged, getrandom,
  fallback + feature-gated TPM2/PKCS#11/PC/SC/YubiKey/YubiHSM/GnuPG/SGX)
- BLAKE2b / HKDF mixer with domain separation
- ChaCha20 CSPRNG with auto-reseed at 1 MiB boundaries
- NIST SP 800-90B continuous health tests (RCT + APT)
- FIPS 140-2 statistical validation suite + advanced entropy metrics
- Linux daemon mode feeding the kernel entropy pool via
  `ioctl(RNDADDENTROPY)`, with systemd `sd_notify`, SIGHUP reload, and
  privilege drop
- 9 output formats: hex, hex-upper, raw, base64, base64url, uuencode,
  text, octal, binary
- 4-layer config (defaults → `/etc/mixrand.toml` → `MIXRAND_*` env →
  CLI flags)
