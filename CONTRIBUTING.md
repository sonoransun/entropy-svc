# Contributing to mixrand

Thanks for your interest in contributing to mixrand. This document covers
how to build, test, and add new functionality — particularly new entropy
sources.

## Quick start

```bash
cargo build                      # default build, no feature flags
cargo test                       # run all unit + integration tests
cargo test --all-features        # exercise every HSM / secure-element path
cargo doc --no-deps --open       # browse API docs locally
```

Bench suite (Criterion):

```bash
cargo bench                      # all benches (mixer, csprng, health)
cargo bench --bench mixer        # one at a time
```

## Feature matrix

Optional HSM and secure-element support is gated by Cargo features. The
default build has no optional features — pure Rust plus libc. When
adding code that depends on a specific crate, put it behind an existing
feature flag or add a new one.

| Feature           | Pulls in              | System deps               |
| ----------------- | --------------------- | ------------------------- |
| `pkcs11`          | `cryptoki`            | runtime dlopen, none      |
| `tpm2`            | `tss-esapi`           | `libtss2-dev`             |
| `pcsc`            | `pcsc`                | `libpcsclite-dev`         |
| `yubikey`         | — (implies `pcsc`)    | `libpcsclite-dev`         |
| `gnupg`           | subprocess            | none                      |
| `yubihsm-native`  | `yubihsm` (HTTP)      | none                      |
| `sgx`             | runtime dlopen        | `libsgx_urts` at runtime  |
| `hsm`             | meta: all of the above except yubihsm-native + sgx |
| `all-sources`     | meta: everything      |                           |

CI runs the test suite against `default`, `hsm`, and `all-sources`.
Code behind feature gates must build **and** its tests must pass under
every combination it compiles for.

## MSRV policy

mixrand supports **stable Rust N-2** — i.e. the current stable release and
the two previous stable releases. When bumping `msrv` in `clippy.toml`,
update this policy and `rust-version` in `Cargo.toml`.

## Adding a new entropy source

Every source implements the [`EntropySource`](src/entropy/mod.rs) trait:

```rust
pub trait EntropySource: Send + Sync {
    fn name(&self) -> &str;           // short machine-friendly name
    fn description(&self) -> &str;    // human-readable description
    fn priority(&self) -> u32;        // lower = tried first
    fn is_available(&self) -> bool;   // quick availability check
    fn source_type(&self) -> &str { "software" }   // "hardware" | "system" | "software"
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error>;
}
```

Steps to wire in a new source:

1. **Add the module**: `src/entropy/myrng.rs`. Feature-gate it with
   `#[cfg(feature = "myrng")]` at both the `pub mod` declaration in
   `src/entropy/mod.rs` and inside the module file where external crates
   are imported.
2. **Pick a priority**: consult the ordering in
   [`build_generate_sources`](src/entropy/mod.rs). Hardware sources belong
   in the 0–30 range; software fallbacks at 40+.
3. **Register it**: add it to `add_hsm_sources` in `src/entropy/mod.rs`
   (for HSMs) or directly to `build_generate_sources` /
   `build_check_sources`.
4. **Config hook**: if your source needs configuration, add a sub-struct in
   `src/config.rs` under `HsmConfig`, with `MIXRAND_*` env-var overrides in
   `apply_hsm_env_overrides`. PINs/passwords must be
   `#[serde(skip_serializing)]`.
5. **CLI flag**: add an `enable_myrng: Option<bool>` to `HsmArgs` in
   `src/cli.rs` and wire it through `build_config` in `src/main.rs`.
6. **Tests**: add at least an availability test, a config-default test, and a
   not-available-on-this-host graceful-failure test. Most HSM modules (see
   `src/entropy/tpm2.rs`, `src/entropy/pkcs11.rs`) can serve as templates.
7. **Docs**: cover the source in
   [`docs/entropy-sources.md`](docs/entropy-sources.md). If it has
   non-obvious setup (daemon prerequisites, device nodes, permissions),
   extend [`docs/troubleshooting.md`](docs/troubleshooting.md).

## Crypto invariants

Domain tags and input framing for the mixer and CSPRNG are pinned by
**Known Answer Tests** (`kat_*` in `src/mixer.rs` and `src/csprng.rs`). If
you need to change a domain tag, bump its version suffix (e.g.
`mixrand-entropy-v1` → `-v2`) and regenerate the KATs. A silent tag change
would mean old callers and new callers compute different seeds from the
same inputs, which is always a bug in a cross-version deployment.

## Running tests per feature combo

```bash
cargo test
cargo test --features hsm
cargo test --features all-sources
cargo test --doc --all-features
```

The CI matrix covers `stable` and `beta` across all three feature
combos. Please run at least the default and `--all-features` locally
before opening a PR.

## Style

- `cargo fmt` before committing (CI enforces `cargo fmt --check`).
- `cargo clippy --all-features -- -D warnings` — zero warnings allowed.
- Keep doc comments on every public item. Use `# Examples` blocks when the
  invocation isn't obvious from the signature.

## Syncing env vars with docs

When adding or removing a `MIXRAND_*` environment variable in
`src/config.rs::apply_env_overrides` or `apply_hsm_env_overrides`, also
update:

1. The env-var list in the matching `pub fn` rustdoc block.
2. The "Environment variables" table in `README.md`.
3. The commented template in `docs/config.example.toml`.
4. The relevant `docs/hsm/<backend>.md` guide.
5. The manpage section in `docs/mixrand.1` if the var is user-facing.

Env-var documentation drifts quietly — grep for the removed/added name
in all five places before opening the PR.

## Domain tag change protocol

Any change to a mixer domain tag (`mixrand-entropy-v<N>`,
`mixrand-hkdf-extract-v<N>`, `mixrand-hkdf-expand-v<N>`, etc.) is a
breaking change for downstream callers who stored output for
reproducibility. The checklist:

1. Bump the numeric suffix (`-v1` → `-v2`). Do not rename laterally.
2. Regenerate every pinned KAT that depends on the tag; commit the
   fresh hex in the same PR.
3. Add a `Security / Fix` or `Security / Breaking` entry in
   `CHANGELOG.md` describing the change and the migration path.
4. Add a matching section to `docs/troubleshooting.md` under
   "<tag> v<N> → v<N+1> migration note".
5. Update `SECURITY.md` §"Domain tag rotation history" with the
   reason for the bump.

Do NOT reuse a retired tag; always go forward.

## Reporting bugs and security issues

- Functional bugs: please file a GitHub issue with a minimal repro.
- Security-relevant reports: follow the process in
  [`SECURITY.md`](SECURITY.md).
