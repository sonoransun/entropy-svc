//! mixrand internal library surface.
//!
//! This crate ships both a binary (`mixrand`) and a library target. The
//! library exists primarily to let benchmarks, integration tests, and
//! embedders reuse the core primitives (mixer, CSPRNG, health tests, entropy
//! sources). The CLI types in [`cli`] are part of the surface too, so that
//! external integrations can re-use flag definitions.
//!
//! Currently public modules:
//! - [`mixer`] — BLAKE2b / HKDF entropy mixing with domain separation
//! - [`csprng`] — ChaCha20-based deterministic output generation
//! - [`health`] — NIST SP 800-90B Repetition Count + Adaptive Proportion tests
//! - [`stats`] — FIPS 140-2 tests + advanced entropy metrics
//! - [`entropy`] — `EntropySource` trait and platform source implementations
//! - [`config`], [`error`], [`output`] — supporting types
//! - [`bench`], [`check`] — subcommand entry points, mainly for the binary
//! - [`daemon`] — Linux-only entropy-pool feeder
//!
//! **Stability**: no API guarantees at 0.x. Domain tags and framing are
//! pinned by KATs in each module's test suite; any intentional change must
//! bump the domain-tag version suffix.

pub mod bench;
pub mod check;
pub mod cli;
pub mod config;
pub mod csprng;
pub mod daemon;
pub mod entropy;
pub mod error;
pub mod health;
pub mod logging;
pub mod memlock;
pub mod mixer;
pub mod output;
pub mod sensitive;
pub mod stats;
pub mod version_info;
