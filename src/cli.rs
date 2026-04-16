//! Command-line interface definitions for `mixrand`.
//!
//! Parsed by the binary at startup via clap derive macros. The main [`Cli`]
//! struct carries both the generate-mode flags and one of the subcommand
//! variants in [`Command`]. Every subcommand flattens three argument groups:
//! [`CpuRngArgs`], [`HsmArgs`], and [`crate::logging::LogArgs`], so the user
//! can tune CPU RNG, HSM, and logging behavior uniformly across modes.

use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::config::{CpuRngPreference, MixerMode};
use crate::logging::LogArgs;

/// Output format selector for the generate subcommand.
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// Hexadecimal lowercase (default, e.g. a1b2c3)
    Hex,
    /// Raw binary bytes (no encoding, for piping to files or tools)
    Raw,
    /// Base64 standard encoding with padding
    Base64,
    /// Base64 URL-safe (no padding, uses - and _ instead of + and /)
    Base64url,
    /// uuencode format (traditional Unix encoding, compatible with uudecode)
    Uuencode,
    /// Printable ASCII text (94 chars: ! through ~, suitable for passwords)
    Text,
    /// Octal bytes separated by spaces (e.g. 241 262 303)
    Octal,
    /// Binary bit strings separated by spaces (e.g. 10100001 10110010)
    Binary,
    /// Hexadecimal uppercase (e.g. A1B2C3)
    HexUpper,
}

/// Output format selector shared by `check` and `bench`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CheckOutputFormat {
    /// Human-readable text (default)
    Text,
    /// JSON
    Json,
    /// CSV
    Csv,
}

/// HSM / secure-element flags flattened into every subcommand.
///
/// Sensitive values (PINs, passwords) are accepted but trigger a runtime
/// WARN — see `crate::main::build_config`. Prefer the `MIXRAND_*` env-var
/// equivalents for real deployments.
#[derive(Debug, Args)]
pub struct HsmArgs {
    /// Enable TPM2 entropy source
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_tpm2: Option<bool>,

    /// Enable PKCS#11 entropy source
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_pkcs11: Option<bool>,

    /// Enable PC/SC smart card entropy source
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_pcsc: Option<bool>,

    /// Enable YubiKey entropy source
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_yubikey: Option<bool>,

    /// Enable GnuPG entropy source
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_gnupg: Option<bool>,

    /// Enable YubiHSM native entropy source
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_yubihsm: Option<bool>,

    /// Enable Intel SGX entropy source
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_sgx: Option<bool>,

    /// PKCS#11 library path (e.g. /usr/lib/softhsm/libsofthsm2.so)
    #[arg(long)]
    pub pkcs11_library: Option<String>,

    /// TPM2 device path (default: /dev/tpmrm0)
    #[arg(long)]
    pub tpm2_device: Option<String>,

    /// PKCS#11 user PIN (WARNING: visible in process list — prefer MIXRAND_PKCS11_PIN env var)
    #[arg(long)]
    pub pkcs11_pin: Option<String>,

    /// YubiHSM authentication password (WARNING: visible in process list — prefer MIXRAND_YUBIHSM_PASSWORD env var)
    #[arg(long)]
    pub yubihsm_password: Option<String>,
}

impl HsmArgs {
    /// Returns true if any CLI-supplied flag carries a secret value that would
    /// be visible to other processes via `/proc/<pid>/cmdline` or the output
    /// of `ps`. Used to emit a runtime warning suggesting the env-var
    /// equivalent.
    pub fn has_cli_secret(&self) -> bool {
        self.pkcs11_pin.is_some() || self.yubihsm_password.is_some()
    }

    /// Human-readable list of names of flags found to carry CLI-visible
    /// secrets. Empty if none.
    pub fn cli_secret_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.pkcs11_pin.is_some() {
            names.push("--pkcs11-pin");
        }
        if self.yubihsm_password.is_some() {
            names.push("--yubihsm-password");
        }
        names
    }
}

#[derive(Debug, Args)]
pub struct CpuRngArgs {
    /// Enable RDSEED instruction
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_rdseed: Option<bool>,

    /// Enable RDRAND instruction
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_rdrand: Option<bool>,

    /// Enable XSTORE instruction
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_xstore: Option<bool>,

    /// Enable AArch64 RNDR instruction
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_rndr: Option<bool>,

    /// Enable AArch64 RNDRRS instruction (reseeded)
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enable_rndrrs: Option<bool>,

    /// RDRAND retry count (1-100)
    #[arg(long)]
    pub rdrand_retries: Option<u32>,

    /// RDSEED retry count (1-100)
    #[arg(long)]
    pub rdseed_retries: Option<u32>,

    /// RNDR retry count (1-100)
    #[arg(long)]
    pub rndr_retries: Option<u32>,

    /// RNDRRS retry count (1-100)
    #[arg(long)]
    pub rndrrs_retries: Option<u32>,

    /// XSTORE quality factor (0-3)
    #[arg(long)]
    pub xstore_quality: Option<u32>,

    /// Preferred CPU RNG instruction
    #[arg(long = "cpu-rng-prefer", value_enum)]
    pub cpu_rng_prefer: Option<CpuRngPreference>,

    /// CPU entropy bytes for fallback mixing (0-1024)
    #[arg(long)]
    pub fallback_mix_bytes: Option<usize>,

    /// Standalone CPU RNG oversample ratio (1-16)
    #[arg(long)]
    pub oversample: Option<u32>,

    /// Mixer mode: blake2b (default) or hkdf (two-stage extract-then-expand)
    #[arg(long, value_enum)]
    pub mixer_mode: Option<MixerMode>,
}

#[derive(Debug, Parser)]
#[command(name = "mixrand", about = "Secure random byte generator", version)]
#[command(args_conflicts_with_subcommands = true)]
#[command(after_long_help = "\
Examples:
  mixrand -n 32                  Generate 32 random bytes (hex)
  mixrand -n 64 -f raw > key     Write 64 raw bytes to file
  mixrand -n 16 -f base64        Generate 16 bytes as base64
  mixrand -n 32 -f text          Generate a 32-char printable password
  mixrand --count 5 -n 32        Generate 5 independent 32-byte values
  mixrand check -d 30s           Run statistical tests for 30 seconds
  mixrand list-sources           Show available entropy sources
  mixrand daemon -t 512 -i 10    Run entropy daemon (Linux, requires root)
  mixrand completions bash       Generate bash completions")]
pub struct Cli {
    /// Number of random bytes to generate
    #[arg(short = 'n', long = "bytes", default_value_t = 32)]
    pub bytes: usize,

    /// Output format
    #[arg(short = 'f', long = "format", value_enum, default_value_t = OutputFormat::Hex)]
    pub format: OutputFormat,

    /// Write output to a file instead of stdout
    #[arg(short = 'o', long = "output-file")]
    pub output_file: Option<PathBuf>,

    /// Configuration file path (default: /etc/mixrand.toml)
    #[arg(long = "config")]
    pub config_file: Option<PathBuf>,

    /// Verbose output (sets log level to debug)
    #[arg(short = 'v', long, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Quiet output (sets log level to error)
    #[arg(short = 'q', long, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Print the effective configuration and exit
    #[arg(long)]
    pub show_config: bool,

    /// Generate N independent random outputs
    #[arg(long)]
    pub count: Option<usize>,

    #[command(flatten)]
    pub cpu_rng: CpuRngArgs,

    #[command(flatten)]
    pub hsm: HsmArgs,

    #[command(flatten)]
    pub log: LogArgs,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Monitor kernel entropy pool and inject mixed entropy when it runs low
    Daemon(DaemonArgs),
    /// Run FIPS 140-2 statistical tests and entropy estimates against each entropy source
    Check(CheckArgs),
    /// Measure throughput (bytes/s, samples/s) of each entropy source
    Bench(BenchArgs),
    /// Generate shell completions for bash, zsh, fish, or PowerShell
    Completions(CompletionsArgs),
    /// List available entropy sources and their status
    ListSources(ListSourcesArgs),
}

#[derive(Debug, Parser)]
pub struct DaemonArgs {
    /// Entropy bits threshold below which to inject (default: 256)
    #[arg(short = 't', long, default_value_t = 256)]
    pub threshold: u32,

    /// Poll interval in seconds (default: 5)
    #[arg(short = 'i', long, default_value_t = 5)]
    pub interval: u64,

    /// Bytes to inject per round (default: 64)
    #[arg(short = 'b', long, default_value_t = 64)]
    pub batch_size: usize,

    /// Bits of entropy credited per byte, 1-8 (default: 4)
    #[arg(short = 'c', long, default_value_t = 4, value_parser = clap::value_parser!(u32).range(1..=8))]
    pub credit_ratio: u32,

    /// Drop privileges to this user after opening /dev/random
    #[arg(long)]
    pub user: Option<String>,

    /// Path to PID file (checks for stale PIDs on startup)
    #[arg(long)]
    pub pid_file: Option<PathBuf>,

    /// Skip the startup self-test (not recommended).
    ///
    /// By default the daemon probes every configured source and runs a
    /// NIST SP 800-90B health pass on the samples before signaling READY
    /// to systemd. With this flag the daemon enters the main loop
    /// immediately; use only for debugging.
    #[arg(long, default_value_t = false)]
    pub no_self_test: bool,

    /// Configuration file path (default: /etc/mixrand.toml)
    #[arg(long = "config")]
    pub config_file: Option<PathBuf>,

    #[command(flatten)]
    pub cpu_rng: CpuRngArgs,

    #[command(flatten)]
    pub hsm: HsmArgs,

    #[command(flatten)]
    pub log: LogArgs,
}

#[derive(Debug, Parser)]
pub struct CheckArgs {
    /// Duration to run tests (e.g. 30s, 5m, 1h, 2d; bare number = minutes)
    #[arg(short = 'd', long, default_value = "1m")]
    pub duration: String,

    /// Bytes per sample (FIPS tests require >= 2500)
    #[arg(short = 's', long, default_value_t = 2500)]
    pub sample_size: usize,

    /// Progress report interval in seconds
    #[arg(short = 'r', long, default_value_t = 10)]
    pub report_interval: u64,

    /// Comma-separated list of sources to test (default: all available)
    #[arg(long, value_delimiter = ',')]
    pub sources: Option<Vec<String>>,

    /// Suppress progress output (only print final results)
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Output format for results
    #[arg(long = "output-format", value_enum, default_value_t = CheckOutputFormat::Text)]
    pub output_format: CheckOutputFormat,

    /// Configuration file path (default: /etc/mixrand.toml)
    #[arg(long = "config")]
    pub config_file: Option<PathBuf>,

    #[command(flatten)]
    pub cpu_rng: CpuRngArgs,

    #[command(flatten)]
    pub hsm: HsmArgs,

    #[command(flatten)]
    pub log: LogArgs,
}

#[derive(Debug, Parser)]
pub struct BenchArgs {
    /// Per-source benchmark duration (e.g. 3s, 30s, 2m, 1h; bare number = seconds)
    #[arg(short = 'd', long, default_value = "3s")]
    pub duration: String,

    /// Bytes per sample call
    #[arg(short = 's', long, default_value_t = 4096)]
    pub sample_size: usize,

    /// Optional byte budget per source (stops once reached)
    #[arg(long)]
    pub max_bytes: Option<u64>,

    /// Comma-separated list of sources to benchmark (default: all)
    #[arg(long, value_delimiter = ',')]
    pub sources: Option<Vec<String>>,

    /// Suppress progress chatter on stderr
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Output format for results
    #[arg(long = "output-format", value_enum, default_value_t = CheckOutputFormat::Text)]
    pub output_format: CheckOutputFormat,

    /// Configuration file path (default: /etc/mixrand.toml)
    #[arg(long = "config")]
    pub config_file: Option<PathBuf>,

    #[command(flatten)]
    pub cpu_rng: CpuRngArgs,

    #[command(flatten)]
    pub hsm: HsmArgs,

    #[command(flatten)]
    pub log: LogArgs,
}

#[derive(Debug, Parser)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: Shell,
}

#[derive(Debug, Parser)]
pub struct ListSourcesArgs {
    /// Configuration file path (default: /etc/mixrand.toml)
    #[arg(long = "config")]
    pub config_file: Option<PathBuf>,

    #[command(flatten)]
    pub cpu_rng: CpuRngArgs,

    #[command(flatten)]
    pub hsm: HsmArgs,

    #[command(flatten)]
    pub log: LogArgs,
}

/// Generate shell completions and write to stdout.
pub fn print_completions(shell: Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "mixrand", &mut std::io::stdout());
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parse_defaults() {
        let cli = Cli::try_parse_from(["mixrand"]).unwrap();
        assert_eq!(cli.bytes, 32);
        assert!(matches!(cli.format, OutputFormat::Hex));
        assert!(!cli.verbose);
        assert!(!cli.quiet);
        assert!(cli.command.is_none());
        assert!(cli.count.is_none());
        assert!(cli.output_file.is_none());
        assert!(cli.config_file.is_none());
        assert!(!cli.show_config);
    }

    #[test]
    fn test_cli_parse_with_args() {
        let cli = Cli::try_parse_from(["mixrand", "-n", "64", "-f", "base64", "-v"]).unwrap();
        assert_eq!(cli.bytes, 64);
        assert!(matches!(cli.format, OutputFormat::Base64));
        assert!(cli.verbose);
    }

    #[test]
    fn test_cli_parse_check_subcommand() {
        let cli = Cli::try_parse_from(["mixrand", "check", "-d", "30s"]).unwrap();
        match cli.command {
            Some(Command::Check(args)) => {
                assert_eq!(args.duration, "30s");
            }
            other => panic!("expected Some(Command::Check(_)), got {:?}", other),
        }
    }

    // ---- format variants ----

    #[test]
    fn test_every_output_format_parses() {
        for (arg, matcher) in [
            ("hex", |f| matches!(f, OutputFormat::Hex)),
            ("hex-upper", |f| matches!(f, OutputFormat::HexUpper)),
            ("raw", |f| matches!(f, OutputFormat::Raw)),
            ("base64", |f| matches!(f, OutputFormat::Base64)),
            ("base64url", |f| matches!(f, OutputFormat::Base64url)),
            ("uuencode", |f| matches!(f, OutputFormat::Uuencode)),
            ("text", |f| matches!(f, OutputFormat::Text)),
            ("octal", |f| matches!(f, OutputFormat::Octal)),
            ("binary", |f| matches!(f, OutputFormat::Binary)),
        ] as [(&str, fn(&OutputFormat) -> bool); 9]
        {
            let cli = Cli::try_parse_from(["mixrand", "-f", arg]).unwrap();
            assert!(matcher(&cli.format), "format {:?} did not match", arg);
        }
    }

    #[test]
    fn test_invalid_output_format_rejected() {
        let result = Cli::try_parse_from(["mixrand", "-f", "yaml"]);
        assert!(result.is_err());
    }

    // ---- flag defaults & overrides ----

    #[test]
    fn test_count_flag() {
        let cli = Cli::try_parse_from(["mixrand", "--count", "5"]).unwrap();
        assert_eq!(cli.count, Some(5));
    }

    #[test]
    fn test_output_file_flag() {
        let cli = Cli::try_parse_from(["mixrand", "-o", "/tmp/out.bin"]).unwrap();
        assert_eq!(
            cli.output_file.as_deref(),
            Some(std::path::Path::new("/tmp/out.bin"))
        );
    }

    #[test]
    fn test_config_file_flag() {
        let cli = Cli::try_parse_from(["mixrand", "--config", "/etc/test.toml"]).unwrap();
        assert_eq!(
            cli.config_file.as_deref(),
            Some(std::path::Path::new("/etc/test.toml"))
        );
    }

    #[test]
    fn test_show_config_flag() {
        let cli = Cli::try_parse_from(["mixrand", "--show-config"]).unwrap();
        assert!(cli.show_config);
    }

    #[test]
    fn test_quiet_verbose_mutually_exclusive() {
        let result = Cli::try_parse_from(["mixrand", "-q", "-v"]);
        assert!(result.is_err(), "-q and -v should be mutually exclusive");
    }

    // ---- CPU RNG flags ----

    #[test]
    fn test_cpu_rng_enable_flags_absent_default_none() {
        let cli = Cli::try_parse_from(["mixrand"]).unwrap();
        assert!(cli.cpu_rng.enable_rdseed.is_none());
        assert!(cli.cpu_rng.enable_rdrand.is_none());
        assert!(cli.cpu_rng.enable_xstore.is_none());
    }

    #[test]
    fn test_cpu_rng_enable_rdseed_bool_forms() {
        let t = Cli::try_parse_from(["mixrand", "--enable-rdseed", "true"]).unwrap();
        assert_eq!(t.cpu_rng.enable_rdseed, Some(true));
        let f = Cli::try_parse_from(["mixrand", "--enable-rdseed", "false"]).unwrap();
        assert_eq!(f.cpu_rng.enable_rdseed, Some(false));
        // Bare flag (default_missing_value="true")
        let bare = Cli::try_parse_from(["mixrand", "--enable-rdseed"]).unwrap();
        assert_eq!(bare.cpu_rng.enable_rdseed, Some(true));
    }

    #[test]
    fn test_cpu_rng_retries_flags() {
        let cli =
            Cli::try_parse_from(["mixrand", "--rdrand-retries", "7", "--rdseed-retries", "3"])
                .unwrap();
        assert_eq!(cli.cpu_rng.rdrand_retries, Some(7));
        assert_eq!(cli.cpu_rng.rdseed_retries, Some(3));
    }

    #[test]
    fn test_cpu_rng_prefer_enum() {
        let cli = Cli::try_parse_from(["mixrand", "--cpu-rng-prefer", "rdrand"]).unwrap();
        assert_eq!(cli.cpu_rng.cpu_rng_prefer, Some(CpuRngPreference::Rdrand));
    }

    #[test]
    fn test_cpu_rng_prefer_invalid_rejected() {
        let result = Cli::try_parse_from(["mixrand", "--cpu-rng-prefer", "notarealthing"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpu_rng_mixer_mode_enum() {
        let cli = Cli::try_parse_from(["mixrand", "--mixer-mode", "hkdf"]).unwrap();
        assert_eq!(cli.cpu_rng.mixer_mode, Some(MixerMode::Hkdf));
    }

    #[test]
    fn test_cpu_rng_oversample_and_fallback_bytes() {
        let cli = Cli::try_parse_from([
            "mixrand",
            "--oversample",
            "4",
            "--fallback-mix-bytes",
            "128",
        ])
        .unwrap();
        assert_eq!(cli.cpu_rng.oversample, Some(4));
        assert_eq!(cli.cpu_rng.fallback_mix_bytes, Some(128));
    }

    // ---- HSM flags ----

    #[test]
    fn test_hsm_enable_flags() {
        let cli = Cli::try_parse_from([
            "mixrand",
            "--enable-tpm2",
            "false",
            "--enable-pkcs11",
            "true",
            "--enable-gnupg",
            "--enable-sgx",
        ])
        .unwrap();
        assert_eq!(cli.hsm.enable_tpm2, Some(false));
        assert_eq!(cli.hsm.enable_pkcs11, Some(true));
        assert_eq!(cli.hsm.enable_gnupg, Some(true));
        assert_eq!(cli.hsm.enable_sgx, Some(true));
    }

    #[test]
    fn test_hsm_pkcs11_library_and_tpm2_device() {
        let cli = Cli::try_parse_from([
            "mixrand",
            "--pkcs11-library",
            "/usr/lib/foo.so",
            "--tpm2-device",
            "/dev/tpmrm1",
        ])
        .unwrap();
        assert_eq!(cli.hsm.pkcs11_library.as_deref(), Some("/usr/lib/foo.so"));
        assert_eq!(cli.hsm.tpm2_device.as_deref(), Some("/dev/tpmrm1"));
    }

    // ---- Subcommands ----

    #[test]
    fn test_daemon_subcommand_defaults() {
        let cli = Cli::try_parse_from(["mixrand", "daemon"]).unwrap();
        match cli.command {
            Some(Command::Daemon(args)) => {
                assert_eq!(args.threshold, 256);
                assert_eq!(args.interval, 5);
                assert_eq!(args.batch_size, 64);
                assert_eq!(args.credit_ratio, 4);
                assert!(args.user.is_none());
                assert!(args.pid_file.is_none());
            }
            other => panic!("expected Daemon(_), got {:?}", other),
        }
    }

    #[test]
    fn test_daemon_credit_ratio_bounds() {
        let too_low = Cli::try_parse_from(["mixrand", "daemon", "-c", "0"]);
        assert!(too_low.is_err());
        let too_high = Cli::try_parse_from(["mixrand", "daemon", "-c", "9"]);
        assert!(too_high.is_err());
        let ok = Cli::try_parse_from(["mixrand", "daemon", "-c", "8"]).unwrap();
        match ok.command {
            Some(Command::Daemon(args)) => assert_eq!(args.credit_ratio, 8),
            _ => panic!(),
        }
    }

    #[test]
    fn test_daemon_user_and_pidfile() {
        let cli = Cli::try_parse_from([
            "mixrand",
            "daemon",
            "--user",
            "_entropy",
            "--pid-file",
            "/run/m.pid",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Daemon(args)) => {
                assert_eq!(args.user.as_deref(), Some("_entropy"));
                assert_eq!(
                    args.pid_file.as_deref(),
                    Some(std::path::Path::new("/run/m.pid"))
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_check_subcommand_defaults() {
        let cli = Cli::try_parse_from(["mixrand", "check"]).unwrap();
        match cli.command {
            Some(Command::Check(args)) => {
                assert_eq!(args.duration, "1m");
                assert_eq!(args.sample_size, 2500);
                assert_eq!(args.report_interval, 10);
                assert!(args.sources.is_none());
                assert!(!args.quiet);
                assert!(matches!(args.output_format, CheckOutputFormat::Text));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_check_output_format_variants() {
        for (arg, matcher) in [
            ("text", |f| matches!(f, CheckOutputFormat::Text)),
            ("json", |f| matches!(f, CheckOutputFormat::Json)),
            ("csv", |f| matches!(f, CheckOutputFormat::Csv)),
        ] as [(&str, fn(&CheckOutputFormat) -> bool); 3]
        {
            let cli = Cli::try_parse_from(["mixrand", "check", "--output-format", arg]).unwrap();
            match cli.command {
                Some(Command::Check(a)) => assert!(matcher(&a.output_format)),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn test_check_comma_separated_sources() {
        let cli = Cli::try_parse_from(["mixrand", "check", "--sources", "hwrng,cpurng,fallback"])
            .unwrap();
        match cli.command {
            Some(Command::Check(args)) => {
                let s = args.sources.unwrap();
                assert_eq!(s, vec!["hwrng", "cpurng", "fallback"]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_completions_subcommand() {
        let cli = Cli::try_parse_from(["mixrand", "completions", "bash"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Completions(_))));
    }

    #[test]
    fn test_completions_rejects_invalid_shell() {
        let result = Cli::try_parse_from(["mixrand", "completions", "cmd"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_sources_subcommand() {
        let cli = Cli::try_parse_from(["mixrand", "list-sources"]).unwrap();
        assert!(matches!(cli.command, Some(Command::ListSources(_))));
    }

    #[test]
    fn test_bytes_zero_accepted_by_parser() {
        // Parser does not reject 0; main.rs enforces the minimum at runtime.
        let cli = Cli::try_parse_from(["mixrand", "-n", "0"]).unwrap();
        assert_eq!(cli.bytes, 0);
    }

    #[test]
    fn test_args_conflict_with_subcommand() {
        // With args_conflicts_with_subcommands, providing main-level args alongside
        // a subcommand must fail.
        let result = Cli::try_parse_from(["mixrand", "-n", "32", "daemon"]);
        assert!(result.is_err());
    }
}
