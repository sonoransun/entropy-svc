use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::config::{CpuRngPreference, MixerMode};
use crate::logging::LogArgs;

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

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CheckOutputFormat {
    /// Human-readable text (default)
    Text,
    /// JSON
    Json,
    /// CSV
    Csv,
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

    /// Configuration file path (default: /etc/mixrand.toml)
    #[arg(long = "config")]
    pub config_file: Option<PathBuf>,

    #[command(flatten)]
    pub cpu_rng: CpuRngArgs,

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
        assert_eq!(cli.verbose, false);
        assert_eq!(cli.quiet, false);
        assert!(cli.command.is_none());
        assert!(cli.count.is_none());
    }

    #[test]
    fn test_cli_parse_with_args() {
        let cli = Cli::try_parse_from(["mixrand", "-n", "64", "-f", "base64", "-v"]).unwrap();
        assert_eq!(cli.bytes, 64);
        assert!(matches!(cli.format, OutputFormat::Base64));
        assert_eq!(cli.verbose, true);
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
}
