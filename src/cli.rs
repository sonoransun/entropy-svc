use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::CpuRngPreference;
use crate::logging::LogArgs;

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// Hexadecimal (lowercase)
    Hex,
    /// Raw binary bytes
    Raw,
    /// Base64 (standard, with padding)
    Base64,
    /// Base64 URL-safe (no padding)
    Base64url,
    /// uuencode format
    Uuencode,
    /// Printable ASCII text (alphanumeric + symbols)
    Text,
    /// Octal bytes separated by spaces
    Octal,
    /// Binary bit strings separated by spaces
    Binary,
    /// Uppercase hexadecimal
    HexUpper,
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

    /// RDRAND retry count (1-100)
    #[arg(long)]
    pub rdrand_retries: Option<u32>,

    /// RDSEED retry count (1-100)
    #[arg(long)]
    pub rdseed_retries: Option<u32>,

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
}

#[derive(Debug, Parser)]
#[command(name = "mixrand", about = "Secure random byte generator for Linux")]
#[command(args_conflicts_with_subcommands = true)]
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

    /// Configuration file path (default: /etc/mixrand.toml)
    #[arg(long = "config")]
    pub config_file: Option<PathBuf>,

    #[command(flatten)]
    pub cpu_rng: CpuRngArgs,

    #[command(flatten)]
    pub log: LogArgs,
}
