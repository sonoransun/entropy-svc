mod check;
mod cli;
mod config;
mod csprng;
mod daemon;
mod entropy;
mod error;
mod logging;
mod mixer;
mod output;
mod stats;

use std::path::Path;
use std::process;

use clap::Parser;

use cli::{Cli, Command, CpuRngArgs};
use config::CpuRngConfig;

/// Build a CpuRngConfig by layering: defaults → TOML file → CLI overrides.
fn build_cpu_rng_config(config_file: Option<&Path>, cpu_rng_args: &CpuRngArgs) -> CpuRngConfig {
    let mut cfg = match config::load_config(config_file) {
        Ok(c) => c.cpu_rng,
        Err(e) => {
            log::warn!("{}", e);
            CpuRngConfig::default()
        }
    };

    // Apply CLI overrides (only if explicitly set)
    if let Some(v) = cpu_rng_args.enable_rdseed {
        cfg.enable_rdseed = v;
    }
    if let Some(v) = cpu_rng_args.enable_rdrand {
        cfg.enable_rdrand = v;
    }
    if let Some(v) = cpu_rng_args.enable_xstore {
        cfg.enable_xstore = v;
    }
    if let Some(v) = cpu_rng_args.rdrand_retries {
        cfg.rdrand_retries = v;
    }
    if let Some(v) = cpu_rng_args.rdseed_retries {
        cfg.rdseed_retries = v;
    }
    if let Some(v) = cpu_rng_args.xstore_quality {
        cfg.xstore_quality = v;
    }
    if let Some(v) = cpu_rng_args.cpu_rng_prefer {
        cfg.prefer = v;
    }
    if let Some(v) = cpu_rng_args.fallback_mix_bytes {
        cfg.fallback_mix_bytes = v;
    }
    if let Some(v) = cpu_rng_args.oversample {
        cfg.oversample = v;
    }

    cfg.validate();
    cfg
}

fn run_generate(cli: &Cli, cpu_config: &CpuRngConfig) {
    if cli.bytes == 0 {
        log::error!("byte count must be greater than 0");
        process::exit(1);
    }

    match entropy::generate(cli.bytes, cpu_config) {
        Ok(result) => {
            log::info!("entropy source: {}", result.source);
            if let Err(e) = output::write_output(&result.bytes, &cli.format, cli.output_file.as_deref()) {
                log::error!("error writing output: {}", e);
                process::exit(1);
            }
        }
        Err(e) => {
            log::error!("{}", e);
            process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Command::Daemon(args)) => {
            logging::init(&args.log, true);
            let cpu_config =
                build_cpu_rng_config(args.config_file.as_deref(), &args.cpu_rng);
            if let Err(e) = daemon::run(args, &cpu_config) {
                log::error!("{}", e);
                process::exit(1);
            }
        }
        Some(Command::Check(args)) => {
            logging::init(&args.log, false);
            let cpu_config =
                build_cpu_rng_config(args.config_file.as_deref(), &args.cpu_rng);
            if let Err(e) = check::run(args, &cpu_config) {
                log::error!("{}", e);
                process::exit(1);
            }
        }
        None => {
            logging::init(&cli.log, false);
            let cpu_config =
                build_cpu_rng_config(cli.config_file.as_deref(), &cli.cpu_rng);
            run_generate(&cli, &cpu_config);
        }
    }
}
