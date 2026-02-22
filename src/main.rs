mod check;
mod cli;
mod config;
mod csprng;
mod daemon;
mod entropy;
mod error;
mod health;
mod logging;
mod memlock;
mod mixer;
mod output;
mod stats;

use std::path::Path;
use std::process;

use clap::Parser;

use cli::{Cli, Command, CpuRngArgs};
use config::CpuRngConfig;

/// Build a CpuRngConfig by layering: defaults -> TOML file -> env vars -> CLI overrides.
fn build_cpu_rng_config(config_file: Option<&Path>, cpu_rng_args: &CpuRngArgs) -> CpuRngConfig {
    let mut cfg = match config::load_config(config_file) {
        Ok(c) => c.cpu_rng,
        Err(e) => {
            log::warn!("{}", e);
            CpuRngConfig::default()
        }
    };

    // Apply environment variable overrides
    config::apply_env_overrides(&mut cfg);

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
    if let Some(v) = cpu_rng_args.enable_rndr {
        cfg.enable_rndr = v;
    }
    if let Some(v) = cpu_rng_args.enable_rndrrs {
        cfg.enable_rndrrs = v;
    }
    if let Some(v) = cpu_rng_args.rdrand_retries {
        cfg.rdrand_retries = v;
    }
    if let Some(v) = cpu_rng_args.rdseed_retries {
        cfg.rdseed_retries = v;
    }
    if let Some(v) = cpu_rng_args.rndr_retries {
        cfg.rndr_retries = v;
    }
    if let Some(v) = cpu_rng_args.rndrrs_retries {
        cfg.rndrrs_retries = v;
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
    if let Some(v) = cpu_rng_args.mixer_mode {
        cfg.mixer_mode = v;
    }

    let warnings = cfg.validate();
    for w in warnings {
        log::warn!("config: {}", w);
    }
    cfg
}

fn run_generate(cli: &Cli, cpu_config: &CpuRngConfig) {
    if cli.bytes == 0 {
        log::error!("byte count must be greater than 0");
        process::exit(1);
    }

    let iterations = cli.count.unwrap_or(1).max(1);

    for _ in 0..iterations {
        match entropy::generate(cli.bytes, cpu_config) {
            Ok(result) => {
                log::info!("entropy source: {}", result.source);
                if let Err(e) =
                    output::write_output(&result.bytes, &cli.format, cli.output_file.as_deref())
                {
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
}

fn run_list_sources(cpu_config: &CpuRngConfig) {
    let sources = entropy::build_check_sources(cpu_config);
    println!("{:<12} {:<10} Description", "Name", "Status");
    println!("{:-<12} {:-<10} {:-<50}", "", "", "");
    for source in &sources {
        let (status, detail) = match source.collect(32) {
            Ok(_) => ("available", String::new()),
            Err(e) => ("skip", format!(" ({})", e)),
        };
        println!(
            "{:<12} {:<10} {}{}",
            source.name(),
            status,
            source.description(),
            detail
        );
    }
}

fn effective_log_level(cli_log: &logging::LogArgs, verbose: bool, quiet: bool) -> Option<logging::LogLevel> {
    if verbose {
        Some(logging::LogLevel::Debug)
    } else if quiet {
        Some(logging::LogLevel::Error)
    } else {
        cli_log.log_level
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Command::Completions(args)) => {
            cli::print_completions(args.shell);
        }
        Some(Command::Daemon(args)) => {
            let mut log_args = args.log.clone();
            if log_args.log_level.is_none() {
                log_args.log_level = Some(logging::LogLevel::Info);
            }
            logging::init(&log_args, true);
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
        Some(Command::ListSources(args)) => {
            logging::init(&args.log, false);
            let cpu_config =
                build_cpu_rng_config(args.config_file.as_deref(), &args.cpu_rng);
            run_list_sources(&cpu_config);
        }
        None => {
            let mut log_args = cli.log.clone();
            log_args.log_level = effective_log_level(&cli.log, cli.verbose, cli.quiet);
            logging::init(&log_args, false);
            let cpu_config =
                build_cpu_rng_config(cli.config_file.as_deref(), &cli.cpu_rng);

            if cli.show_config {
                println!("{}", toml::to_string_pretty(&cpu_config).unwrap_or_else(|_| format!("{:?}", cpu_config)));
                return;
            }

            run_generate(&cli, &cpu_config);
        }
    }
}
