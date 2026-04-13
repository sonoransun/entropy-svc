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

use cli::{Cli, Command, CpuRngArgs, HsmArgs};
use config::Config;

/// Build a full Config by layering: defaults -> TOML file -> env vars -> CLI overrides.
fn build_config(
    config_file: Option<&Path>,
    cpu_rng_args: &CpuRngArgs,
    hsm_args: &HsmArgs,
) -> Config {
    let mut full_cfg = match config::load_config(config_file) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("{}", e);
            Config::default()
        }
    };

    // Apply environment variable overrides
    config::apply_env_overrides(&mut full_cfg.cpu_rng);
    config::apply_hsm_env_overrides(&mut full_cfg.hsm);

    // Apply CPU RNG CLI overrides (only if explicitly set)
    let cfg = &mut full_cfg.cpu_rng;
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

    // Apply HSM CLI overrides (only if explicitly set)
    let hsm = &mut full_cfg.hsm;
    if let Some(v) = hsm_args.enable_tpm2 {
        hsm.tpm2.enabled = v;
    }
    if let Some(v) = hsm_args.enable_pkcs11 {
        hsm.pkcs11.enabled = v;
    }
    if let Some(v) = hsm_args.enable_pcsc {
        hsm.pcsc.enabled = v;
    }
    if let Some(v) = hsm_args.enable_yubikey {
        hsm.yubikey.enabled = v;
    }
    if let Some(v) = hsm_args.enable_gnupg {
        hsm.gnupg.enabled = v;
    }
    if let Some(v) = hsm_args.enable_yubihsm {
        hsm.yubihsm.enabled = v;
    }
    if let Some(v) = hsm_args.enable_sgx {
        hsm.sgx.enabled = v;
    }
    if let Some(ref v) = hsm_args.pkcs11_library {
        hsm.pkcs11.library_path = Some(v.clone());
    }
    if let Some(ref v) = hsm_args.tpm2_device {
        hsm.tpm2.tcti = Some(format!("device:{}", v));
    }

    let cpu_warnings = full_cfg.cpu_rng.validate();
    for w in cpu_warnings {
        log::warn!("config: {}", w);
    }
    let hsm_warnings = full_cfg.hsm.validate();
    for w in hsm_warnings {
        log::warn!("config: {}", w);
    }
    full_cfg
}

/// Maximum byte count per generation (100 MiB).
const MAX_BYTES: usize = 100 * 1024 * 1024;

/// Maximum iteration count for --count flag.
const MAX_COUNT: usize = 10_000;

fn run_generate(cli: &Cli, config: &Config) {
    if cli.bytes == 0 {
        log::error!("byte count must be greater than 0");
        process::exit(1);
    }
    if cli.bytes > MAX_BYTES {
        log::error!(
            "byte count {} exceeds maximum {} (100 MiB)",
            cli.bytes, MAX_BYTES
        );
        process::exit(1);
    }

    let iterations = cli.count.unwrap_or(1).max(1);
    if iterations > MAX_COUNT {
        log::error!("--count {} exceeds maximum {}", iterations, MAX_COUNT);
        process::exit(1);
    }

    for _ in 0..iterations {
        match entropy::generate(cli.bytes, config) {
            Ok(result) => {
                log::info!("entropy source: {}", result.source);
                let mut bytes = result.bytes;
                let write_result =
                    output::write_output(&bytes, &cli.format, cli.output_file.as_deref());
                entropy::cpurng::zeroize_vec(&mut bytes);
                if let Err(e) = write_result {
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

fn run_list_sources(config: &Config) {
    const PROBE_BYTES: usize = 32;
    let sources = entropy::build_check_sources(config);
    println!("{:<12} {:<10} {:<10} Description", "Name", "Status", "Type");
    println!("{:-<12} {:-<10} {:-<10} {:-<50}", "", "", "", "");
    for source in &sources {
        let (status, detail) = match source.collect(PROBE_BYTES) {
            Ok(_) => ("available", String::new()),
            Err(e) => ("skip", format!(" ({})", e)),
        };
        println!(
            "{:<12} {:<10} {:<10} {}{}",
            source.name(),
            status,
            source.source_type(),
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
            let config =
                build_config(args.config_file.as_deref(), &args.cpu_rng, &args.hsm);
            if let Err(e) = daemon::run(args, &config) {
                log::error!("{}", e);
                process::exit(1);
            }
        }
        Some(Command::Check(args)) => {
            logging::init(&args.log, false);
            let config =
                build_config(args.config_file.as_deref(), &args.cpu_rng, &args.hsm);
            if let Err(e) = check::run(args, &config) {
                log::error!("{}", e);
                process::exit(1);
            }
        }
        Some(Command::ListSources(args)) => {
            logging::init(&args.log, false);
            let config =
                build_config(args.config_file.as_deref(), &args.cpu_rng, &args.hsm);
            run_list_sources(&config);
        }
        None => {
            let mut log_args = cli.log.clone();
            log_args.log_level = effective_log_level(&cli.log, cli.verbose, cli.quiet);
            logging::init(&log_args, false);
            let config =
                build_config(cli.config_file.as_deref(), &cli.cpu_rng, &cli.hsm);

            if cli.show_config {
                println!("{}", toml::to_string_pretty(&config.cpu_rng).unwrap_or_else(|_| format!("{:?}", config.cpu_rng)));
                return;
            }

            run_generate(&cli, &config);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::CpuRngConfig;

    fn default_log_args() -> logging::LogArgs {
        logging::LogArgs {
            log_level: None,
            log_file: None,
            syslog: false,
            log_format: logging::LogFormat::Text,
        }
    }

    fn default_cpu_rng_args() -> CpuRngArgs {
        CpuRngArgs {
            enable_rdseed: None,
            enable_rdrand: None,
            enable_xstore: None,
            enable_rndr: None,
            enable_rndrrs: None,
            rdrand_retries: None,
            rdseed_retries: None,
            rndr_retries: None,
            rndrrs_retries: None,
            xstore_quality: None,
            cpu_rng_prefer: None,
            fallback_mix_bytes: None,
            oversample: None,
            mixer_mode: None,
        }
    }

    fn default_hsm_args() -> HsmArgs {
        HsmArgs {
            enable_tpm2: None,
            enable_pkcs11: None,
            enable_pcsc: None,
            enable_yubikey: None,
            enable_gnupg: None,
            enable_yubihsm: None,
            enable_sgx: None,
            pkcs11_library: None,
            tpm2_device: None,
        }
    }

    #[test]
    fn test_effective_log_level_verbose() {
        let args = default_log_args();
        assert!(matches!(
            effective_log_level(&args, true, false),
            Some(logging::LogLevel::Debug)
        ));
    }

    #[test]
    fn test_effective_log_level_quiet() {
        let args = default_log_args();
        assert!(matches!(
            effective_log_level(&args, false, true),
            Some(logging::LogLevel::Error)
        ));
    }

    #[test]
    fn test_effective_log_level_explicit() {
        let mut args = default_log_args();
        args.log_level = Some(logging::LogLevel::Info);
        assert!(matches!(
            effective_log_level(&args, false, false),
            Some(logging::LogLevel::Info)
        ));
    }

    #[test]
    fn test_effective_log_level_none() {
        let args = default_log_args();
        assert!(effective_log_level(&args, false, false).is_none());
    }

    #[test]
    fn test_build_config_defaults_no_file() {
        let args = default_cpu_rng_args();
        let hsm = default_hsm_args();
        let cfg = build_config(None, &args, &hsm);
        let default = CpuRngConfig::default();
        assert_eq!(cfg.cpu_rng.enable_rdseed, default.enable_rdseed);
        assert_eq!(cfg.cpu_rng.rdrand_retries, default.rdrand_retries);
        assert_eq!(cfg.cpu_rng.oversample, default.oversample);
    }

    #[test]
    fn test_build_config_cli_overrides() {
        let mut args = default_cpu_rng_args();
        args.enable_rdseed = Some(false);
        args.rdrand_retries = Some(50);
        let hsm = default_hsm_args();
        let cfg = build_config(None, &args, &hsm);
        assert!(!cfg.cpu_rng.enable_rdseed);
        assert_eq!(cfg.cpu_rng.rdrand_retries, 50);
        // Unset fields remain default
        assert!(cfg.cpu_rng.enable_rdrand);
    }

    #[test]
    fn test_build_config_validates() {
        let mut args = default_cpu_rng_args();
        args.rdrand_retries = Some(200);
        let hsm = default_hsm_args();
        let cfg = build_config(None, &args, &hsm);
        assert_eq!(cfg.cpu_rng.rdrand_retries, 100); // clamped from 200
    }

    #[test]
    fn test_build_config_hsm_overrides() {
        let args = default_cpu_rng_args();
        let mut hsm = default_hsm_args();
        hsm.enable_tpm2 = Some(false);
        hsm.pkcs11_library = Some("/usr/lib/test.so".into());
        let cfg = build_config(None, &args, &hsm);
        assert!(!cfg.hsm.tpm2.enabled);
        assert_eq!(cfg.hsm.pkcs11.library_path.as_deref(), Some("/usr/lib/test.so"));
    }
}
