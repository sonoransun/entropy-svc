//! `bench` subcommand — measure throughput of each entropy source.
//!
//! Runs each configured source for a bounded duration (or byte budget),
//! counting samples and total bytes collected. Reports per-source throughput
//! (MB/s) and sample rate in text, JSON, or CSV. Unlike `check`, `bench`
//! does NOT run statistical tests — it only measures how fast each source
//! can produce bytes.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::cli::{BenchArgs, CheckOutputFormat};
use crate::config::Config;
use crate::entropy::{self, EntropySource};
use crate::error::Error;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Release);
}

fn install_signal_handlers() {
    #[cfg(unix)]
    unsafe {
        libc::signal(
            libc::SIGINT,
            signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            signal_handler as *const () as libc::sighandler_t,
        );
    }
}

fn parse_duration(s: &str) -> Result<Duration, Error> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::InvalidArgs("empty duration".into()));
    }
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else {
        (s, 1) // bare = seconds for bench (shorter by nature than check)
    };
    let num: u64 = num_str
        .parse()
        .map_err(|_| Error::InvalidArgs(format!("invalid duration: {}", s)))?;
    if num == 0 {
        return Err(Error::InvalidArgs("duration must be > 0".into()));
    }
    Ok(Duration::from_secs(num * multiplier))
}

fn format_throughput(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_000_000.0 {
        format!("{:.2} MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec >= 1_000.0 {
        format!("{:.2} KB/s", bytes_per_sec / 1_000.0)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.2} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

#[derive(Serialize)]
struct BenchResult {
    name: String,
    description: String,
    samples: u64,
    bytes: u64,
    errors: u64,
    duration_secs: f64,
    throughput_bytes_per_sec: f64,
    samples_per_sec: f64,
    latency_us_per_sample: f64,
}

fn run_bench_source(
    source: &dyn EntropySource,
    deadline: Instant,
    sample_size: usize,
    max_bytes: Option<u64>,
) -> BenchResult {
    let start = Instant::now();
    let mut samples = 0u64;
    let mut bytes = 0u64;
    let mut errors = 0u64;

    while !SHUTDOWN.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            break;
        }
        if let Some(limit) = max_bytes {
            if bytes >= limit {
                break;
            }
        }
        match source.collect(sample_size) {
            Ok(buf) => {
                samples += 1;
                bytes += buf.len() as u64;
            }
            Err(_) => {
                errors += 1;
                // Don't retry a source that can't produce a single sample.
                if samples == 0 && errors >= 3 {
                    break;
                }
            }
        }
    }

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64().max(f64::EPSILON);
    BenchResult {
        name: source.name().to_string(),
        description: source.description().to_string(),
        samples,
        bytes,
        errors,
        duration_secs: elapsed.as_secs_f64(),
        throughput_bytes_per_sec: bytes as f64 / secs,
        samples_per_sec: samples as f64 / secs,
        latency_us_per_sample: if samples > 0 {
            elapsed.as_secs_f64() * 1_000_000.0 / samples as f64
        } else {
            0.0
        },
    }
}

fn output_text(results: &[BenchResult], out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "{:<12} {:>10} {:>12} {:>14} {:>14} {:>12} {:>6}",
        "Source", "Samples", "Bytes", "Throughput", "Samples/s", "Latency", "Errs"
    )?;
    writeln!(
        out,
        "{:-<12} {:->10} {:->12} {:->14} {:->14} {:->12} {:->6}",
        "", "", "", "", "", "", ""
    )?;
    for r in results {
        writeln!(
            out,
            "{:<12} {:>10} {:>12} {:>14} {:>14} {:>10.1}us {:>6}",
            r.name,
            r.samples,
            format_bytes(r.bytes),
            format_throughput(r.throughput_bytes_per_sec),
            format!("{:.0}", r.samples_per_sec),
            r.latency_us_per_sample,
            r.errors
        )?;
    }
    Ok(())
}

fn output_json(results: &[BenchResult], out: &mut dyn Write) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(results).map_err(std::io::Error::other)?;
    writeln!(out, "{}", json)
}

fn output_csv(results: &[BenchResult], out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "name,description,samples,bytes,errors,duration_secs,throughput_bytes_per_sec,samples_per_sec,latency_us_per_sample"
    )?;
    for r in results {
        writeln!(
            out,
            "{},{:?},{},{},{},{:.6},{:.2},{:.2},{:.2}",
            r.name,
            r.description,
            r.samples,
            r.bytes,
            r.errors,
            r.duration_secs,
            r.throughput_bytes_per_sec,
            r.samples_per_sec,
            r.latency_us_per_sample
        )?;
    }
    Ok(())
}

/// Entry point for the `bench` subcommand.
pub fn run(args: &BenchArgs, config: &Config) -> Result<(), Error> {
    install_signal_handlers();

    let per_source = parse_duration(&args.duration)?;
    let sample_size = args.sample_size.max(1);
    let max_bytes = args.max_bytes;

    let mut sources = entropy::build_check_sources(config);
    if let Some(filter) = &args.sources {
        let filter_lc: Vec<String> = filter.iter().map(|s| s.to_lowercase()).collect();
        sources.retain(|s| filter_lc.iter().any(|f| s.name().eq_ignore_ascii_case(f)));
        if sources.is_empty() {
            return Err(Error::InvalidArgs(format!(
                "no sources match filter: {:?}",
                filter
            )));
        }
    }

    let mut results = Vec::with_capacity(sources.len());
    for source in &sources {
        if SHUTDOWN.load(Ordering::Acquire) {
            break;
        }
        if !args.quiet {
            eprintln!("benchmarking {}...", source.name());
        }
        let deadline = Instant::now() + per_source;
        let result = run_bench_source(source.as_ref(), deadline, sample_size, max_bytes);
        results.push(result);
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match args.output_format {
        CheckOutputFormat::Text => output_text(&results, &mut out)?,
        CheckOutputFormat::Json => output_json(&results, &mut out)?,
        CheckOutputFormat::Csv => output_csv(&results, &mut out)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_seconds_default() {
        assert_eq!(parse_duration("5").unwrap(), Duration::from_secs(5));
    }

    #[test]
    fn test_parse_duration_suffixed() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_rejects_zero_and_empty() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("0s").is_err());
    }

    #[test]
    fn test_format_throughput_units() {
        assert!(format_throughput(500.0).ends_with("B/s"));
        assert!(format_throughput(5000.0).ends_with("KB/s"));
        assert!(format_throughput(5_000_000.0).ends_with("MB/s"));
    }

    #[test]
    fn test_format_bytes_units() {
        assert_eq!(format_bytes(42), "42 B");
        assert_eq!(format_bytes(1500), "1.50 KB");
        assert_eq!(format_bytes(2_500_000), "2.50 MB");
    }
}
