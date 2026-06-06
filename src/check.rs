use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::cli::{CheckArgs, CheckOutputFormat};
use crate::config::Config;
use crate::entropy::{self, EntropySource};
use crate::error::Error;
use crate::stats;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

struct SourceStats {
    total_samples: u64,
    total_bytes: u64,
    total_time: Duration,
    fips_monobit_pass: u64,
    fips_poker_pass: u64,
    fips_runs_pass: u64,
    fips_long_runs_pass: u64,
    fips_all_pass: u64,
    shannon_sum: f64,
    min_entropy_sum: f64,
    chi_square_sum: f64,
    mean_sum: f64,
    serial_corr_sum: f64,
    approx_entropy_m2_sum: f64,
    approx_entropy_m3_sum: f64,
    compression_ratio_sum: f64,
    block_entropy_2_sum: f64,
    block_entropy_4_sum: f64,
    errors: u64,
}

impl SourceStats {
    fn new() -> Self {
        Self {
            total_samples: 0,
            total_bytes: 0,
            total_time: Duration::ZERO,
            fips_monobit_pass: 0,
            fips_poker_pass: 0,
            fips_runs_pass: 0,
            fips_long_runs_pass: 0,
            fips_all_pass: 0,
            shannon_sum: 0.0,
            min_entropy_sum: 0.0,
            chi_square_sum: 0.0,
            mean_sum: 0.0,
            serial_corr_sum: 0.0,
            approx_entropy_m2_sum: 0.0,
            approx_entropy_m3_sum: 0.0,
            compression_ratio_sum: 0.0,
            block_entropy_2_sum: 0.0,
            block_entropy_4_sum: 0.0,
            errors: 0,
        }
    }

    fn fips_pass_pct(&self, pass_count: u64) -> f64 {
        if self.total_samples == 0 {
            return 0.0;
        }
        100.0 * pass_count as f64 / self.total_samples as f64
    }

    fn avg(&self, sum: f64) -> f64 {
        if self.total_samples == 0 {
            return 0.0;
        }
        sum / self.total_samples as f64
    }

    fn throughput_bytes_per_sec(&self) -> f64 {
        let secs = self.total_time.as_secs_f64();
        if secs < f64::EPSILON {
            return 0.0;
        }
        self.total_bytes as f64 / secs
    }
}

/// Serializable result for a single source (used for JSON/CSV output).
#[derive(Serialize)]
struct SourceResult {
    name: String,
    description: String,
    samples: u64,
    bytes: u64,
    throughput_bytes_per_sec: f64,
    errors: u64,
    fips_monobit_pct: f64,
    fips_poker_pct: f64,
    fips_runs_pct: f64,
    fips_long_runs_pct: f64,
    fips_all_pct: f64,
    shannon: f64,
    min_entropy: f64,
    chi_square: f64,
    chi_square_p: f64,
    mean: f64,
    serial_correlation: f64,
    approx_entropy_m2: f64,
    approx_entropy_m3: f64,
    compression_ratio: f64,
    block_entropy_2: f64,
    block_entropy_4: f64,
}

/// Top-level serializable check result.
#[derive(Serialize)]
struct CheckResult {
    duration_secs: f64,
    sample_size: usize,
    fips_enabled: bool,
    sources: Vec<SourceResult>,
}

fn build_source_result(source: &dyn EntropySource, stat: &SourceStats) -> SourceResult {
    let chi = stat.avg(stat.chi_square_sum);
    SourceResult {
        name: source.name().to_string(),
        description: source.description().to_string(),
        samples: stat.total_samples,
        bytes: stat.total_bytes,
        throughput_bytes_per_sec: stat.throughput_bytes_per_sec(),
        errors: stat.errors,
        fips_monobit_pct: stat.fips_pass_pct(stat.fips_monobit_pass),
        fips_poker_pct: stat.fips_pass_pct(stat.fips_poker_pass),
        fips_runs_pct: stat.fips_pass_pct(stat.fips_runs_pass),
        fips_long_runs_pct: stat.fips_pass_pct(stat.fips_long_runs_pass),
        fips_all_pct: stat.fips_pass_pct(stat.fips_all_pass),
        shannon: stat.avg(stat.shannon_sum),
        min_entropy: stat.avg(stat.min_entropy_sum),
        chi_square: chi,
        chi_square_p: stats::chi_square_p_value(chi, 255.0),
        mean: stat.avg(stat.mean_sum),
        serial_correlation: stat.avg(stat.serial_corr_sum),
        approx_entropy_m2: stat.avg(stat.approx_entropy_m2_sum),
        approx_entropy_m3: stat.avg(stat.approx_entropy_m3_sum),
        compression_ratio: stat.avg(stat.compression_ratio_sum),
        block_entropy_2: stat.avg(stat.block_entropy_2_sum),
        block_entropy_4: stat.avg(stat.block_entropy_4_sum),
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
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86400)
    } else {
        (s, 60) // bare number = minutes
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| Error::InvalidArgs(format!("invalid duration: {}", s)))?;

    if num == 0 {
        return Err(Error::InvalidArgs("duration must be > 0".into()));
    }

    Ok(Duration::from_secs(num * multiplier))
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        if s == 0 {
            format!("{}m", m)
        } else {
            format!("{}m {}s", m, s)
        }
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m == 0 {
            format!("{}h", h)
        } else {
            format!("{}h {}m", h, m)
        }
    }
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

#[cfg(unix)]
extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Release);
}

fn install_signal_handlers() {
    #[cfg(unix)]
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

/// Probe all sources, printing availability status and returning available ones.
fn probe_sources(
    all_sources: Vec<Box<dyn EntropySource>>,
    quiet: bool,
) -> Vec<Box<dyn EntropySource>> {
    let mut available = Vec::new();

    for source in all_sources {
        if !quiet {
            eprint!("  {:10} ... ", source.name());
        }
        match source.collect(32) {
            Ok(_) => {
                if !quiet {
                    eprintln!("[ok]");
                }
                available.push(source);
            }
            Err(e) => {
                if !quiet {
                    eprintln!("[skip] {}", e);
                }
            }
        }
    }

    available
}

fn print_progress(
    sources: &[Box<dyn EntropySource>],
    stats: &[SourceStats],
    elapsed: Duration,
    total: Duration,
    do_fips: bool,
) {
    let pct = 100.0 * elapsed.as_secs_f64() / total.as_secs_f64();
    let mut stderr = std::io::stderr().lock();

    writeln!(
        stderr,
        "--- Progress ({} / {}, {:.1}%) ---",
        format_duration(elapsed),
        format_duration(total),
        pct
    )
    .ok();

    if do_fips {
        writeln!(
            stderr,
            "{:<12} {:>8} {:>10} {:>8} {:>12} {:>7}",
            "Source", "Samples", "FIPS Pass%", "Shannon", "Throughput", "Errors"
        )
        .ok();
    } else {
        writeln!(
            stderr,
            "{:<12} {:>8} {:>8} {:>12} {:>7}",
            "Source", "Samples", "Shannon", "Throughput", "Errors"
        )
        .ok();
    }

    for (source, stat) in sources.iter().zip(stats.iter()) {
        let throughput = format_throughput(stat.throughput_bytes_per_sec());
        let shannon = stat.avg(stat.shannon_sum);

        if do_fips {
            let fips_pct = stat.fips_pass_pct(stat.fips_all_pass);
            writeln!(
                stderr,
                "{:<12} {:>8} {:>9.1}% {:>8.3} {:>12} {:>7}",
                source.name(),
                stat.total_samples,
                fips_pct,
                shannon,
                throughput,
                stat.errors
            )
            .ok();
        } else {
            writeln!(
                stderr,
                "{:<12} {:>8} {:>8.3} {:>12} {:>7}",
                source.name(),
                stat.total_samples,
                shannon,
                throughput,
                stat.errors
            )
            .ok();
        }
    }
    writeln!(stderr).ok();
}

fn print_final_report(
    sources: &[Box<dyn EntropySource>],
    stats_vec: &[SourceStats],
    do_fips: bool,
) {
    // Per-source detailed results
    for (source, stat) in sources.iter().zip(stats_vec.iter()) {
        println!("--- {} ({}) ---", source.name(), source.description());
        println!(
            "  Samples: {} | Bytes: {} | Throughput: {} | Errors: {}",
            stat.total_samples,
            format_bytes(stat.total_bytes),
            format_throughput(stat.throughput_bytes_per_sec()),
            stat.errors
        );

        if do_fips && stat.total_samples > 0 {
            println!(
                "  FIPS 140-2:  Monobit {:.1}%  Poker {:.1}%  Runs {:.1}%  Long Runs {:.1}%",
                stat.fips_pass_pct(stat.fips_monobit_pass),
                stat.fips_pass_pct(stat.fips_poker_pass),
                stat.fips_pass_pct(stat.fips_runs_pass),
                stat.fips_pass_pct(stat.fips_long_runs_pass)
            );
        }

        if stat.total_samples > 0 {
            let chi = stat.avg(stat.chi_square_sum);
            let p = stats::chi_square_p_value(chi, 255.0);
            println!(
                "  Entropy:     Shannon {:.3}   Min-ent {:.3}  Chi-sq {:.1} (p={:.2})",
                stat.avg(stat.shannon_sum),
                stat.avg(stat.min_entropy_sum),
                chi,
                p
            );
            println!(
                "               Mean {:.2}     SerCorr {:.4}",
                stat.avg(stat.mean_sum),
                stat.avg(stat.serial_corr_sum)
            );
            println!(
                "  Advanced:    ApEn(m=2) {:.4}  ApEn(m=3) {:.4}  LZ ratio {:.3}",
                stat.avg(stat.approx_entropy_m2_sum),
                stat.avg(stat.approx_entropy_m3_sum),
                stat.avg(stat.compression_ratio_sum)
            );
            println!(
                "               BlkEnt(2) {:.3}  BlkEnt(4) {:.3}",
                stat.avg(stat.block_entropy_2_sum),
                stat.avg(stat.block_entropy_4_sum)
            );
        }
        println!();
    }

    // Comparison table (only if multiple sources)
    if sources.len() > 1 {
        println!("--- Comparison ---");
        if do_fips {
            println!(
                "{:<12} {:>12} {:>10} {:>8} {:>8}",
                "Source", "Throughput", "FIPS Pass%", "Shannon", "Min-ent"
            );
        } else {
            println!(
                "{:<12} {:>12} {:>8} {:>8}",
                "Source", "Throughput", "Shannon", "Min-ent"
            );
        }

        for (source, stat) in sources.iter().zip(stats_vec.iter()) {
            let throughput = format_throughput(stat.throughput_bytes_per_sec());
            let shannon = stat.avg(stat.shannon_sum);
            let min_ent = stat.avg(stat.min_entropy_sum);

            if do_fips {
                let fips_pct = stat.fips_pass_pct(stat.fips_all_pass);
                println!(
                    "{:<12} {:>12} {:>9.1}% {:>8.3} {:>8.3}",
                    source.name(),
                    throughput,
                    fips_pct,
                    shannon,
                    min_ent
                );
            } else {
                println!(
                    "{:<12} {:>12} {:>8.3} {:>8.3}",
                    source.name(),
                    throughput,
                    shannon,
                    min_ent
                );
            }
        }
        println!();

        // Verdict
        let best_throughput = sources
            .iter()
            .zip(stats_vec.iter())
            .filter(|(_, s)| s.total_samples > 0)
            .max_by(|a, b| {
                a.1.throughput_bytes_per_sec()
                    .partial_cmp(&b.1.throughput_bytes_per_sec())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        let best_min_entropy = sources
            .iter()
            .zip(stats_vec.iter())
            .filter(|(_, s)| s.total_samples > 0)
            .max_by(|a, b| {
                a.1.avg(a.1.min_entropy_sum)
                    .partial_cmp(&b.1.avg(b.1.min_entropy_sum))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        println!("Verdict:");
        if let Some((source, stat)) = best_throughput {
            println!(
                "  Highest throughput:   {} ({})",
                source.name(),
                format_throughput(stat.throughput_bytes_per_sec())
            );
        }
        if let Some((source, stat)) = best_min_entropy {
            println!(
                "  Highest min-entropy:  {} ({:.3} bits/byte)",
                source.name(),
                stat.avg(stat.min_entropy_sum)
            );
        }
    }
}

fn output_json(
    sources: &[Box<dyn EntropySource>],
    stats_vec: &[SourceStats],
    total_elapsed: Duration,
    sample_size: usize,
    do_fips: bool,
) {
    let result = CheckResult {
        duration_secs: total_elapsed.as_secs_f64(),
        sample_size,
        fips_enabled: do_fips,
        sources: sources
            .iter()
            .zip(stats_vec.iter())
            .map(|(s, st)| build_source_result(s.as_ref(), st))
            .collect(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
}

fn output_csv(sources: &[Box<dyn EntropySource>], stats_vec: &[SourceStats]) {
    println!(
        "source,samples,bytes,throughput_bps,errors,\
         fips_monobit_pct,fips_poker_pct,fips_runs_pct,fips_long_runs_pct,fips_all_pct,\
         shannon,min_entropy,chi_square,chi_square_p,mean,serial_correlation,\
         approx_entropy_m2,approx_entropy_m3,compression_ratio,block_entropy_2,block_entropy_4"
    );
    for (source, stat) in sources.iter().zip(stats_vec.iter()) {
        let r = build_source_result(source.as_ref(), stat);
        println!(
            "{},{},{},{:.2},{},{:.1},{:.1},{:.1},{:.1},{:.1},\
             {:.4},{:.4},{:.1},{:.4},{:.2},{:.6},\
             {:.4},{:.4},{:.4},{:.4},{:.4}",
            r.name,
            r.samples,
            r.bytes,
            r.throughput_bytes_per_sec,
            r.errors,
            r.fips_monobit_pct,
            r.fips_poker_pct,
            r.fips_runs_pct,
            r.fips_long_runs_pct,
            r.fips_all_pct,
            r.shannon,
            r.min_entropy,
            r.chi_square,
            r.chi_square_p,
            r.mean,
            r.serial_correlation,
            r.approx_entropy_m2,
            r.approx_entropy_m3,
            r.compression_ratio,
            r.block_entropy_2,
            r.block_entropy_4
        );
    }
}

/// Maximum sample size for statistical tests (10 MiB).
const MAX_SAMPLE_SIZE: usize = 10 * 1024 * 1024;

pub fn run(args: &CheckArgs, config: &Config) -> Result<(), Error> {
    if args.sample_size == 0 {
        return Err(Error::InvalidArgs(
            "sample-size must be greater than 0".into(),
        ));
    }
    if args.sample_size > MAX_SAMPLE_SIZE {
        return Err(Error::InvalidArgs(format!(
            "sample-size {} exceeds maximum {} (10 MiB)",
            args.sample_size, MAX_SAMPLE_SIZE
        )));
    }

    let duration = parse_duration(&args.duration)?;
    let do_fips = args.sample_size >= 2500;

    let quiet = args.quiet;

    if !do_fips && !quiet {
        eprintln!(
            "Warning: sample_size {} < 2500 bytes, FIPS 140-2 tests will be skipped",
            args.sample_size
        );
    }

    install_signal_handlers();

    if !quiet {
        eprintln!("Probing entropy sources...");
    }
    let all_sources = entropy::build_check_sources(config);
    let sources = probe_sources(all_sources, quiet);

    // Filter by user-requested sources
    let sources: Vec<Box<dyn EntropySource>> = if let Some(ref names) = args.sources {
        sources
            .into_iter()
            .filter(|s| names.iter().any(|n| n.eq_ignore_ascii_case(s.name())))
            .collect()
    } else {
        sources
    };

    if sources.is_empty() {
        return Err(Error::NoEntropy("no entropy sources available".into()));
    }

    if !quiet {
        let source_list: Vec<&str> = sources.iter().map(|s| s.name()).collect();
        eprintln!(
            "\nStatistical check: sources=[{}], duration={}, sample_size={} bytes",
            source_list.join(", "),
            format_duration(duration),
            args.sample_size
        );
        eprintln!();
    }

    // GPS Subframe 4/Page 17 additional-input is public data, not an entropy
    // source: report its status for visibility but DO NOT add it to the graded
    // `sources` (no FIPS / entropy estimates on a public constant).
    #[cfg(feature = "gps")]
    if config.hsm.gps.enabled && !quiet {
        let src = crate::entropy::gps::GpsSource::new(&config.hsm.gps);
        let status = if src.collect(0).is_ok() {
            "available"
        } else {
            "unavailable"
        };
        eprintln!(
            "additional-input: gps-sf4p17 [{}] — 0-bit credit, not statistically graded\n",
            status
        );
    }

    let mut stats_vec: Vec<SourceStats> = sources.iter().map(|_| SourceStats::new()).collect();

    let start = Instant::now();
    let deadline = start + duration;
    let mut last_report = start;

    'outer: loop {
        for i in 0..sources.len() {
            if SHUTDOWN.load(Ordering::Acquire) || Instant::now() >= deadline {
                break 'outer;
            }

            let sample_start = Instant::now();

            match sources[i].collect(args.sample_size) {
                Ok(data) => {
                    let elapsed = sample_start.elapsed();
                    let stat = &mut stats_vec[i];
                    stat.total_samples += 1;
                    stat.total_bytes += data.len() as u64;
                    stat.total_time += elapsed;

                    if do_fips {
                        if data.len() < 2500 {
                            stats_vec[i].errors += 1;
                            continue;
                        }
                        let fips_data: &[u8; 2500] = match (&data[..2500]).try_into() {
                            Ok(arr) => arr,
                            Err(_) => {
                                stats_vec[i].errors += 1;
                                continue;
                            }
                        };
                        let fips = stats::fips_suite(fips_data);
                        if fips.monobit.passed {
                            stat.fips_monobit_pass += 1;
                        }
                        if fips.poker.passed {
                            stat.fips_poker_pass += 1;
                        }
                        if fips.runs.passed {
                            stat.fips_runs_pass += 1;
                        }
                        if fips.long_runs.passed {
                            stat.fips_long_runs_pass += 1;
                        }
                        if fips.all_passed() {
                            stat.fips_all_pass += 1;
                        }
                    }

                    let est = stats::entropy_estimates(&data);
                    stat.shannon_sum += est.shannon;
                    stat.min_entropy_sum += est.min_entropy;
                    stat.chi_square_sum += est.chi_square;
                    stat.mean_sum += est.mean;
                    stat.serial_corr_sum += est.serial_correlation;
                    stat.approx_entropy_m2_sum += est.approx_entropy_m2;
                    stat.approx_entropy_m3_sum += est.approx_entropy_m3;
                    stat.compression_ratio_sum += est.compression_ratio;
                    stat.block_entropy_2_sum += est.block_entropy_2;
                    stat.block_entropy_4_sum += est.block_entropy_4;
                }
                Err(_) => {
                    stats_vec[i].errors += 1;
                }
            }

            if !quiet && last_report.elapsed().as_secs() >= args.report_interval {
                print_progress(&sources, &stats_vec, start.elapsed(), duration, do_fips);
                last_report = Instant::now();
            }
        }
    }

    let total_elapsed = start.elapsed();

    if !quiet {
        if SHUTDOWN.load(Ordering::Acquire) {
            eprintln!(
                "\nInterrupted after {} — printing partial results\n",
                format_duration(total_elapsed)
            );
        } else {
            eprintln!("\nCompleted {} check\n", format_duration(total_elapsed));
        }
    }

    match args.output_format {
        CheckOutputFormat::Json => output_json(
            &sources,
            &stats_vec,
            total_elapsed,
            args.sample_size,
            do_fips,
        ),
        CheckOutputFormat::Csv => output_csv(&sources, &stats_vec),
        CheckOutputFormat::Text => print_final_report(&sources, &stats_vec, do_fips),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_duration ---

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn test_parse_duration_bare_number() {
        // Bare number = minutes
        assert_eq!(parse_duration("5").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_zero() {
        assert!(parse_duration("0s").is_err());
    }

    #[test]
    fn test_parse_duration_empty() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("abcs").is_err());
    }

    // --- format_duration ---

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(120)), "2m");
    }

    #[test]
    fn test_format_duration_minutes_seconds() {
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
    }

    #[test]
    fn test_format_duration_hours_minutes() {
        assert_eq!(format_duration(Duration::from_secs(5400)), "1h 30m");
    }

    // --- format_throughput ---

    #[test]
    fn test_format_throughput_bytes() {
        assert_eq!(format_throughput(100.0), "100 B/s");
    }

    #[test]
    fn test_format_throughput_kb() {
        assert_eq!(format_throughput(5000.0), "5.00 KB/s");
    }

    #[test]
    fn test_format_throughput_mb() {
        assert_eq!(format_throughput(2_500_000.0), "2.50 MB/s");
    }

    // --- format_bytes ---

    #[test]
    fn test_format_bytes_small() {
        assert_eq!(format_bytes(500), "500 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(5000), "5.00 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(2_500_000), "2.50 MB");
    }

    // --- SourceStats ---

    #[test]
    fn test_source_stats_empty() {
        let stat = SourceStats::new();
        assert_eq!(stat.fips_pass_pct(0), 0.0);
        assert_eq!(stat.avg(0.0), 0.0);
        assert_eq!(stat.throughput_bytes_per_sec(), 0.0);
        assert_eq!(stat.approx_entropy_m2_sum, 0.0);
        assert_eq!(stat.compression_ratio_sum, 0.0);
    }

    #[test]
    fn test_source_stats_computations() {
        let mut stat = SourceStats::new();
        stat.total_samples = 10;
        stat.total_bytes = 25000;
        stat.total_time = Duration::from_secs(5);
        stat.fips_all_pass = 8;
        stat.shannon_sum = 75.0;
        stat.approx_entropy_m2_sum = 6.93;
        stat.compression_ratio_sum = 9.5;

        assert!((stat.fips_pass_pct(8) - 80.0).abs() < f64::EPSILON);
        assert!((stat.avg(75.0) - 7.5).abs() < f64::EPSILON);
        assert!((stat.throughput_bytes_per_sec() - 5000.0).abs() < f64::EPSILON);
        assert!((stat.avg(stat.approx_entropy_m2_sum) - 0.693).abs() < 0.001);
        assert!((stat.avg(stat.compression_ratio_sum) - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_parse_duration_whitespace() {
        assert_eq!(parse_duration("  30s  ").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_large_value() {
        assert_eq!(
            parse_duration("365d").unwrap(),
            Duration::from_secs(365 * 86400)
        );
    }

    #[test]
    fn test_format_throughput_zero() {
        let result = format_throughput(0.0);
        assert!(result.contains("0"), "expected '0' in '{}'", result);
    }

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_source_stats_new_all_zero() {
        let stat = SourceStats::new();
        assert_eq!(stat.total_samples, 0);
        assert_eq!(stat.total_bytes, 0);
        assert_eq!(stat.errors, 0);
    }
}
