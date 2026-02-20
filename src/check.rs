use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::cli::CheckArgs;
use crate::config::CpuRngConfig;
use crate::entropy::{cpurng, fallback, haveged, hwrng};
use crate::error::Error;
use crate::stats;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Hwrng,
    Rdseed,
    Rdrand,
    Xstore,
    Haveged,
    Urandom,
    Fallback,
}

impl SourceKind {
    fn name(&self) -> &'static str {
        match self {
            SourceKind::Hwrng => "hwrng",
            SourceKind::Rdseed => "rdseed",
            SourceKind::Rdrand => "rdrand",
            SourceKind::Xstore => "xstore",
            SourceKind::Haveged => "haveged",
            SourceKind::Urandom => "urandom",
            SourceKind::Fallback => "fallback",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            SourceKind::Hwrng => "Hardware RNG (/dev/hwrng)",
            SourceKind::Rdseed => "CPU RDSEED instruction",
            SourceKind::Rdrand => "CPU RDRAND instruction",
            SourceKind::Xstore => "VIA PadLock XSTORE instruction",
            SourceKind::Haveged => "haveged (/dev/random)",
            SourceKind::Urandom => "/dev/urandom",
            SourceKind::Fallback => "Fallback (urandom + procfs + jitter + cpu-rng)",
        }
    }
}

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

fn collect_sample(
    source: &SourceKind,
    count: usize,
    config: &CpuRngConfig,
) -> Result<Vec<u8>, Error> {
    match source {
        SourceKind::Hwrng => hwrng::read_hwrng(count),
        SourceKind::Rdseed => cpurng::collect_rdseed(count, config.rdseed_retries),
        SourceKind::Rdrand => cpurng::collect_rdrand(count, config.rdrand_retries),
        SourceKind::Xstore => cpurng::collect_xstore(count, config.xstore_quality),
        SourceKind::Haveged => haveged::read_haveged(count),
        SourceKind::Urandom => read_urandom(count),
        SourceKind::Fallback => fallback::generate_fallback(count, config),
    }
}

fn read_urandom(count: usize) -> Result<Vec<u8>, Error> {
    let mut f = File::open("/dev/urandom")
        .map_err(|e| Error::NoEntropy(format!("/dev/urandom not available: {}", e)))?;
    let mut buf = vec![0u8; count];
    f.read_exact(&mut buf)?;
    Ok(buf)
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

extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

fn probe_sources(cpu_config: &CpuRngConfig) -> Vec<SourceKind> {
    let candidates = [
        SourceKind::Hwrng,
        SourceKind::Rdseed,
        SourceKind::Rdrand,
        SourceKind::Xstore,
        SourceKind::Haveged,
        SourceKind::Urandom,
        SourceKind::Fallback,
    ];

    let mut available = Vec::new();

    for &kind in &candidates {
        eprint!("  {:10} ... ", kind.name());
        match collect_sample(&kind, 32, cpu_config) {
            Ok(_) => {
                eprintln!("[ok]");
                available.push(kind);
            }
            Err(e) => {
                eprintln!("[skip] {}", e);
            }
        }
    }

    available
}

fn print_progress(
    stats_vec: &[(SourceKind, SourceStats)],
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

    for (kind, stat) in stats_vec {
        let throughput = format_throughput(stat.throughput_bytes_per_sec());
        let shannon = stat.avg(stat.shannon_sum);

        if do_fips {
            let fips_pct = stat.fips_pass_pct(stat.fips_all_pass);
            writeln!(
                stderr,
                "{:<12} {:>8} {:>9.1}% {:>8.3} {:>12} {:>7}",
                kind.name(),
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
                kind.name(),
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

fn print_final_report(stats_vec: &[(SourceKind, SourceStats)], do_fips: bool) {
    // Per-source detailed results
    for (kind, stat) in stats_vec {
        println!("--- {} ({}) ---", kind.name(), kind.description());
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
                "               Mean {:.2}     SerCorr {:.3}",
                stat.avg(stat.mean_sum),
                stat.avg(stat.serial_corr_sum)
            );
        }
        println!();
    }

    // Comparison table (only if multiple sources)
    if stats_vec.len() > 1 {
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

        for (kind, stat) in stats_vec {
            let throughput = format_throughput(stat.throughput_bytes_per_sec());
            let shannon = stat.avg(stat.shannon_sum);
            let min_ent = stat.avg(stat.min_entropy_sum);

            if do_fips {
                let fips_pct = stat.fips_pass_pct(stat.fips_all_pass);
                println!(
                    "{:<12} {:>12} {:>9.1}% {:>8.3} {:>8.3}",
                    kind.name(),
                    throughput,
                    fips_pct,
                    shannon,
                    min_ent
                );
            } else {
                println!(
                    "{:<12} {:>12} {:>8.3} {:>8.3}",
                    kind.name(),
                    throughput,
                    shannon,
                    min_ent
                );
            }
        }
        println!();

        // Verdict
        let best_throughput = stats_vec
            .iter()
            .filter(|(_, s)| s.total_samples > 0)
            .max_by(|a, b| {
                a.1.throughput_bytes_per_sec()
                    .partial_cmp(&b.1.throughput_bytes_per_sec())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        let best_min_entropy = stats_vec
            .iter()
            .filter(|(_, s)| s.total_samples > 0)
            .max_by(|a, b| {
                a.1.avg(a.1.min_entropy_sum)
                    .partial_cmp(&b.1.avg(b.1.min_entropy_sum))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        println!("Verdict:");
        if let Some((kind, stat)) = best_throughput {
            println!(
                "  Highest throughput:   {} ({})",
                kind.name(),
                format_throughput(stat.throughput_bytes_per_sec())
            );
        }
        if let Some((kind, stat)) = best_min_entropy {
            println!(
                "  Highest min-entropy:  {} ({:.3} bits/byte)",
                kind.name(),
                stat.avg(stat.min_entropy_sum)
            );
        }
    }
}

pub fn run(args: &CheckArgs, cpu_config: &CpuRngConfig) -> Result<(), Error> {
    let duration = parse_duration(&args.duration)?;
    let do_fips = args.sample_size >= 2500;

    if !do_fips {
        eprintln!(
            "Warning: sample_size {} < 2500 bytes, FIPS 140-2 tests will be skipped",
            args.sample_size
        );
    }

    install_signal_handlers();

    eprintln!("Probing entropy sources...");
    let sources = probe_sources(cpu_config);

    let sources: Vec<SourceKind> = if let Some(ref names) = args.sources {
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

    let source_list: Vec<&str> = sources.iter().map(|s| s.name()).collect();
    eprintln!(
        "\nStatistical check: sources=[{}], duration={}, sample_size={} bytes",
        source_list.join(", "),
        format_duration(duration),
        args.sample_size
    );
    eprintln!();

    let mut stats_vec: Vec<(SourceKind, SourceStats)> =
        sources.iter().map(|&s| (s, SourceStats::new())).collect();

    let start = Instant::now();
    let deadline = start + duration;
    let mut last_report = start;

    'outer: loop {
        for i in 0..sources.len() {
            if SHUTDOWN.load(Ordering::Relaxed) || Instant::now() >= deadline {
                break 'outer;
            }

            let source = &sources[i];
            let sample_start = Instant::now();

            match collect_sample(source, args.sample_size, cpu_config) {
                Ok(data) => {
                    let elapsed = sample_start.elapsed();
                    let stat = &mut stats_vec[i].1;
                    stat.total_samples += 1;
                    stat.total_bytes += data.len() as u64;
                    stat.total_time += elapsed;

                    if do_fips {
                        let fips_data: &[u8; 2500] = (&data[..2500]).try_into().unwrap();
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
                }
                Err(_) => {
                    stats_vec[i].1.errors += 1;
                }
            }

            if last_report.elapsed().as_secs() >= args.report_interval {
                print_progress(&stats_vec, start.elapsed(), duration, do_fips);
                last_report = Instant::now();
            }
        }
    }

    let total_elapsed = start.elapsed();

    if SHUTDOWN.load(Ordering::Relaxed) {
        eprintln!(
            "\nInterrupted after {} — printing partial results\n",
            format_duration(total_elapsed)
        );
    } else {
        eprintln!("\nCompleted {} check\n", format_duration(total_elapsed));
    }

    print_final_report(&stats_vec, do_fips);

    Ok(())
}
