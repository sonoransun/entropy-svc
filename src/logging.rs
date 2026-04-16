//! Structured logging for mixrand.
//!
//! Installs a global [`log`]-crate sink that can fan out to any combination
//! of stderr, a log file, and syslog. Supports text (default) and JSON
//! formats. Timestamps are RFC3339 with millisecond resolution.
//!
//! Log level defaults differ by operating mode: `info` for the long-running
//! daemon, `warn` for one-shot CLI invocations. The user can override with
//! `--log-level` or the `-v`/`-q` shortcuts.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use clap::{Args, ValueEnum};
use log::{Level, LevelFilter, Log, Metadata, Record};

type SyslogLogger = syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>;

/// Minimum log level emitted by the configured sinks.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogLevel {
    /// Error messages only.
    Error,
    /// Warnings and errors (default for one-shot CLI).
    Warn,
    /// Info, warnings, errors (default for daemon).
    Info,
    /// All log messages including verbose debug tracing.
    Debug,
}

impl LogLevel {
    fn to_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
        }
    }
}

/// Output format used by the logger.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    /// Human-readable text with timestamps (default).
    Text,
    /// Structured JSON (one object per line).
    Json,
}

/// CLI-visible logging arguments, flattened into every subcommand.
#[derive(Debug, Clone, Args)]
pub struct LogArgs {
    /// Log level (default: warn for one-shot, info for daemon)
    #[arg(long = "log-level", value_enum)]
    pub log_level: Option<LogLevel>,

    /// Append log messages to a file
    #[arg(long = "log-file")]
    pub log_file: Option<PathBuf>,

    /// Send log messages to syslog
    #[arg(long)]
    pub syslog: bool,

    /// Log output format
    #[arg(long = "log-format", value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
}

struct MixrandLogger {
    log_file: Option<Mutex<File>>,
    syslog: Option<Mutex<SyslogLogger>>,
    format: LogFormat,
}

fn level_tag(level: Level) -> &'static str {
    match level {
        Level::Error => "error",
        Level::Warn => "warning",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "debug",
    }
}

fn rfc3339_now() -> String {
    let now = SystemTime::now();
    let dur = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();

    // Convert to UTC components
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;

    // Compute year/month/day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_date(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, h, m, s, millis
    )
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Guard against extreme values that could overflow the civil algorithm.
    // Day 10,000,000 ≈ year 29,349 — well beyond any realistic timestamp.
    if days > 10_000_000 {
        return (9999, 12, 31);
    }

    // Civil from days algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

impl Log for MixrandLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let prefix = if record.target().contains("daemon") {
            "mixrand daemon"
        } else {
            "mixrand"
        };

        let timestamp = rfc3339_now();

        match self.format {
            LogFormat::Text => {
                let msg = format!(
                    "{} [{}] {}: {}",
                    timestamp,
                    prefix,
                    level_tag(record.level()),
                    record.args()
                );
                let _ = writeln!(std::io::stderr().lock(), "{}", msg);

                if let Some(ref file) = self.log_file {
                    if let Ok(mut f) = file.lock() {
                        let _ = writeln!(f, "{}", msg);
                    }
                }
            }
            LogFormat::Json => {
                let message = format!("{}", record.args());
                let json = serde_json::json!({
                    "timestamp": timestamp,
                    "level": level_tag(record.level()),
                    "target": prefix,
                    "message": message,
                });
                let line = serde_json::to_string(&json).unwrap_or_default();
                let _ = writeln!(std::io::stderr().lock(), "{}", line);

                if let Some(ref file) = self.log_file {
                    if let Ok(mut f) = file.lock() {
                        let _ = writeln!(f, "{}", line);
                    }
                }
            }
        }

        // Optionally write to syslog (always text format)
        if let Some(ref logger) = self.syslog {
            if let Ok(mut l) = logger.lock() {
                let text = format!("{}", record.args());
                let _ = match record.level() {
                    Level::Error => l.err(&text),
                    Level::Warn => l.warning(&text),
                    Level::Info => l.info(&text),
                    Level::Debug | Level::Trace => l.debug(&text),
                };
            }
        }
    }

    fn flush(&self) {
        if let Some(ref file) = self.log_file {
            if let Ok(mut f) = file.lock() {
                let _ = f.flush();
            }
        }
    }
}

pub fn init(args: &LogArgs, is_daemon: bool) {
    let level = args.log_level.unwrap_or(if is_daemon {
        LogLevel::Info
    } else {
        LogLevel::Warn
    });

    let log_file = args.log_file.as_ref().and_then(|path| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
            .map(Mutex::new)
    });

    #[cfg(unix)]
    let syslog = if args.syslog {
        syslog::unix(syslog::Formatter3164 {
            facility: syslog::Facility::LOG_DAEMON,
            hostname: None,
            process: "mixrand".into(),
            pid: std::process::id(),
        })
        .ok()
        .map(Mutex::new)
    } else {
        None
    };
    #[cfg(not(unix))]
    let syslog: Option<Mutex<SyslogLogger>> = {
        if args.syslog {
            log::warn!("syslog is not supported on this platform");
        }
        None
    };

    let logger = MixrandLogger {
        log_file,
        syslog,
        format: args.log_format,
    };

    let _ = log::set_boxed_logger(Box::new(logger));
    log::set_max_level(level.to_level_filter());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_now_format() {
        let ts = rfc3339_now();
        // Should match YYYY-MM-DDThh:mm:ss.mmmZ
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 24); // e.g. "2024-01-15T12:30:45.123Z"
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }

    #[test]
    fn test_days_to_date_epoch() {
        let (y, m, d) = days_to_date(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_date_known() {
        // 2024-01-01 is day 19723 since epoch
        let (y, m, d) = days_to_date(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn test_level_tag() {
        assert_eq!(level_tag(Level::Error), "error");
        assert_eq!(level_tag(Level::Warn), "warning");
        assert_eq!(level_tag(Level::Info), "info");
        assert_eq!(level_tag(Level::Debug), "debug");
    }

    #[test]
    fn test_log_level_to_level_filter() {
        assert_eq!(LogLevel::Error.to_level_filter(), LevelFilter::Error);
        assert_eq!(LogLevel::Warn.to_level_filter(), LevelFilter::Warn);
        assert_eq!(LogLevel::Info.to_level_filter(), LevelFilter::Info);
        assert_eq!(LogLevel::Debug.to_level_filter(), LevelFilter::Debug);
    }

    #[test]
    fn test_days_to_date_leap_year() {
        // 2000-01-01 is day 10957; Feb 29 = 10957 + 31 + 28 = 11016
        let (y, m, d) = days_to_date(11016);
        assert_eq!((y, m, d), (2000, 2, 29));
    }

    #[test]
    fn test_days_to_date_year_boundary() {
        // 1970 is not a leap year, so day 365 = 1971-01-01
        let (y, m, d) = days_to_date(365);
        assert_eq!((y, m, d), (1971, 1, 1));
    }

    #[test]
    fn test_days_to_date_extreme() {
        // Values above 10,000,000 should hit the guard and return (9999, 12, 31)
        let (y, m, d) = days_to_date(10_000_001);
        assert_eq!((y, m, d), (9999, 12, 31));

        // 10,000,000 should NOT hit the guard — it should return a normal date
        let (y2, m2, d2) = days_to_date(10_000_000);
        assert_ne!((y2, m2, d2), (9999, 12, 31));
    }

    #[test]
    fn test_rfc3339_now_format_structure() {
        let ts = rfc3339_now();
        assert_eq!(ts.len(), 24);
        let bytes = ts.as_bytes();
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert_eq!(bytes[10], b'T');
        assert_eq!(bytes[13], b':');
        assert_eq!(bytes[16], b':');
        assert_eq!(bytes[19], b'.');
        assert_eq!(bytes[23], b'Z');
    }
}
