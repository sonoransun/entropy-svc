use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use clap::{Args, ValueEnum};
use log::{Level, LevelFilter, Log, Metadata, Record};

type SyslogLogger = syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
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

#[derive(Debug, Args)]
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
}

struct MixrandLogger {
    log_file: Option<Mutex<File>>,
    syslog: Option<Mutex<SyslogLogger>>,
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

        let msg = format!("[{}] {}: {}", prefix, level_tag(record.level()), record.args());

        // Always write to stderr
        let _ = writeln!(std::io::stderr().lock(), "{}", msg);

        // Optionally write to log file
        if let Some(ref file) = self.log_file {
            if let Ok(mut f) = file.lock() {
                let _ = writeln!(f, "{}", msg);
            }
        }

        // Optionally write to syslog
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
            .map(|f| Mutex::new(f))
    });

    let syslog = if args.syslog {
        syslog::unix(syslog::Formatter3164 {
            facility: syslog::Facility::LOG_DAEMON,
            hostname: None,
            process: "mixrand".into(),
            pid: std::process::id(),
        })
        .ok()
        .map(|l| Mutex::new(l))
    } else {
        None
    };

    let logger = MixrandLogger { log_file, syslog };

    let _ = log::set_boxed_logger(Box::new(logger));
    log::set_max_level(level.to_level_filter());
}
