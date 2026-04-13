use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};

use crate::config::GnuPGConfig;
use crate::error::Error;

use super::EntropySource;

/// Entropy source that invokes `gpg --gen-random` to collect random bytes
/// from the GnuPG entropy pool.
pub struct GnuPGSource {
    gpg_path: String,
    quality: u8,
    /// Cached availability: 0 = unchecked, 1 = absent, 2 = present.
    available: AtomicU8,
}

impl GnuPGSource {
    pub fn new(config: &GnuPGConfig) -> Self {
        Self {
            gpg_path: config
                .gpg_path
                .as_deref()
                .unwrap_or("gpg")
                .to_string(),
            quality: config.quality_level,
            available: AtomicU8::new(0),
        }
    }
}

impl EntropySource for GnuPGSource {
    fn name(&self) -> &str {
        "gnupg"
    }

    fn description(&self) -> &str {
        "GnuPG entropy (gpg --gen-random)"
    }

    fn priority(&self) -> u32 {
        8
    }

    fn source_type(&self) -> &str {
        "software"
    }

    fn is_available(&self) -> bool {
        let cached = self.available.load(Ordering::Relaxed);
        if cached != 0 {
            return cached == 2;
        }

        let present = Command::new(&self.gpg_path)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .is_ok();

        self.available
            .store(if present { 2 } else { 1 }, Ordering::Relaxed);
        present
    }

    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        let output = Command::new(&self.gpg_path)
            .args([
                "--gen-random",
                &self.quality.to_string(),
                &count.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| Error::NoEntropy(format!("gpg --gen-random failed to execute: {}", e)))?;

        if !output.status.success() {
            return Err(Error::NoEntropy(format!(
                "gpg --gen-random exited with status {}",
                output.status
            )));
        }

        if output.stdout.len() != count {
            return Err(Error::NoEntropy(format!(
                "gpg --gen-random returned {} bytes, expected {}",
                output.stdout.len(),
                count
            )));
        }

        Ok(output.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default_path() {
        let config = GnuPGConfig::default();
        let source = GnuPGSource::new(&config);
        assert_eq!(source.gpg_path, "gpg");
    }

    #[test]
    fn test_new_custom_path() {
        let config = GnuPGConfig {
            enabled: true,
            gpg_path: Some("/usr/local/bin/gpg2".to_string()),
            quality_level: 1,
        };
        let source = GnuPGSource::new(&config);
        assert_eq!(source.gpg_path, "/usr/local/bin/gpg2");
        assert_eq!(source.quality, 1);
    }
}
