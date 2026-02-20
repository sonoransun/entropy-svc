use std::path::Path;

use serde::Deserialize;

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum CpuRngPreference {
    Rdseed,
    Rdrand,
    Xstore,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CpuRngConfig {
    pub enable_rdseed: bool,
    pub enable_rdrand: bool,
    pub enable_xstore: bool,
    pub rdrand_retries: u32,
    pub rdseed_retries: u32,
    pub xstore_quality: u32,
    pub prefer: CpuRngPreference,
    pub fallback_mix_bytes: usize,
    pub oversample: u32,
}

impl Default for CpuRngConfig {
    fn default() -> Self {
        Self {
            enable_rdseed: true,
            enable_rdrand: true,
            enable_xstore: true,
            rdrand_retries: 10,
            rdseed_retries: 10,
            xstore_quality: 3,
            prefer: CpuRngPreference::Rdseed,
            fallback_mix_bytes: 32,
            oversample: 2,
        }
    }
}

impl CpuRngConfig {
    /// Clamp fields to valid ranges.
    pub fn validate(&mut self) {
        self.rdrand_retries = self.rdrand_retries.clamp(1, 100);
        self.rdseed_retries = self.rdseed_retries.clamp(1, 100);
        self.xstore_quality = self.xstore_quality.clamp(0, 3);
        self.fallback_mix_bytes = self.fallback_mix_bytes.clamp(0, 1024);
        self.oversample = self.oversample.clamp(1, 16);
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub cpu_rng: CpuRngConfig,
}

/// Load configuration from a TOML file.
///
/// - If `explicit_path` is `Some` and the file is missing, returns an error.
/// - If `explicit_path` is `None`, tries `/etc/mixrand.toml`; if missing, returns defaults.
pub fn load_config(explicit_path: Option<&Path>) -> Result<Config, Error> {
    let path = match explicit_path {
        Some(p) => {
            if !p.exists() {
                return Err(Error::InvalidArgs(format!(
                    "config file not found: {}",
                    p.display()
                )));
            }
            p.to_path_buf()
        }
        None => {
            let default = Path::new("/etc/mixrand.toml");
            if !default.exists() {
                return Ok(Config::default());
            }
            default.to_path_buf()
        }
    };

    let contents = std::fs::read_to_string(&path).map_err(|e| {
        Error::InvalidArgs(format!("failed to read config {}: {}", path.display(), e))
    })?;

    let config: Config = toml::from_str(&contents).map_err(|e| {
        Error::InvalidArgs(format!("failed to parse config {}: {}", path.display(), e))
    })?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_values() {
        let cfg = CpuRngConfig::default();
        assert!(cfg.enable_rdseed);
        assert!(cfg.enable_rdrand);
        assert!(cfg.enable_xstore);
        assert_eq!(cfg.rdrand_retries, 10);
        assert_eq!(cfg.rdseed_retries, 10);
        assert_eq!(cfg.xstore_quality, 3);
        assert_eq!(cfg.prefer, CpuRngPreference::Rdseed);
        assert_eq!(cfg.fallback_mix_bytes, 32);
        assert_eq!(cfg.oversample, 2);
    }

    #[test]
    fn test_validate_clamps_high() {
        let mut cfg = CpuRngConfig {
            rdrand_retries: 200,
            rdseed_retries: 200,
            xstore_quality: 10,
            fallback_mix_bytes: 2000,
            oversample: 50,
            ..Default::default()
        };
        cfg.validate();
        assert_eq!(cfg.rdrand_retries, 100);
        assert_eq!(cfg.rdseed_retries, 100);
        assert_eq!(cfg.xstore_quality, 3);
        assert_eq!(cfg.fallback_mix_bytes, 1024);
        assert_eq!(cfg.oversample, 16);
    }

    #[test]
    fn test_validate_clamps_low() {
        let mut cfg = CpuRngConfig {
            rdrand_retries: 0,
            rdseed_retries: 0,
            xstore_quality: 0,
            fallback_mix_bytes: 0,
            oversample: 0,
            ..Default::default()
        };
        cfg.validate();
        assert_eq!(cfg.rdrand_retries, 1);
        assert_eq!(cfg.rdseed_retries, 1);
        assert_eq!(cfg.xstore_quality, 0); // 0 is valid minimum
        assert_eq!(cfg.fallback_mix_bytes, 0); // 0 is valid minimum
        assert_eq!(cfg.oversample, 1);
    }

    #[test]
    fn test_toml_parsing() {
        let dir = std::env::temp_dir();
        let path = dir.join("mixrand_test_config.toml");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            write!(
                f,
                r#"
[cpu_rng]
enable_rdseed = false
rdrand_retries = 20
prefer = "rdrand"
"#
            )
            .unwrap();
        }
        let config = load_config(Some(&path)).unwrap();
        assert!(!config.cpu_rng.enable_rdseed);
        assert_eq!(config.cpu_rng.rdrand_retries, 20);
        assert_eq!(config.cpu_rng.prefer, CpuRngPreference::Rdrand);
        // Unset fields should get defaults
        assert!(config.cpu_rng.enable_rdrand);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_missing_explicit_config_errors() {
        let path = std::path::Path::new("/tmp/mixrand_nonexistent_config.toml");
        let result = load_config(Some(path));
        assert!(result.is_err());
    }
}
