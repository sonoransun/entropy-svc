use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum CpuRngPreference {
    Rdseed,
    Rdrand,
    Xstore,
    Rndr,
    Rndrrs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum MixerMode {
    #[default]
    Blake2b,
    Hkdf,
}


#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CpuRngConfig {
    pub enable_rdseed: bool,
    pub enable_rdrand: bool,
    pub enable_xstore: bool,
    pub enable_rndr: bool,
    pub enable_rndrrs: bool,
    pub rdrand_retries: u32,
    pub rdseed_retries: u32,
    pub rndr_retries: u32,
    pub rndrrs_retries: u32,
    pub xstore_quality: u32,
    pub prefer: CpuRngPreference,
    pub fallback_mix_bytes: usize,
    pub oversample: u32,
    pub mixer_mode: MixerMode,
}

impl Default for CpuRngConfig {
    fn default() -> Self {
        Self {
            enable_rdseed: true,
            enable_rdrand: true,
            enable_xstore: true,
            enable_rndr: true,
            enable_rndrrs: true,
            rdrand_retries: 10,
            rdseed_retries: 10,
            rndr_retries: 10,
            rndrrs_retries: 10,
            xstore_quality: 3,
            prefer: CpuRngPreference::Rdseed,
            fallback_mix_bytes: 32,
            oversample: 2,
            mixer_mode: MixerMode::Blake2b,
        }
    }
}

impl CpuRngConfig {
    /// Clamp fields to valid ranges. Returns a list of warnings for any fields that were clamped.
    pub fn validate(&mut self) -> Vec<String> {
        let mut warnings = Vec::new();

        fn clamp_warn(name: &str, val: &mut u32, min: u32, max: u32, warnings: &mut Vec<String>) {
            if *val < min {
                warnings.push(format!("{} clamped from {} to {}", name, val, min));
                *val = min;
            } else if *val > max {
                warnings.push(format!("{} clamped from {} to {}", name, val, max));
                *val = max;
            }
        }

        clamp_warn(
            "rdrand_retries",
            &mut self.rdrand_retries,
            1,
            100,
            &mut warnings,
        );
        clamp_warn(
            "rdseed_retries",
            &mut self.rdseed_retries,
            1,
            100,
            &mut warnings,
        );
        clamp_warn(
            "rndr_retries",
            &mut self.rndr_retries,
            1,
            100,
            &mut warnings,
        );
        clamp_warn(
            "rndrrs_retries",
            &mut self.rndrrs_retries,
            1,
            100,
            &mut warnings,
        );
        clamp_warn(
            "xstore_quality",
            &mut self.xstore_quality,
            0,
            3,
            &mut warnings,
        );
        clamp_warn(
            "oversample",
            &mut self.oversample,
            1,
            16,
            &mut warnings,
        );

        if self.fallback_mix_bytes > 1024 {
            warnings.push(format!(
                "fallback_mix_bytes clamped from {} to 1024",
                self.fallback_mix_bytes
            ));
            self.fallback_mix_bytes = 1024;
        }

        warnings
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

/// Apply MIXRAND_* environment variable overrides to a CpuRngConfig.
///
/// Supported variables:
/// - `MIXRAND_ENABLE_RDSEED` (true/false)
/// - `MIXRAND_ENABLE_RDRAND` (true/false)
/// - `MIXRAND_ENABLE_XSTORE` (true/false)
/// - `MIXRAND_ENABLE_RNDR` (true/false)
/// - `MIXRAND_ENABLE_RNDRRS` (true/false)
/// - `MIXRAND_RDRAND_RETRIES` (u32)
/// - `MIXRAND_RDSEED_RETRIES` (u32)
/// - `MIXRAND_RNDR_RETRIES` (u32)
/// - `MIXRAND_RNDRRS_RETRIES` (u32)
/// - `MIXRAND_XSTORE_QUALITY` (u32)
/// - `MIXRAND_PREFER` (rdseed|rdrand|xstore|rndr|rndrrs)
/// - `MIXRAND_FALLBACK_MIX_BYTES` (usize)
/// - `MIXRAND_OVERSAMPLE` (u32)
/// - `MIXRAND_MIXER_MODE` (blake2b|hkdf)
pub fn apply_env_overrides(cfg: &mut CpuRngConfig) {
    fn env_bool(name: &str) -> Option<bool> {
        std::env::var(name).ok().and_then(|v| match v.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        })
    }

    fn env_u32(name: &str) -> Option<u32> {
        std::env::var(name).ok().and_then(|v| v.parse().ok())
    }

    fn env_usize(name: &str) -> Option<usize> {
        std::env::var(name).ok().and_then(|v| v.parse().ok())
    }

    if let Some(v) = env_bool("MIXRAND_ENABLE_RDSEED") {
        cfg.enable_rdseed = v;
    }
    if let Some(v) = env_bool("MIXRAND_ENABLE_RDRAND") {
        cfg.enable_rdrand = v;
    }
    if let Some(v) = env_bool("MIXRAND_ENABLE_XSTORE") {
        cfg.enable_xstore = v;
    }
    if let Some(v) = env_bool("MIXRAND_ENABLE_RNDR") {
        cfg.enable_rndr = v;
    }
    if let Some(v) = env_bool("MIXRAND_ENABLE_RNDRRS") {
        cfg.enable_rndrrs = v;
    }
    if let Some(v) = env_u32("MIXRAND_RDRAND_RETRIES") {
        cfg.rdrand_retries = v;
    }
    if let Some(v) = env_u32("MIXRAND_RDSEED_RETRIES") {
        cfg.rdseed_retries = v;
    }
    if let Some(v) = env_u32("MIXRAND_RNDR_RETRIES") {
        cfg.rndr_retries = v;
    }
    if let Some(v) = env_u32("MIXRAND_RNDRRS_RETRIES") {
        cfg.rndrrs_retries = v;
    }
    if let Some(v) = env_u32("MIXRAND_XSTORE_QUALITY") {
        cfg.xstore_quality = v;
    }
    if let Some(v) = env_usize("MIXRAND_FALLBACK_MIX_BYTES") {
        cfg.fallback_mix_bytes = v;
    }
    if let Some(v) = env_u32("MIXRAND_OVERSAMPLE") {
        cfg.oversample = v;
    }

    if let Ok(v) = std::env::var("MIXRAND_PREFER") {
        match v.to_lowercase().as_str() {
            "rdseed" => cfg.prefer = CpuRngPreference::Rdseed,
            "rdrand" => cfg.prefer = CpuRngPreference::Rdrand,
            "xstore" => cfg.prefer = CpuRngPreference::Xstore,
            "rndr" => cfg.prefer = CpuRngPreference::Rndr,
            "rndrrs" => cfg.prefer = CpuRngPreference::Rndrrs,
            _ => {}
        }
    }

    if let Ok(v) = std::env::var("MIXRAND_MIXER_MODE") {
        match v.to_lowercase().as_str() {
            "blake2b" => cfg.mixer_mode = MixerMode::Blake2b,
            "hkdf" => cfg.mixer_mode = MixerMode::Hkdf,
            _ => {}
        }
    }
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
        assert!(cfg.enable_rndr);
        assert!(cfg.enable_rndrrs);
        assert_eq!(cfg.rdrand_retries, 10);
        assert_eq!(cfg.rdseed_retries, 10);
        assert_eq!(cfg.rndr_retries, 10);
        assert_eq!(cfg.rndrrs_retries, 10);
        assert_eq!(cfg.xstore_quality, 3);
        assert_eq!(cfg.prefer, CpuRngPreference::Rdseed);
        assert_eq!(cfg.fallback_mix_bytes, 32);
        assert_eq!(cfg.oversample, 2);
        assert_eq!(cfg.mixer_mode, MixerMode::Blake2b);
    }

    #[test]
    fn test_validate_clamps_high() {
        let mut cfg = CpuRngConfig {
            rdrand_retries: 200,
            rdseed_retries: 200,
            rndr_retries: 200,
            rndrrs_retries: 200,
            xstore_quality: 10,
            fallback_mix_bytes: 2000,
            oversample: 50,
            ..Default::default()
        };
        let warnings = cfg.validate();
        assert_eq!(cfg.rdrand_retries, 100);
        assert_eq!(cfg.rdseed_retries, 100);
        assert_eq!(cfg.rndr_retries, 100);
        assert_eq!(cfg.rndrrs_retries, 100);
        assert_eq!(cfg.xstore_quality, 3);
        assert_eq!(cfg.fallback_mix_bytes, 1024);
        assert_eq!(cfg.oversample, 16);
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_validate_clamps_low() {
        let mut cfg = CpuRngConfig {
            rdrand_retries: 0,
            rdseed_retries: 0,
            rndr_retries: 0,
            rndrrs_retries: 0,
            xstore_quality: 0,
            fallback_mix_bytes: 0,
            oversample: 0,
            ..Default::default()
        };
        let warnings = cfg.validate();
        assert_eq!(cfg.rdrand_retries, 1);
        assert_eq!(cfg.rdseed_retries, 1);
        assert_eq!(cfg.rndr_retries, 1);
        assert_eq!(cfg.rndrrs_retries, 1);
        assert_eq!(cfg.xstore_quality, 0); // 0 is valid minimum
        assert_eq!(cfg.fallback_mix_bytes, 0); // 0 is valid minimum
        assert_eq!(cfg.oversample, 1);
        assert!(warnings.len() >= 4); // retries + oversample
    }

    #[test]
    fn test_validate_no_warnings_on_default() {
        let mut cfg = CpuRngConfig::default();
        let warnings = cfg.validate();
        assert!(warnings.is_empty());
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

    #[test]
    fn test_env_override_bool() {
        let mut cfg = CpuRngConfig::default();
        // Set env var and test
        std::env::set_var("MIXRAND_ENABLE_RDSEED", "false");
        apply_env_overrides(&mut cfg);
        assert!(!cfg.enable_rdseed);
        std::env::remove_var("MIXRAND_ENABLE_RDSEED");
    }

    #[test]
    fn test_env_override_u32() {
        let mut cfg = CpuRngConfig::default();
        std::env::set_var("MIXRAND_RDRAND_RETRIES", "50");
        apply_env_overrides(&mut cfg);
        assert_eq!(cfg.rdrand_retries, 50);
        std::env::remove_var("MIXRAND_RDRAND_RETRIES");
    }

    #[test]
    fn test_env_override_prefer() {
        let mut cfg = CpuRngConfig::default();
        std::env::set_var("MIXRAND_PREFER", "rndr");
        apply_env_overrides(&mut cfg);
        assert_eq!(cfg.prefer, CpuRngPreference::Rndr);
        std::env::remove_var("MIXRAND_PREFER");
    }

    #[test]
    fn test_env_override_mixer_mode() {
        let mut cfg = CpuRngConfig::default();
        std::env::set_var("MIXRAND_MIXER_MODE", "hkdf");
        apply_env_overrides(&mut cfg);
        assert_eq!(cfg.mixer_mode, MixerMode::Hkdf);
        std::env::remove_var("MIXRAND_MIXER_MODE");
    }

    #[test]
    fn test_serialize_roundtrip() {
        let cfg = CpuRngConfig::default();
        let toml_str = toml::to_string(&cfg).unwrap();
        let deserialized: CpuRngConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(deserialized.prefer, cfg.prefer);
        assert_eq!(deserialized.oversample, cfg.oversample);
    }
}
