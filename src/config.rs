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
        clamp_warn("oversample", &mut self.oversample, 1, 16, &mut warnings);

        if self.fallback_mix_bytes == 0 {
            warnings.push("fallback_mix_bytes clamped from 0 to 8 (minimum)".into());
            self.fallback_mix_bytes = 8;
        } else if self.fallback_mix_bytes > 1024 {
            warnings.push(format!(
                "fallback_mix_bytes clamped from {} to 1024",
                self.fallback_mix_bytes
            ));
            self.fallback_mix_bytes = 1024;
        }

        warnings
    }
}

// ---------------------------------------------------------------------------
// HSM / secure-element configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Tpm2Config {
    pub enabled: bool,
    pub tcti: Option<String>,
}

impl Default for Tpm2Config {
    fn default() -> Self {
        Self {
            enabled: true,
            tcti: None, // defaults to "device:/dev/tpmrm0" at runtime
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Pkcs11Config {
    pub enabled: bool,
    pub library_path: Option<String>,
    pub slot_id: Option<u64>,
    #[serde(skip_serializing)]
    pub pin: Option<String>,
}

impl Default for Pkcs11Config {
    fn default() -> Self {
        Self {
            enabled: true,
            library_path: None,
            slot_id: None,
            pin: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PcscConfig {
    pub enabled: bool,
    pub reader: Option<String>,
    pub max_le: u8,
}

impl Default for PcscConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reader: None,
            max_le: 32,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct YubiKeyConfig {
    pub enabled: bool,
    pub serial: Option<u32>,
}

impl Default for YubiKeyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            serial: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct GnuPGConfig {
    pub enabled: bool,
    pub gpg_path: Option<String>,
    pub quality_level: u8,
}

impl Default for GnuPGConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            gpg_path: None,
            quality_level: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct YubiHsmConfig {
    pub enabled: bool,
    pub connector_url: Option<String>,
    pub auth_key_id: u16,
    #[serde(skip_serializing)]
    pub password: Option<String>,
}

impl Default for YubiHsmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            connector_url: None,
            auth_key_id: 1,
            password: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SgxConfig {
    pub enabled: bool,
    pub enclave_path: Option<String>,
}

impl Default for SgxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enclave_path: None,
        }
    }
}

/// GPS Subframe 4/Page 17 "Special Message" field as a NIST SP 800-90A
/// additional-input / personalization string.
///
/// NOTE: this is **not** an HSM, despite living under [`HsmConfig`] (which is
/// the de-facto home for all optional-source plumbing — env vars, CLI flags,
/// validation). The decoded field is **public broadcast data** with ~0 bits of
/// real entropy; it is *mixed* into output but **never** credited as entropy
/// and **never** selectable as a standalone source. See `src/entropy/gps.rs`.
///
/// `enabled` defaults to **false** (unlike the HSM sources): building with
/// `--features gps` does nothing until a `command` or `path` is configured.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct GpsConfig {
    pub enabled: bool,
    /// Command to run; its stdout is read as the field (takes precedence over `path`).
    pub command: Option<String>,
    /// File or FIFO to read the field from (used when `command` is unset).
    pub path: Option<String>,
    /// Acquisition timeout in milliseconds. Acquisition must never block the
    /// entropy path — a live page-17 capture can take ~12.5 min, so the
    /// command/file must return a *cached* value quickly.
    pub timeout_ms: u64,
    /// Expected field length in bytes (176 bits = 22 bytes). A read whose
    /// length differs is treated as unavailable (misconfigured collector).
    pub expected_len: usize,
}

impl Default for GpsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            command: None,
            path: None,
            timeout_ms: 2000,
            expected_len: 22,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct HsmConfig {
    pub tpm2: Tpm2Config,
    pub pkcs11: Pkcs11Config,
    pub pcsc: PcscConfig,
    pub yubikey: YubiKeyConfig,
    pub gnupg: GnuPGConfig,
    pub yubihsm: YubiHsmConfig,
    pub sgx: SgxConfig,
    /// GPS Subframe 4/Page 17 additional-input (not an HSM; see [`GpsConfig`]).
    pub gps: GpsConfig,
}

impl HsmConfig {
    /// Clamp fields to valid ranges. Returns a list of warnings for any fields that were clamped.
    pub fn validate(&mut self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.gnupg.quality_level > 2 {
            warnings.push(format!(
                "gnupg quality_level clamped from {} to 2",
                self.gnupg.quality_level
            ));
            self.gnupg.quality_level = 2;
        }

        if self.pcsc.max_le == 0 {
            warnings.push("pcsc max_le clamped from 0 to 1".into());
            self.pcsc.max_le = 1;
        }

        if self.yubihsm.auth_key_id == 0 {
            warnings.push("yubihsm auth_key_id clamped from 0 to 1".into());
            self.yubihsm.auth_key_id = 1;
        }

        if self.gps.timeout_ms == 0 {
            warnings.push("gps timeout_ms clamped from 0 to 2000".into());
            self.gps.timeout_ms = 2000;
        }

        if self.gps.expected_len == 0 {
            warnings.push("gps expected_len clamped from 0 to 22".into());
            self.gps.expected_len = 22;
        }

        warnings
    }
}

/// Apply MIXRAND_* environment variable overrides to an HsmConfig.
pub fn apply_hsm_env_overrides(cfg: &mut HsmConfig) {
    fn env_bool(name: &str) -> Option<bool> {
        std::env::var(name).ok().and_then(|v| match v.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        })
    }

    fn env_str(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|s| !s.is_empty())
    }

    fn env_u8(name: &str) -> Option<u8> {
        std::env::var(name).ok().and_then(|v| v.parse().ok())
    }

    fn env_u16(name: &str) -> Option<u16> {
        std::env::var(name).ok().and_then(|v| v.parse().ok())
    }

    fn env_u32(name: &str) -> Option<u32> {
        std::env::var(name).ok().and_then(|v| v.parse().ok())
    }

    fn env_u64(name: &str) -> Option<u64> {
        std::env::var(name).ok().and_then(|v| v.parse().ok())
    }

    // TPM2
    if let Some(v) = env_bool("MIXRAND_TPM2_ENABLED") {
        cfg.tpm2.enabled = v;
    }
    if let Some(v) = env_str("MIXRAND_TPM2_TCTI") {
        cfg.tpm2.tcti = Some(v);
    }

    // PKCS#11
    if let Some(v) = env_bool("MIXRAND_PKCS11_ENABLED") {
        cfg.pkcs11.enabled = v;
    }
    if let Some(v) = env_str("MIXRAND_PKCS11_LIBRARY_PATH") {
        cfg.pkcs11.library_path = Some(v);
    }
    if let Some(v) = env_u64("MIXRAND_PKCS11_SLOT_ID") {
        cfg.pkcs11.slot_id = Some(v);
    }
    if let Some(v) = env_str("MIXRAND_PKCS11_PIN") {
        cfg.pkcs11.pin = Some(v);
    }

    // PC/SC
    if let Some(v) = env_bool("MIXRAND_PCSC_ENABLED") {
        cfg.pcsc.enabled = v;
    }
    if let Some(v) = env_str("MIXRAND_PCSC_READER") {
        cfg.pcsc.reader = Some(v);
    }
    if let Some(v) = env_u8("MIXRAND_PCSC_MAX_LE") {
        cfg.pcsc.max_le = v;
    }

    // YubiKey
    if let Some(v) = env_bool("MIXRAND_YUBIKEY_ENABLED") {
        cfg.yubikey.enabled = v;
    }
    if let Some(v) = env_u32("MIXRAND_YUBIKEY_SERIAL") {
        cfg.yubikey.serial = Some(v);
    }

    // GnuPG
    if let Some(v) = env_bool("MIXRAND_GNUPG_ENABLED") {
        cfg.gnupg.enabled = v;
    }
    if let Some(v) = env_str("MIXRAND_GNUPG_GPG_PATH") {
        cfg.gnupg.gpg_path = Some(v);
    }
    if let Some(v) = env_u8("MIXRAND_GNUPG_QUALITY_LEVEL") {
        cfg.gnupg.quality_level = v;
    }

    // YubiHSM
    if let Some(v) = env_bool("MIXRAND_YUBIHSM_ENABLED") {
        cfg.yubihsm.enabled = v;
    }
    if let Some(v) = env_str("MIXRAND_YUBIHSM_CONNECTOR_URL") {
        cfg.yubihsm.connector_url = Some(v);
    }
    if let Some(v) = env_u16("MIXRAND_YUBIHSM_AUTH_KEY_ID") {
        cfg.yubihsm.auth_key_id = v;
    }
    if let Some(v) = env_str("MIXRAND_YUBIHSM_PASSWORD") {
        cfg.yubihsm.password = Some(v);
    }

    // SGX
    if let Some(v) = env_bool("MIXRAND_SGX_ENABLED") {
        cfg.sgx.enabled = v;
    }
    if let Some(v) = env_str("MIXRAND_SGX_ENCLAVE_PATH") {
        cfg.sgx.enclave_path = Some(v);
    }

    // GPS Subframe 4/Page 17 additional-input (not an HSM; see GpsConfig)
    if let Some(v) = env_bool("MIXRAND_GPS_ENABLED") {
        cfg.gps.enabled = v;
    }
    if let Some(v) = env_str("MIXRAND_GPS_COMMAND") {
        cfg.gps.command = Some(v);
    }
    if let Some(v) = env_str("MIXRAND_GPS_PATH") {
        cfg.gps.path = Some(v);
    }
    if let Some(v) = env_u64("MIXRAND_GPS_TIMEOUT_MS") {
        cfg.gps.timeout_ms = v;
    }
    if let Some(v) = env_u64("MIXRAND_GPS_EXPECTED_LEN") {
        cfg.gps.expected_len = v as usize;
    }
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub cpu_rng: CpuRngConfig,
    pub hsm: HsmConfig,
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
        assert_eq!(cfg.fallback_mix_bytes, 8); // 0 clamped to minimum 8
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

    #[test]
    fn test_invalid_toml_syntax() {
        let dir = std::env::temp_dir();
        let path = dir.join("mixrand_test_invalid_toml.toml");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            write!(f, "[cpu_rng\nnot valid toml!!!").unwrap();
        }
        let result = load_config(Some(&path));
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_env_override_invalid_bool() {
        // Use XSTORE to avoid conflicting with other env var tests
        let mut cfg = CpuRngConfig::default();
        std::env::set_var("MIXRAND_ENABLE_XSTORE", "maybe");
        apply_env_overrides(&mut cfg);
        assert!(cfg.enable_xstore);
        std::env::remove_var("MIXRAND_ENABLE_XSTORE");
    }

    #[test]
    fn test_env_override_invalid_u32() {
        // Use RDSEED_RETRIES to avoid conflicting with other env var tests
        let mut cfg = CpuRngConfig::default();
        std::env::set_var("MIXRAND_RDSEED_RETRIES", "notanumber");
        apply_env_overrides(&mut cfg);
        assert_eq!(cfg.rdseed_retries, 10);
        std::env::remove_var("MIXRAND_RDSEED_RETRIES");
    }

    #[test]
    fn test_env_override_all_bool_formats() {
        // Use RNDR to avoid conflicting with other env var tests
        for (val, expected) in &[
            ("true", true),
            ("1", true),
            ("yes", true),
            ("false", false),
            ("0", false),
            ("no", false),
        ] {
            let mut cfg = CpuRngConfig::default();
            std::env::set_var("MIXRAND_ENABLE_RNDR", val);
            apply_env_overrides(&mut cfg);
            assert_eq!(cfg.enable_rndr, *expected, "failed for input {:?}", val);
        }
        std::env::remove_var("MIXRAND_ENABLE_RNDR");
    }

    #[test]
    fn test_validate_exact_max_boundary() {
        let mut cfg = CpuRngConfig {
            rdrand_retries: 100,
            rdseed_retries: 100,
            rndr_retries: 100,
            rndrrs_retries: 100,
            xstore_quality: 3,
            oversample: 16,
            fallback_mix_bytes: 1024,
            ..Default::default()
        };
        let warnings = cfg.validate();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_exact_min_boundary() {
        let mut cfg = CpuRngConfig {
            rdrand_retries: 1,
            rdseed_retries: 1,
            rndr_retries: 1,
            rndrrs_retries: 1,
            xstore_quality: 0,
            oversample: 1,
            fallback_mix_bytes: 8,
            ..Default::default()
        };
        let warnings = cfg.validate();
        assert!(warnings.is_empty());
    }

    // --- Load-config edge cases ---

    #[test]
    fn test_load_config_malformed_toml_returns_error_not_panic() {
        use std::io::Write as _;
        let path = std::env::temp_dir().join("mixrand_malformed.toml");
        let mut f = std::fs::File::create(&path).expect("test setup: File::create");
        f.write_all(b"this is [ not = valid toml\n")
            .expect("test setup: write_all");
        let result = load_config(Some(&path));
        let _ = std::fs::remove_file(&path);
        match result {
            Err(Error::InvalidArgs(msg)) => {
                assert!(msg.contains("failed to parse"), "msg was: {msg}");
            }
            other => panic!("expected InvalidArgs parse error, got {:?}", other),
        }
    }

    #[test]
    fn test_load_config_nonexistent_explicit_path_errors() {
        let result = load_config(Some(Path::new("/nonexistent/mixrand-never.toml")));
        match result {
            Err(Error::InvalidArgs(msg)) => {
                assert!(msg.contains("not found"), "msg was: {msg}");
            }
            other => panic!("expected InvalidArgs not-found, got {:?}", other),
        }
    }

    #[test]
    fn test_load_config_no_path_no_default_returns_default() {
        // With /etc/mixrand.toml absent on test hosts this returns defaults.
        // On a host that DOES have /etc/mixrand.toml we instead validate
        // that the result loads successfully.
        let out = load_config(None);
        assert!(out.is_ok(), "load_config(None) returned: {:?}", out);
    }

    #[test]
    fn test_validate_is_idempotent_for_clamped_values() {
        // First validate clamps; second validate sees valid values and
        // emits no new warnings.
        let mut cfg = CpuRngConfig {
            rdrand_retries: 1_000_000, // out of range -> clamp
            rdseed_retries: 0,         // out of range -> clamp
            oversample: 0,             // out of range -> clamp
            ..Default::default()
        };
        let warnings_first = cfg.validate();
        assert!(
            !warnings_first.is_empty(),
            "first validate should emit clamp warnings"
        );
        let warnings_second = cfg.validate();
        assert!(
            warnings_second.is_empty(),
            "idempotent validate should produce no warnings, got: {warnings_second:?}"
        );
    }

    #[test]
    fn test_apply_env_overrides_invalid_numeric_is_ignored() {
        // Parse failure leaves the field untouched — no panic.
        std::env::set_var("MIXRAND_RDRAND_RETRIES", "not-a-number");
        let mut cfg = CpuRngConfig {
            rdrand_retries: 7,
            ..Default::default()
        };
        apply_env_overrides(&mut cfg);
        assert_eq!(cfg.rdrand_retries, 7, "invalid env should be ignored");
        std::env::remove_var("MIXRAND_RDRAND_RETRIES");
    }

    #[test]
    fn test_apply_env_overrides_bool_variants() {
        for (val, expected) in [
            ("true", true),
            ("1", true),
            ("yes", true),
            ("false", false),
            ("0", false),
            ("no", false),
        ] {
            std::env::set_var("MIXRAND_ENABLE_RDRAND", val);
            let mut cfg = CpuRngConfig::default();
            apply_env_overrides(&mut cfg);
            assert_eq!(cfg.enable_rdrand, expected, "val={val}");
        }
        // Unknown value leaves the config untouched (stays default).
        std::env::set_var("MIXRAND_ENABLE_RDRAND", "maybe");
        let mut cfg = CpuRngConfig::default();
        let before = cfg.enable_rdrand;
        apply_env_overrides(&mut cfg);
        assert_eq!(cfg.enable_rdrand, before);
        std::env::remove_var("MIXRAND_ENABLE_RDRAND");
    }
}
