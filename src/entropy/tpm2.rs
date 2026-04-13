use std::path::Path;
use std::str::FromStr;

use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

use crate::config::Tpm2Config;
use crate::error::Error;

use super::EntropySource;

const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// Maximum bytes the TPM will return per `GetRandom` call.
const TPM_MAX_RANDOM_CHUNK: usize = 48;

/// Entropy source that collects random bytes from a TPM 2.0 device via
/// `TPM2_GetRandom`.
pub struct Tpm2Source {
    tcti: String,
}

impl Tpm2Source {
    pub fn new(config: &Tpm2Config) -> Self {
        Self {
            tcti: config
                .tcti
                .as_deref()
                .unwrap_or(DEFAULT_TCTI)
                .to_string(),
        }
    }

    /// Extract the device path from the TCTI string.
    ///
    /// If the TCTI begins with `"device:"`, the remainder is the path.
    /// Otherwise, fall back to `/dev/tpmrm0`.
    fn device_path(&self) -> &str {
        if let Some(path) = self.tcti.strip_prefix("device:") {
            path
        } else {
            "/dev/tpmrm0"
        }
    }
}

impl EntropySource for Tpm2Source {
    fn name(&self) -> &str {
        "tpm2"
    }

    fn description(&self) -> &str {
        "TPM 2.0 (TPM2_GetRandom)"
    }

    fn priority(&self) -> u32 {
        5
    }

    fn source_type(&self) -> &str {
        "hardware"
    }

    fn is_available(&self) -> bool {
        Path::new(self.device_path()).exists()
    }

    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        let tcti = TctiNameConf::from_str(&self.tcti)
            .map_err(|e| Error::NoEntropy(format!("TPM2: {}", e)))?;

        let mut ctx =
            Context::create(tcti).map_err(|e| Error::NoEntropy(format!("TPM2: {}", e)))?;

        let mut buf = Vec::with_capacity(count);
        while buf.len() < count {
            let remaining = count - buf.len();
            let chunk_size = remaining.min(TPM_MAX_RANDOM_CHUNK);
            let digest = ctx
                .get_random(chunk_size)
                .map_err(|e| Error::NoEntropy(format!("TPM2: {}", e)))?;
            buf.extend_from_slice(digest.as_bytes());
        }

        // Truncate in case the last chunk overshot (the TPM may return
        // exactly what we asked for, but be defensive).
        buf.truncate(count);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default_tcti() {
        let config = Tpm2Config::default();
        let source = Tpm2Source::new(&config);
        assert_eq!(source.tcti, "device:/dev/tpmrm0");
    }

    #[test]
    fn test_new_custom_tcti() {
        let config = Tpm2Config {
            enabled: true,
            tcti: Some("device:/dev/tpm0".to_string()),
        };
        let source = Tpm2Source::new(&config);
        assert_eq!(source.tcti, "device:/dev/tpm0");
    }

    #[test]
    fn test_is_available_no_device() {
        let config = Tpm2Config {
            enabled: true,
            tcti: Some("device:/dev/nonexistent_tpm_device_xyz".to_string()),
        };
        let source = Tpm2Source::new(&config);
        assert!(!source.is_available());
    }
}
