use std::path::Path;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

use crate::config::Pkcs11Config;
use crate::error::Error;

use super::EntropySource;

/// Entropy source that uses a PKCS#11 token to generate random bytes
/// via the `C_GenerateRandom` mechanism.
pub struct Pkcs11Source {
    library_path: String,
    slot_index: usize,
    pin: Option<String>,
}

impl Pkcs11Source {
    pub fn new(config: &Pkcs11Config) -> Self {
        Self {
            library_path: config
                .library_path
                .as_deref()
                .unwrap_or("")
                .to_string(),
            slot_index: config.slot_id.unwrap_or(0) as usize,
            pin: config.pin.clone(),
        }
    }
}

impl EntropySource for Pkcs11Source {
    fn name(&self) -> &str {
        "pkcs11"
    }

    fn description(&self) -> &str {
        "PKCS#11 token (C_GenerateRandom)"
    }

    fn priority(&self) -> u32 {
        6
    }

    fn source_type(&self) -> &str {
        "hardware"
    }

    fn is_available(&self) -> bool {
        Path::new(&self.library_path).exists()
    }

    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        let pkcs11 = Pkcs11::new(&self.library_path).map_err(|e| {
            Error::NoEntropy(format!("PKCS#11 library load failed: {}", e))
        })?;

        pkcs11.initialize(CInitializeArgs::OsThreads).map_err(|e| {
            Error::NoEntropy(format!("PKCS#11 initialize failed: {}", e))
        })?;

        let slots = pkcs11.get_slots_with_token().map_err(|e| {
            Error::NoEntropy(format!("PKCS#11 get_slots_with_token failed: {}", e))
        })?;

        let slot = slots.get(self.slot_index).ok_or_else(|| {
            Error::NoEntropy(format!(
                "PKCS#11 slot index {} not found ({} slots available)",
                self.slot_index,
                slots.len()
            ))
        })?;

        let session = pkcs11.open_ro_session(*slot).map_err(|e| {
            Error::NoEntropy(format!("PKCS#11 open_ro_session failed: {}", e))
        })?;

        if let Some(ref pin) = self.pin {
            session
                .login(UserType::User, Some(&AuthPin::new(pin.clone())))
                .map_err(|e| {
                    Error::NoEntropy(format!("PKCS#11 login failed: {}", e))
                })?;
        }

        let bytes = session.generate_random(count).map_err(|e| {
            Error::NoEntropy(format!("PKCS#11 generate_random failed: {}", e))
        })?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_extracts_config() {
        let config = Pkcs11Config {
            enabled: true,
            library_path: Some("/usr/lib/pkcs11/opensc-pkcs11.so".to_string()),
            slot_id: Some(2),
            pin: Some("1234".to_string()),
        };
        let source = Pkcs11Source::new(&config);
        assert_eq!(source.library_path, "/usr/lib/pkcs11/opensc-pkcs11.so");
        assert_eq!(source.slot_index, 2);
        assert_eq!(source.pin.as_deref(), Some("1234"));
    }

    #[test]
    fn test_new_defaults() {
        let config = Pkcs11Config::default();
        let source = Pkcs11Source::new(&config);
        assert_eq!(source.library_path, "");
        assert_eq!(source.slot_index, 0);
        assert!(source.pin.is_none());
    }

    #[test]
    fn test_is_available_nonexistent_library() {
        let config = Pkcs11Config {
            enabled: true,
            library_path: Some("/nonexistent/path/to/pkcs11.so".to_string()),
            slot_id: None,
            pin: None,
        };
        let source = Pkcs11Source::new(&config);
        assert!(!source.is_available());
    }
}
