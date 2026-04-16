use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::config::YubiHsmConfig;
use crate::error::Error;

use super::EntropySource;

/// Entropy source that uses a YubiHSM 2 to generate pseudo-random bytes
/// via the `GetPseudoRandom` command.
pub struct YubiHsmSource {
    connector_url: String,
    auth_key_id: u16,
    password: String,
}

impl YubiHsmSource {
    pub fn new(config: &YubiHsmConfig) -> Self {
        Self {
            connector_url: config
                .connector_url
                .as_deref()
                .unwrap_or("http://127.0.0.1:12345")
                .to_string(),
            auth_key_id: config.auth_key_id,
            password: config.password.as_deref().unwrap_or("password").to_string(),
        }
    }
}

impl EntropySource for YubiHsmSource {
    fn name(&self) -> &str {
        "yubihsm"
    }

    fn description(&self) -> &str {
        "YubiHSM 2 (GetPseudoRandom)"
    }

    fn priority(&self) -> u32 {
        6
    }

    fn source_type(&self) -> &str {
        "hardware"
    }

    fn is_available(&self) -> bool {
        // Parse the connector URL to extract host and port for a quick TCP probe.
        let url = &self.connector_url;
        let without_scheme = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .unwrap_or(url);

        // Strip any trailing path components
        let authority = without_scheme.split('/').next().unwrap_or(without_scheme);

        let timeout = Duration::from_millis(200);
        if let Ok(mut addrs) = authority.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                return TcpStream::connect_timeout(&addr, timeout).is_ok();
            }
        }

        false
    }

    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        let connector = yubihsm::connector::HttpConnector::new(&self.connector_url)
            .map_err(|e| Error::NoEntropy(format!("YubiHSM connector creation failed: {}", e)))?;

        let credentials =
            yubihsm::Credentials::from_password(self.auth_key_id, self.password.as_bytes());

        let client = yubihsm::Client::open(connector, credentials, true)
            .map_err(|e| Error::NoEntropy(format!("YubiHSM client open failed: {}", e)))?;

        let bytes = client
            .get_pseudo_random(count)
            .map_err(|e| Error::NoEntropy(format!("YubiHSM get_pseudo_random failed: {}", e)))?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_uses_defaults() {
        let config = YubiHsmConfig::default();
        let source = YubiHsmSource::new(&config);
        assert_eq!(source.connector_url, "http://127.0.0.1:12345");
        assert_eq!(source.auth_key_id, 1);
        assert_eq!(source.password, "password");
    }

    #[test]
    fn test_new_custom_config() {
        let config = YubiHsmConfig {
            enabled: true,
            connector_url: Some("http://10.0.0.5:12345".to_string()),
            auth_key_id: 42,
            password: Some("hunter2".to_string()),
        };
        let source = YubiHsmSource::new(&config);
        assert_eq!(source.connector_url, "http://10.0.0.5:12345");
        assert_eq!(source.auth_key_id, 42);
        assert_eq!(source.password, "hunter2");
    }

    #[test]
    fn test_is_available_no_connector() {
        let config = YubiHsmConfig::default();
        let source = YubiHsmSource::new(&config);
        // No YubiHSM connector running on dev machines, should return false.
        assert!(!source.is_available());
    }
}
