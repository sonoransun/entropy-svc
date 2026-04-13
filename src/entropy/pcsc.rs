use pcsc;

use crate::config::PcscConfig;
use crate::error::Error;

use super::EntropySource;

/// Entropy source that uses a PC/SC smart card reader to collect random bytes
/// via the ISO 7816 GET CHALLENGE command.
pub struct PcscSource {
    reader_filter: Option<String>,
    max_le: u8,
}

impl PcscSource {
    pub fn new(config: &PcscConfig) -> Self {
        Self {
            reader_filter: config.reader.clone(),
            max_le: config.max_le,
        }
    }
}

impl EntropySource for PcscSource {
    fn name(&self) -> &str {
        "pcsc"
    }

    fn description(&self) -> &str {
        "PC/SC smart card (GET CHALLENGE)"
    }

    fn priority(&self) -> u32 {
        7
    }

    fn source_type(&self) -> &str {
        "hardware"
    }

    fn is_available(&self) -> bool {
        let ctx = match pcsc::Context::establish(pcsc::Scope::User) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let mut reader_buf = [0u8; 2048];
        let readers = match ctx.list_readers(&mut reader_buf) {
            Ok(r) => r,
            Err(_) => return false,
        };

        // At least one reader must be present.
        readers.count() > 0
    }

    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)
            .map_err(|e| Error::NoEntropy(format!("PC/SC context failed: {}", e)))?;

        let mut reader_buf = [0u8; 2048];
        let readers = ctx
            .list_readers(&mut reader_buf)
            .map_err(|e| Error::NoEntropy(format!("PC/SC list readers failed: {}", e)))?;

        let readers: Vec<&std::ffi::CStr> = readers.collect();
        if readers.is_empty() {
            return Err(Error::NoEntropy("PC/SC: no readers found".into()));
        }

        // Pick a reader: apply substring filter if configured, otherwise take the first.
        let reader = if let Some(ref filter) = self.reader_filter {
            readers
                .iter()
                .find(|r| {
                    r.to_string_lossy().contains(filter.as_str())
                })
                .copied()
                .ok_or_else(|| {
                    Error::NoEntropy(format!(
                        "PC/SC: no reader matching filter '{}'",
                        filter
                    ))
                })?
        } else {
            readers[0]
        };

        let card = ctx
            .connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|e| Error::NoEntropy(format!("PC/SC connect failed: {}", e)))?;

        let mut result = Vec::with_capacity(count);
        let mut resp_buf = [0u8; 258];

        while result.len() < count {
            let remaining = count - result.len();
            let le = remaining.min(self.max_le as usize) as u8;
            let apdu = [0x00, 0x84, 0x00, 0x00, le];

            let resp = card
                .transmit(&apdu, &mut resp_buf)
                .map_err(|e| Error::NoEntropy(format!("PC/SC transmit failed: {}", e)))?;

            if resp.len() < 2 {
                return Err(Error::NoEntropy(
                    "PC/SC: response too short".into(),
                ));
            }

            let sw1 = resp[resp.len() - 2];
            let sw2 = resp[resp.len() - 1];
            if sw1 != 0x90 || sw2 != 0x00 {
                return Err(Error::NoEntropy(format!(
                    "PC/SC GET CHALLENGE failed: SW={:02X}{:02X}",
                    sw1, sw2
                )));
            }

            let data = &resp[..resp.len() - 2];
            result.extend_from_slice(data);
        }

        result.truncate(count);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default_config() {
        let config = PcscConfig::default();
        let source = PcscSource::new(&config);
        assert!(source.reader_filter.is_none());
        assert_eq!(source.max_le, 32);
    }

    #[test]
    fn test_new_custom_reader_filter() {
        let config = PcscConfig {
            enabled: true,
            reader: Some("Identiv".to_string()),
            max_le: 64,
        };
        let source = PcscSource::new(&config);
        assert_eq!(source.reader_filter.as_deref(), Some("Identiv"));
        assert_eq!(source.max_le, 64);
    }
}
