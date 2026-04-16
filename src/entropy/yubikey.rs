use pcsc;

use crate::config::YubiKeyConfig;
use crate::error::Error;

use super::EntropySource;

/// Maximum bytes to request per GET CHALLENGE APDU on a YubiKey PIV applet.
const YUBIKEY_MAX_LE: u8 = 32;

/// SELECT PIV applet APDU: CLA=00, INS=A4 (SELECT), P1=04 (by name),
/// P2=00, Lc=05, AID=A0 00 00 03 08.
const SELECT_PIV: [u8; 10] = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];

/// Entropy source that collects random bytes from a YubiKey via the PIV
/// applet's GET CHALLENGE command over PC/SC.
pub struct YubiKeySource {
    serial: Option<u32>,
}

impl YubiKeySource {
    pub fn new(config: &YubiKeyConfig) -> Self {
        Self {
            serial: config.serial,
        }
    }
}

/// Check whether a reader name refers to a YubiKey (case-insensitive).
fn is_yubikey_reader(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("yubico") || lower.contains("yubikey")
}

impl EntropySource for YubiKeySource {
    fn name(&self) -> &str {
        "yubikey"
    }

    fn description(&self) -> &str {
        "YubiKey (PIV GET CHALLENGE)"
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

        readers
            .into_iter()
            .any(|r| is_yubikey_reader(&r.to_string_lossy()))
    }

    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)
            .map_err(|e| Error::NoEntropy(format!("YubiKey: PC/SC context failed: {}", e)))?;

        let mut reader_buf = [0u8; 2048];
        let readers = ctx
            .list_readers(&mut reader_buf)
            .map_err(|e| Error::NoEntropy(format!("YubiKey: list readers failed: {}", e)))?;

        let reader = readers
            .into_iter()
            .find(|r| is_yubikey_reader(&r.to_string_lossy()))
            .ok_or_else(|| Error::NoEntropy("YubiKey: no YubiKey reader found".into()))?;

        let card = ctx
            .connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|e| Error::NoEntropy(format!("YubiKey: connect failed: {}", e)))?;

        // Select PIV applet.
        let mut resp_buf = [0u8; 258];
        let resp = card
            .transmit(&SELECT_PIV, &mut resp_buf)
            .map_err(|e| Error::NoEntropy(format!("YubiKey: SELECT PIV failed: {}", e)))?;

        if resp.len() < 2 {
            return Err(Error::NoEntropy(
                "YubiKey: SELECT PIV response too short".into(),
            ));
        }

        let sw1 = resp[resp.len() - 2];
        let sw2 = resp[resp.len() - 1];
        if sw1 != 0x90 || sw2 != 0x00 {
            return Err(Error::NoEntropy(format!(
                "YubiKey: SELECT PIV failed: SW={:02X}{:02X}",
                sw1, sw2
            )));
        }

        // Collect random bytes via GET CHALLENGE.
        let mut result = Vec::with_capacity(count);

        while result.len() < count {
            let remaining = count - result.len();
            let le = remaining.min(YUBIKEY_MAX_LE as usize) as u8;
            let apdu = [0x00, 0x84, 0x00, 0x00, le];

            let resp = card.transmit(&apdu, &mut resp_buf).map_err(|e| {
                Error::NoEntropy(format!("YubiKey: GET CHALLENGE transmit failed: {}", e))
            })?;

            if resp.len() < 2 {
                return Err(Error::NoEntropy(
                    "YubiKey: GET CHALLENGE response too short".into(),
                ));
            }

            let sw1 = resp[resp.len() - 2];
            let sw2 = resp[resp.len() - 1];
            if sw1 != 0x90 || sw2 != 0x00 {
                return Err(Error::NoEntropy(format!(
                    "YubiKey: GET CHALLENGE failed: SW={:02X}{:02X}",
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
        let config = YubiKeyConfig::default();
        let source = YubiKeySource::new(&config);
        assert!(source.serial.is_none());
    }

    #[test]
    fn test_is_available_returns_false_without_yubikey() {
        // On most dev/CI machines there is no YubiKey attached, so
        // is_available() should return false (or true if one happens to be
        // plugged in — either outcome is valid).
        let config = YubiKeyConfig::default();
        let source = YubiKeySource::new(&config);
        // Just ensure it does not panic.
        let _ = source.is_available();
    }
}
