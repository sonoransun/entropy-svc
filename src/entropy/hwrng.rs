use std::fs::File;
use std::io::Read;

use crate::error::Error;

/// Attempts to read `count` bytes from /dev/hwrng (hardware RNG).
pub fn read_hwrng(count: usize) -> Result<Vec<u8>, Error> {
    let mut f = File::open("/dev/hwrng").map_err(|e| {
        Error::NoEntropy(format!("/dev/hwrng not available: {}", e))
    })?;
    let mut buf = vec![0u8; count];
    f.read_exact(&mut buf)?;
    Ok(buf)
}
