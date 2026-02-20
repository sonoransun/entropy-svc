use crate::config::{CpuRngConfig, CpuRngPreference};
use crate::error::Error;
use core::sync::atomic::{fence, Ordering};

// ---------------------------------------------------------------------------
// Zeroize utilities (not arch-gated)
// ---------------------------------------------------------------------------

/// Volatile-zeroes a byte slice, preventing the compiler from eliding the write.
pub fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: pointer is valid and aligned (derived from a live mutable ref).
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    fence(Ordering::SeqCst);
}

/// Volatile-zeroes the contents of a Vec.
pub fn zeroize_vec(buf: &mut Vec<u8>) {
    zeroize_bytes(buf.as_mut_slice());
}

// ---------------------------------------------------------------------------
// x86_64 implementation
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::arch::asm;
    use core::sync::atomic::{AtomicU8, Ordering};

    // 0 = unchecked, 1 = absent, 2 = present
    static RDRAND_SUPPORT: AtomicU8 = AtomicU8::new(0);
    static RDSEED_SUPPORT: AtomicU8 = AtomicU8::new(0);
    static XSTORE_SUPPORT: AtomicU8 = AtomicU8::new(0);

    /// Checks CPUID leaf 1, ECX bit 30 for RDRAND support.
    pub fn has_rdrand() -> bool {
        let cached = RDRAND_SUPPORT.load(Ordering::Relaxed);
        if cached != 0 {
            return cached == 2;
        }

        // SAFETY: CPUID is always available on x86_64.
        let ecx: u32;
        unsafe {
            asm!(
                "push rbx",       // rbx is callee-saved
                "mov eax, 1",
                "cpuid",
                "mov {ecx:e}, ecx",
                "pop rbx",
                ecx = out(reg) ecx,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
            );
        }

        let present = (ecx >> 30) & 1 == 1;
        RDRAND_SUPPORT.store(if present { 2 } else { 1 }, Ordering::Relaxed);
        present
    }

    /// Checks CPUID leaf 7 subleaf 0, EBX bit 18 for RDSEED support.
    pub fn has_rdseed() -> bool {
        let cached = RDSEED_SUPPORT.load(Ordering::Relaxed);
        if cached != 0 {
            return cached == 2;
        }

        // SAFETY: CPUID is always available on x86_64.
        let ebx: u32;
        unsafe {
            asm!(
                "push rbx",
                "mov eax, 7",
                "xor ecx, ecx",
                "cpuid",
                "mov {ebx:e}, ebx",
                "pop rbx",
                ebx = out(reg) ebx,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
            );
        }

        let present = (ebx >> 18) & 1 == 1;
        RDSEED_SUPPORT.store(if present { 2 } else { 1 }, Ordering::Relaxed);
        present
    }

    /// Checks for VIA PadLock XSTORE (Centaur CPUID leaf 0xC0000001, EDX bits 2+3).
    pub fn has_xstore() -> bool {
        let cached = XSTORE_SUPPORT.load(Ordering::Relaxed);
        if cached != 0 {
            return cached == 2;
        }

        // First check if Centaur extended range is available.
        let max_centaur: u32;
        unsafe {
            asm!(
                "push rbx",
                "mov eax, 0xC0000000",
                "cpuid",
                "mov {out:e}, eax",
                "pop rbx",
                out = out(reg) max_centaur,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
            );
        }

        if max_centaur < 0xC0000001 {
            XSTORE_SUPPORT.store(1, Ordering::Relaxed);
            return false;
        }

        // Check leaf 0xC0000001 EDX bit 2 (RNG present) and bit 3 (RNG enabled).
        let edx: u32;
        unsafe {
            asm!(
                "push rbx",
                "mov eax, 0xC0000001",
                "cpuid",
                "mov {edx:e}, edx",
                "pop rbx",
                edx = out(reg) edx,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
            );
        }

        let present = (edx & 0b1100) == 0b1100; // bits 2 and 3 both set
        XSTORE_SUPPORT.store(if present { 2 } else { 1 }, Ordering::Relaxed);
        present
    }

    /// Executes RDRAND and returns the 64-bit result, retrying up to `retries` times.
    pub fn rdrand64(retries: u32) -> Option<u64> {
        for _ in 0..retries {
            let value: u64;
            let success: u8;
            unsafe {
                asm!(
                    "rdrand {val}",
                    "setc {ok}",
                    val = out(reg) value,
                    ok = out(reg_byte) success,
                );
            }
            if success != 0 {
                return Some(value);
            }
        }
        None
    }

    /// Executes RDSEED and returns the 64-bit result, retrying up to `retries` times.
    pub fn rdseed64(retries: u32) -> Option<u64> {
        for _ in 0..retries {
            let value: u64;
            let success: u8;
            unsafe {
                asm!(
                    "rdseed {val}",
                    "setc {ok}",
                    val = out(reg) value,
                    ok = out(reg_byte) success,
                );
            }
            if success != 0 {
                return Some(value);
            }
        }
        None
    }

    /// Fills an 8-byte buffer using the VIA PadLock XSTORE instruction.
    /// `quality` is the quality factor (0-3): 0=raw, 3=max von Neumann whitening.
    /// Returns true on success.
    pub fn xstore_bytes(buf: &mut [u8; 8], quality: u32) -> bool {
        let ptr = buf.as_mut_ptr();
        let ok: u8;
        unsafe {
            asm!(
                // rep xstore-rng: F3 0F A7 C0
                ".byte 0xF3, 0x0F, 0xA7, 0xC0",
                "setc {ok}",
                ok = out(reg_byte) ok,
                in("edi") ptr, // destination pointer
                in("edx") quality, // quality factor
                in("ecx") 8u32, // byte count
                options(nostack),
            );
        }
        ok != 0
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of CPU entropy collection, including the bytes and which instruction was used.
#[derive(Debug)]
pub struct CpuRngResult {
    pub bytes: Vec<u8>,
    pub source_label: &'static str,
}

/// Collects `count` bytes of entropy from RDSEED.
pub fn collect_rdseed(count: usize, retries: u32) -> Result<Vec<u8>, Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if !x86::has_rdseed() {
            return Err(Error::NoEntropy("RDSEED not supported on this CPU".into()));
        }
        let mut buf = vec![0u8; count];
        let mut offset = 0;
        while offset < count {
            let val = x86::rdseed64(retries).ok_or_else(|| {
                Error::NoEntropy(format!("RDSEED failed after {} retries", retries))
            })?;
            let bytes = val.to_ne_bytes();
            let to_copy = (count - offset).min(8);
            buf[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
            offset += to_copy;
        }
        Ok(buf)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (count, retries);
        Err(Error::NoEntropy(
            "CPU hardware RNG not available on this architecture".into(),
        ))
    }
}

/// Collects `count` bytes of entropy from RDRAND.
pub fn collect_rdrand(count: usize, retries: u32) -> Result<Vec<u8>, Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if !x86::has_rdrand() {
            return Err(Error::NoEntropy("RDRAND not supported on this CPU".into()));
        }
        let mut buf = vec![0u8; count];
        let mut offset = 0;
        while offset < count {
            let val = x86::rdrand64(retries).ok_or_else(|| {
                Error::NoEntropy(format!("RDRAND failed after {} retries", retries))
            })?;
            let bytes = val.to_ne_bytes();
            let to_copy = (count - offset).min(8);
            buf[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
            offset += to_copy;
        }
        Ok(buf)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (count, retries);
        Err(Error::NoEntropy(
            "CPU hardware RNG not available on this architecture".into(),
        ))
    }
}

/// Collects `count` bytes of entropy from VIA PadLock XSTORE.
pub fn collect_xstore(count: usize, quality: u32) -> Result<Vec<u8>, Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if !x86::has_xstore() {
            return Err(Error::NoEntropy("XSTORE not supported on this CPU".into()));
        }
        let mut buf = vec![0u8; count];
        let mut offset = 0;
        while offset < count {
            let mut tmp = [0u8; 8];
            if !x86::xstore_bytes(&mut tmp, quality) {
                zeroize_bytes(&mut tmp);
                return Err(Error::NoEntropy("XSTORE instruction failed".into()));
            }
            let to_copy = (count - offset).min(8);
            buf[offset..offset + to_copy].copy_from_slice(&tmp[..to_copy]);
            zeroize_bytes(&mut tmp);
            offset += to_copy;
        }
        Ok(buf)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (count, quality);
        Err(Error::NoEntropy(
            "CPU hardware RNG not available on this architecture".into(),
        ))
    }
}

/// Returns the instruction order based on the preferred instruction.
/// The preferred instruction comes first, then the remaining two in a fixed order.
fn instruction_order(config: &CpuRngConfig) -> Vec<CpuRngPreference> {
    let all = match config.prefer {
        CpuRngPreference::Rdseed => [
            CpuRngPreference::Rdseed,
            CpuRngPreference::Rdrand,
            CpuRngPreference::Xstore,
        ],
        CpuRngPreference::Rdrand => [
            CpuRngPreference::Rdrand,
            CpuRngPreference::Rdseed,
            CpuRngPreference::Xstore,
        ],
        CpuRngPreference::Xstore => [
            CpuRngPreference::Xstore,
            CpuRngPreference::Rdseed,
            CpuRngPreference::Rdrand,
        ],
    };

    all.into_iter()
        .filter(|pref| match pref {
            CpuRngPreference::Rdseed => config.enable_rdseed,
            CpuRngPreference::Rdrand => config.enable_rdrand,
            CpuRngPreference::Xstore => config.enable_xstore,
        })
        .collect()
}

/// Tries a single instruction, returning the bytes and source label on success.
fn try_instruction(
    pref: CpuRngPreference,
    count: usize,
    config: &CpuRngConfig,
) -> Result<(Vec<u8>, &'static str), Error> {
    match pref {
        CpuRngPreference::Rdseed => {
            let bytes = collect_rdseed(count, config.rdseed_retries)?;
            Ok((bytes, "RDSEED"))
        }
        CpuRngPreference::Rdrand => {
            let bytes = collect_rdrand(count, config.rdrand_retries)?;
            Ok((bytes, "RDRAND"))
        }
        CpuRngPreference::Xstore => {
            let bytes = collect_xstore(count, config.xstore_quality)?;
            Ok((bytes, "XSTORE"))
        }
    }
}

/// Collects `count` bytes of CPU entropy using the configured instruction preference
/// and fallback order. Returns the bytes and which instruction succeeded.
pub fn collect_cpu_entropy(count: usize, config: &CpuRngConfig) -> Result<CpuRngResult, Error> {
    let order = instruction_order(config);

    if order.is_empty() {
        return Err(Error::NoEntropy(
            "all CPU RNG instructions are disabled".into(),
        ));
    }

    let mut last_err = None;
    for pref in order {
        match try_instruction(pref, count, config) {
            Ok((bytes, label)) => {
                return Ok(CpuRngResult {
                    bytes,
                    source_label: label,
                });
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| Error::NoEntropy("no CPU RNG instruction succeeded".into())))
}

/// Collects CPU entropy with optional oversampling for the standalone path.
/// If `oversample > 1`, collects `count * oversample` raw bytes and compresses
/// through BLAKE2b → ChaCha20 to produce `count` output bytes.
pub fn collect_cpu_entropy_standalone(
    count: usize,
    config: &CpuRngConfig,
) -> Result<CpuRngResult, Error> {
    if config.oversample <= 1 {
        return collect_cpu_entropy(count, config);
    }

    let raw_count = count.saturating_mul(config.oversample as usize);
    let result = collect_cpu_entropy(raw_count, config)?;

    let mut raw_bytes = result.bytes;
    let seed = crate::mixer::mix_entropy(&[("cpu-rng-oversample", &raw_bytes)]);
    let output = crate::csprng::generate(seed, count);

    zeroize_vec(&mut raw_bytes);

    Ok(CpuRngResult {
        bytes: output,
        source_label: result.source_label,
    })
}

/// Best-effort CPU entropy collection. Returns an empty Vec on failure.
pub fn collect_cpu_entropy_best_effort(count: usize, config: &CpuRngConfig) -> Vec<u8> {
    collect_cpu_entropy(count, config)
        .map(|r| r.bytes)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_bytes() {
        let mut buf = vec![0xAA; 16];
        zeroize_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_vec() {
        let mut buf = vec![0xFF; 32];
        zeroize_vec(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_empty() {
        let mut buf: Vec<u8> = Vec::new();
        zeroize_vec(&mut buf);
        assert!(buf.is_empty());

        let mut empty: [u8; 0] = [];
        zeroize_bytes(&mut empty);
    }

    #[test]
    fn test_instruction_order_prefer_rdseed() {
        let config = CpuRngConfig {
            prefer: CpuRngPreference::Rdseed,
            ..Default::default()
        };
        let order = instruction_order(&config);
        assert_eq!(order.len(), 3);
        assert_eq!(order[0], CpuRngPreference::Rdseed);
        assert_eq!(order[1], CpuRngPreference::Rdrand);
        assert_eq!(order[2], CpuRngPreference::Xstore);
    }

    #[test]
    fn test_instruction_order_prefer_xstore() {
        let config = CpuRngConfig {
            prefer: CpuRngPreference::Xstore,
            ..Default::default()
        };
        let order = instruction_order(&config);
        assert_eq!(order.len(), 3);
        assert_eq!(order[0], CpuRngPreference::Xstore);
        assert_eq!(order[1], CpuRngPreference::Rdseed);
        assert_eq!(order[2], CpuRngPreference::Rdrand);
    }

    #[test]
    fn test_instruction_order_filtered() {
        let config = CpuRngConfig {
            enable_rdrand: false,
            prefer: CpuRngPreference::Rdseed,
            ..Default::default()
        };
        let order = instruction_order(&config);
        assert_eq!(order.len(), 2);
        assert!(!order.contains(&CpuRngPreference::Rdrand));
    }

    #[test]
    fn test_all_disabled_error() {
        let config = CpuRngConfig {
            enable_rdseed: false,
            enable_rdrand: false,
            enable_xstore: false,
            ..Default::default()
        };
        let result = collect_cpu_entropy(32, &config);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("disabled"));
    }
}
