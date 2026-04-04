use serde::Serialize;

/// Result of a single statistical test.
#[derive(Serialize)]
pub struct TestResult {
    pub name: &'static str,
    pub passed: bool,
    pub value: f64,
    pub range: (f64, f64),
    pub detail: String,
}

/// Result of the FIPS 140-2 test suite.
#[derive(Serialize)]
pub struct FipsResult {
    pub monobit: TestResult,
    pub poker: TestResult,
    pub runs: TestResult,
    pub long_runs: TestResult,
}

impl FipsResult {
    pub fn all_passed(&self) -> bool {
        self.monobit.passed && self.poker.passed && self.runs.passed && self.long_runs.passed
    }
}

/// Entropy quality estimates.
#[derive(Serialize)]
pub struct EntropyEstimates {
    pub shannon: f64,
    pub min_entropy: f64,
    pub chi_square: f64,
    pub mean: f64,
    pub serial_correlation: f64,
    pub approx_entropy_m2: f64,
    pub approx_entropy_m3: f64,
    pub compression_ratio: f64,
    pub block_entropy_2: f64,
    pub block_entropy_4: f64,
    pub autocorrelation: Vec<f64>,
}

/// FIPS 140-2 Monobit Test.
/// Counts the number of 1-bits in the 20,000-bit (2500-byte) sample.
pub fn fips_monobit(data: &[u8; 2500]) -> TestResult {
    let count: u32 = data.iter().map(|b| b.count_ones()).sum();
    let passed = count > 9725 && count < 10275;
    TestResult {
        name: "Monobit",
        passed,
        value: count as f64,
        range: (9725.0, 10275.0),
        detail: format!("ones count: {}", count),
    }
}

/// FIPS 140-2 Poker Test.
/// Divides 20,000 bits into 5,000 4-bit nibbles and computes chi-square.
pub fn fips_poker(data: &[u8; 2500]) -> TestResult {
    let mut counts = [0u32; 16];
    for &byte in data.iter() {
        counts[(byte >> 4) as usize] += 1;
        counts[(byte & 0x0F) as usize] += 1;
    }
    let sum_sq: u64 = counts.iter().map(|&c| (c as u64) * (c as u64)).sum();
    let x = (16.0 / 5000.0) * sum_sq as f64 - 5000.0;
    let passed = x > 2.16 && x < 46.17;
    TestResult {
        name: "Poker",
        passed,
        value: x,
        range: (2.16, 46.17),
        detail: format!("chi-square: {:.2}", x),
    }
}

/// FIPS 140-2 Runs Test.
/// Counts runs of consecutive identical bits by length (1-6+), separately
/// for 0-bits and 1-bits. All 12 categories must fall within bounds.
pub fn fips_runs(data: &[u8; 2500]) -> TestResult {
    let mut runs_0 = [0u32; 6]; // runs of 0-bits: length 1, 2, 3, 4, 5, 6+
    let mut runs_1 = [0u32; 6]; // runs of 1-bits: length 1, 2, 3, 4, 5, 6+

    let mut current_bit: u8 = (data[0] >> 7) & 1;
    let mut run_len: u32 = 0;

    for &byte in data.iter() {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            if bit == current_bit {
                run_len += 1;
            } else {
                let bucket = ((run_len as usize) - 1).min(5);
                if current_bit == 0 {
                    runs_0[bucket] += 1;
                } else {
                    runs_1[bucket] += 1;
                }
                current_bit = bit;
                run_len = 1;
            }
        }
    }
    // Record the last run
    let bucket = ((run_len as usize) - 1).min(5);
    if current_bit == 0 {
        runs_0[bucket] += 1;
    } else {
        runs_1[bucket] += 1;
    }

    let lower: [u32; 6] = [2315, 1114, 527, 240, 103, 103];
    let upper: [u32; 6] = [2685, 1386, 723, 384, 209, 209];

    let mut all_passed = true;
    let mut failures = Vec::new();
    let mut passed_count = 0u32;

    for i in 0..6 {
        let len_label = if i < 5 {
            format!("{}", i + 1)
        } else {
            "6+".to_string()
        };
        if runs_0[i] >= lower[i] && runs_0[i] <= upper[i] {
            passed_count += 1;
        } else {
            all_passed = false;
            failures.push(format!(
                "0-runs len {}: {} not in [{}, {}]",
                len_label, runs_0[i], lower[i], upper[i]
            ));
        }
        if runs_1[i] >= lower[i] && runs_1[i] <= upper[i] {
            passed_count += 1;
        } else {
            all_passed = false;
            failures.push(format!(
                "1-runs len {}: {} not in [{}, {}]",
                len_label, runs_1[i], lower[i], upper[i]
            ));
        }
    }

    let detail = if all_passed {
        "all 12 run categories within bounds".to_string()
    } else {
        failures.join("; ")
    };

    TestResult {
        name: "Runs",
        passed: all_passed,
        value: passed_count as f64,
        range: (12.0, 12.0),
        detail,
    }
}

/// FIPS 140-2 Long Runs Test.
/// Checks that the longest run of consecutive identical bits is at most 25.
pub fn fips_long_runs(data: &[u8; 2500]) -> TestResult {
    let mut max_run: u32 = 0;
    let mut current_bit: u8 = (data[0] >> 7) & 1;
    let mut run_len: u32 = 0;

    for &byte in data.iter() {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            if bit == current_bit {
                run_len += 1;
            } else {
                max_run = max_run.max(run_len);
                current_bit = bit;
                run_len = 1;
            }
        }
    }
    max_run = max_run.max(run_len);

    let passed = max_run <= 25;
    TestResult {
        name: "Long Runs",
        passed,
        value: max_run as f64,
        range: (0.0, 25.0),
        detail: format!("longest run: {} bits", max_run),
    }
}

/// Run all four FIPS 140-2 tests on a 2500-byte (20,000-bit) sample.
pub fn fips_suite(data: &[u8; 2500]) -> FipsResult {
    FipsResult {
        monobit: fips_monobit(data),
        poker: fips_poker(data),
        runs: fips_runs(data),
        long_runs: fips_long_runs(data),
    }
}

/// Compute byte frequency distribution.
fn byte_frequencies(data: &[u8]) -> [u64; 256] {
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    freq
}

/// Shannon entropy in bits per byte (max 8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let freq = byte_frequencies(data);
    let n = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Min-entropy: -log2(max(p(x))).
pub fn min_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let freq = byte_frequencies(data);
    let n = data.len() as f64;
    let max_count = *freq.iter().max().unwrap_or(&0) as f64;
    -(max_count / n).log2()
}

/// Chi-square statistic over byte frequencies (df=255).
pub fn chi_square(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let freq = byte_frequencies(data);
    let expected = data.len() as f64 / 256.0;
    freq.iter()
        .map(|&obs| {
            let diff = obs as f64 - expected;
            diff * diff / expected
        })
        .sum()
}

/// Mean byte value (expected 127.5 for uniform random).
pub fn mean_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().map(|&b| b as f64).sum::<f64>() / data.len() as f64
}

/// Serial correlation coefficient (lag-1 autocorrelation, expected ~0.0).
pub fn serial_correlation(data: &[u8]) -> f64 {
    autocorrelation(data, 1)
}

/// Autocorrelation at a given lag.
pub fn autocorrelation(data: &[u8], lag: usize) -> f64 {
    if data.len() <= lag {
        return 0.0;
    }
    let n = data.len() as f64;
    let mean = data.iter().map(|&b| b as f64).sum::<f64>() / n;

    let mut numerator = 0.0;
    for i in 0..data.len() - lag {
        numerator += (data[i] as f64 - mean) * (data[i + lag] as f64 - mean);
    }

    let denominator: f64 = data
        .iter()
        .map(|&b| {
            let d = b as f64 - mean;
            d * d
        })
        .sum();

    if denominator.abs() < f64::EPSILON {
        return 0.0;
    }

    numerator / denominator
}

/// Multi-lag autocorrelation for lags 1..=max_lag.
pub fn multi_lag_autocorrelation(data: &[u8], max_lag: usize) -> Vec<f64> {
    (1..=max_lag).map(|lag| autocorrelation(data, lag)).collect()
}

/// Approximate Entropy (ApEn) for block size m.
///
/// Operates on the bit-level representation of data (NIST standard formulation).
/// For truly random data, ApEn(m=2) approaches ln(2) ≈ 0.693.
/// Lower values indicate more regularity (less randomness).
pub fn approximate_entropy(data: &[u8], m: usize) -> f64 {
    if m == 0 || data.is_empty() {
        return 0.0;
    }

    // Convert bytes to bits
    let n_bits = data.len() * 8;
    if n_bits <= m + 1 {
        return 0.0;
    }

    fn get_bit(data: &[u8], bit_index: usize) -> u8 {
        let byte_index = bit_index / 8;
        let bit_offset = 7 - (bit_index % 8);
        (data[byte_index] >> bit_offset) & 1
    }

    fn phi_bits(data: &[u8], n_bits: usize, m: usize) -> f64 {
        use std::collections::HashMap;
        if n_bits < m {
            return 0.0;
        }

        let num_patterns = n_bits - m + 1;
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for i in 0..num_patterns {
            let mut pattern: u64 = 0;
            for j in 0..m {
                pattern = (pattern << 1) | get_bit(data, i + j) as u64;
            }
            *counts.entry(pattern).or_insert(0) += 1;
        }

        let n_f = num_patterns as f64;
        counts
            .values()
            .map(|&c| {
                let p = c as f64 / n_f;
                p * p.ln()
            })
            .sum::<f64>()
    }

    phi_bits(data, n_bits, m) - phi_bits(data, n_bits, m + 1)
}

/// Lempel-Ziv complexity estimate (normalized).
///
/// Uses LZ78-style dictionary parsing: scans left-to-right, building phrases
/// where each new phrase extends a previously seen phrase by one byte.
/// For random data over an alphabet of size A and length n, expected
/// complexity ≈ n / log_A(n). Returns the ratio, which should be ≈ 1.0 for
/// random data and < 1.0 for structured data.
pub fn lempel_ziv_complexity(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    use std::collections::HashSet;
    let n = data.len();
    let mut dictionary = HashSet::new();
    let mut complexity = 0u64;
    let mut i = 0;

    while i < n {
        let mut k = 1;
        while i + k <= n && dictionary.contains(&data[i..i + k]) {
            k += 1;
        }
        if i + k <= n {
            dictionary.insert(&data[i..i + k]);
        }
        complexity += 1;
        i += k;
    }

    // For alphabet size A=256, expected phrases ≈ n / log_A(n)
    let log_alpha_n = (n as f64).ln() / 256.0_f64.ln();
    let expected = if log_alpha_n > f64::EPSILON {
        n as f64 / log_alpha_n
    } else {
        n as f64
    };
    complexity as f64 / expected
}

/// Block entropy: Shannon entropy computed over multi-byte blocks.
///
/// For block_size=2, treats each pair of consecutive bytes as a 16-bit symbol.
/// Returns entropy in bits per byte (not per block).
pub fn block_entropy(data: &[u8], block_size: usize) -> f64 {
    if block_size == 0 || data.len() < block_size {
        return 0.0;
    }

    use std::collections::HashMap;
    let mut counts: HashMap<&[u8], u64> = HashMap::new();
    let num_blocks = data.len() / block_size;
    if num_blocks == 0 {
        return 0.0;
    }

    for i in 0..num_blocks {
        let start = i * block_size;
        *counts.entry(&data[start..start + block_size]).or_insert(0) += 1;
    }

    let n = num_blocks as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        if count > 0 {
            let p = count as f64 / n;
            entropy -= p * p.log2();
        }
    }

    // Normalize to bits per byte
    entropy / block_size as f64
}

/// Standard normal CDF (Abramowitz & Stegun approximation).
pub fn normal_cdf(x: f64) -> f64 {
    if x < 0.0 {
        return 1.0 - normal_cdf(-x);
    }

    let b1 = 0.319381530;
    let b2 = -0.356563782;
    let b3 = 1.781477937;
    let b4 = -1.821255978;
    let b5 = 1.330274429;
    let p = 0.2316419;

    let t = 1.0 / (1.0 + p * x);
    let phi = (-x * x / 2.0).exp() / (2.0 * std::f64::consts::PI).sqrt();

    1.0 - phi * (b1 * t + b2 * t * t + b3 * t.powi(3) + b4 * t.powi(4) + b5 * t.powi(5))
}

/// Chi-square p-value using Wilson-Hilferty normal approximation.
pub fn chi_square_p_value(chi_sq: f64, df: f64) -> f64 {
    if df <= 0.0 || chi_sq < 0.0 {
        return 0.0;
    }
    let cube_root = (chi_sq / df).powf(1.0 / 3.0);
    let mean = 1.0 - 2.0 / (9.0 * df);
    let stddev = (2.0 / (9.0 * df)).sqrt();
    let z = (cube_root - mean) / stddev;
    1.0 - normal_cdf(z)
}

/// Compute all entropy estimates for a byte slice.
pub fn entropy_estimates(data: &[u8]) -> EntropyEstimates {
    EntropyEstimates {
        shannon: shannon_entropy(data),
        min_entropy: min_entropy(data),
        chi_square: chi_square(data),
        mean: mean_byte(data),
        serial_correlation: serial_correlation(data),
        approx_entropy_m2: approximate_entropy(data, 2),
        approx_entropy_m3: approximate_entropy(data, 3),
        compression_ratio: lempel_ziv_complexity(data),
        block_entropy_2: block_entropy(data, 2),
        block_entropy_4: block_entropy(data, 4),
        autocorrelation: multi_lag_autocorrelation(data, 16),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_zeros() -> [u8; 2500] {
        [0u8; 2500]
    }

    fn all_aa() -> [u8; 2500] {
        [0xAA; 2500]
    }

    fn chacha_data() -> Vec<u8> {
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut data = vec![0u8; 4096];
        rng.fill_bytes(&mut data);
        data
    }

    // --- FIPS Monobit ---

    #[test]
    fn test_monobit_zeros_fails() {
        let result = fips_monobit(&all_zeros());
        assert!(!result.passed);
        assert_eq!(result.value, 0.0);
    }

    #[test]
    fn test_monobit_aa_passes() {
        let result = fips_monobit(&all_aa());
        assert!(result.passed);
        assert_eq!(result.value, 10000.0);
    }

    // --- FIPS Poker ---

    #[test]
    fn test_poker_zeros_fails() {
        let result = fips_poker(&all_zeros());
        assert!(!result.passed);
    }

    #[test]
    fn test_poker_aa_fails() {
        let result = fips_poker(&all_aa());
        assert!(!result.passed);
    }

    // --- FIPS Runs ---

    #[test]
    fn test_runs_zeros_fails() {
        let result = fips_runs(&all_zeros());
        assert!(!result.passed);
    }

    #[test]
    fn test_runs_aa_fails() {
        let result = fips_runs(&all_aa());
        assert!(!result.passed);
    }

    // --- FIPS Long Runs ---

    #[test]
    fn test_long_runs_zeros_fails() {
        let result = fips_long_runs(&all_zeros());
        assert!(!result.passed);
        assert_eq!(result.value, 20000.0);
    }

    #[test]
    fn test_long_runs_aa_passes() {
        let result = fips_long_runs(&all_aa());
        assert!(result.passed);
        assert_eq!(result.value, 1.0);
    }

    // --- Shannon Entropy ---

    #[test]
    fn test_shannon_uniform() {
        let mut data = vec![0u8; 256 * 100];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }
        let s = shannon_entropy(&data);
        assert!((s - 8.0).abs() < 0.01, "expected ~8.0, got {}", s);
    }

    #[test]
    fn test_shannon_constant() {
        let data = vec![42u8; 1000];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    // --- Min Entropy ---

    #[test]
    fn test_min_entropy_uniform() {
        let mut data = vec![0u8; 256 * 100];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }
        let m = min_entropy(&data);
        assert!((m - 8.0).abs() < 0.01, "expected ~8.0, got {}", m);
    }

    // --- Mean Byte ---

    #[test]
    fn test_mean_byte_uniform() {
        let mut data = vec![0u8; 256];
        for i in 0..256 {
            data[i] = i as u8;
        }
        let m = mean_byte(&data);
        assert!((m - 127.5).abs() < 0.01, "expected ~127.5, got {}", m);
    }

    // --- Serial Correlation ---

    #[test]
    fn test_serial_correlation_constant() {
        let data = vec![42u8; 1000];
        assert_eq!(serial_correlation(&data), 0.0);
    }

    #[test]
    fn test_serial_correlation_alternating() {
        let mut data = vec![0u8; 1000];
        for i in 0..1000 {
            data[i] = if i % 2 == 0 { 0 } else { 255 };
        }
        let s = serial_correlation(&data);
        assert!(s < -0.9, "expected strong negative correlation, got {}", s);
    }

    // --- Normal CDF ---

    #[test]
    fn test_normal_cdf() {
        assert!((normal_cdf(0.0) - 0.5).abs() < 0.001);
        assert!((normal_cdf(5.0) - 1.0).abs() < 0.001);
        assert!(normal_cdf(-5.0) < 0.001);
    }

    // --- Integration: ChaCha20Rng passes all FIPS ---

    #[test]
    fn test_fips_suite_chacha20() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};

        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut data = [0u8; 2500];
        rng.fill_bytes(&mut data);

        let result = fips_suite(&data);
        assert!(result.monobit.passed, "monobit: {}", result.monobit.detail);
        assert!(result.poker.passed, "poker: {}", result.poker.detail);
        assert!(result.runs.passed, "runs: {}", result.runs.detail);
        assert!(
            result.long_runs.passed,
            "long runs: {}",
            result.long_runs.detail
        );
    }

    // --- Approximate Entropy ---

    #[test]
    fn test_approx_entropy_random() {
        let data = chacha_data();
        let apen = approximate_entropy(&data, 2);
        // For random bit-level data, ApEn(m=2) should be near ln(2) ≈ 0.693
        assert!(apen > 0.5, "expected ApEn near 0.693, got {}", apen);
        assert!(apen < 0.9, "expected ApEn near 0.693, got {}", apen);
    }

    #[test]
    fn test_approx_entropy_constant() {
        // All-zero bytes produce a constant bit stream (all 0-bits)
        let data = vec![0u8; 1000];
        let apen = approximate_entropy(&data, 2);
        assert!(apen.abs() < 0.01, "expected ~0 for constant bit data, got {}", apen);
    }

    #[test]
    fn test_approx_entropy_empty() {
        assert_eq!(approximate_entropy(&[], 2), 0.0);
    }

    // --- Multi-lag Autocorrelation ---

    #[test]
    fn test_autocorrelation_random() {
        let data = chacha_data();
        let ac = multi_lag_autocorrelation(&data, 16);
        assert_eq!(ac.len(), 16);
        // Random data should have near-zero autocorrelation at all lags
        for (lag, &val) in ac.iter().enumerate() {
            assert!(
                val.abs() < 0.1,
                "autocorrelation at lag {} = {}, expected near 0",
                lag + 1,
                val
            );
        }
    }

    #[test]
    fn test_autocorrelation_alternating() {
        let mut data = vec![0u8; 1000];
        for i in 0..1000 {
            data[i] = if i % 2 == 0 { 0 } else { 255 };
        }
        let ac = multi_lag_autocorrelation(&data, 4);
        // Lag 1 should be strongly negative
        assert!(ac[0] < -0.9, "lag-1 should be negative: {}", ac[0]);
        // Lag 2 should be positive (repeats every 2)
        assert!(ac[1] > 0.9, "lag-2 should be positive: {}", ac[1]);
    }

    // --- Lempel-Ziv Complexity ---

    #[test]
    fn test_lz_complexity_random() {
        let data = chacha_data();
        let lz = lempel_ziv_complexity(&data);
        // Random data: most bytes form new phrases, ratio should be high
        assert!(lz > 0.7, "expected LZ ratio near 1.0, got {}", lz);
        assert!(lz < 1.5, "expected LZ ratio near 1.0, got {}", lz);
    }

    #[test]
    fn test_lz_complexity_constant() {
        let data = vec![42u8; 1000];
        let lz = lempel_ziv_complexity(&data);
        // Constant data: only ~log(n) phrases, much less than expected
        assert!(lz < 0.1, "expected low LZ ratio for constant data, got {}", lz);
    }

    #[test]
    fn test_lz_complexity_empty() {
        assert_eq!(lempel_ziv_complexity(&[]), 0.0);
        assert_eq!(lempel_ziv_complexity(&[42]), 0.0);
    }

    // --- Block Entropy ---

    #[test]
    fn test_block_entropy_random() {
        let data = chacha_data();
        let be2 = block_entropy(&data, 2);
        let be4 = block_entropy(&data, 4);
        // With 4096 bytes: 2048 two-byte blocks from 65536 possible → max ~log2(2048)/2 ≈ 5.5 bits/byte
        // 1024 four-byte blocks from 2^32 possible → max ~log2(1024)/4 ≈ 2.5 bits/byte
        assert!(be2 > 5.0, "expected block entropy > 5.0, got {}", be2);
        assert!(be4 > 2.0, "expected block entropy > 2.0, got {}", be4);
        // Both should be higher than constant data
        assert!(be2 > be4, "2-byte blocks should have higher per-byte entropy than 4-byte");
    }

    #[test]
    fn test_block_entropy_constant() {
        let data = vec![42u8; 1000];
        let be = block_entropy(&data, 2);
        assert!(be < 0.01, "expected ~0 for constant data, got {}", be);
    }

    #[test]
    fn test_block_entropy_empty() {
        assert_eq!(block_entropy(&[], 2), 0.0);
    }

    // --- entropy_estimates integration ---

    #[test]
    fn test_entropy_estimates_complete() {
        let data = chacha_data();
        let est = entropy_estimates(&data);
        assert!(est.shannon > 7.0);
        assert!(est.min_entropy > 5.0);
        assert!(est.autocorrelation.len() == 16);
        assert!(est.compression_ratio > 0.0);
        assert!(est.block_entropy_2 > 0.0);
    }

    // --- Edge cases and boundary conditions ---

    #[test]
    fn test_approximate_entropy_short_data() {
        // 1 byte = 8 bits, m=10 means we need > 10+1=11 bits, so should return 0.0
        assert_eq!(approximate_entropy(&[0xFF], 10), 0.0);
    }

    #[test]
    fn test_lempel_ziv_single_byte() {
        // data.len() < 2 should return 0.0
        assert_eq!(lempel_ziv_complexity(&[42]), 0.0);
    }

    #[test]
    fn test_lempel_ziv_two_identical() {
        let lz = lempel_ziv_complexity(&[42, 42]);
        assert!(lz > 0.0, "expected > 0.0 for two-byte input, got {}", lz);
    }

    #[test]
    fn test_block_entropy_block_exceeds_data() {
        assert_eq!(block_entropy(&[1, 2, 3], 4), 0.0);
    }

    #[test]
    fn test_block_entropy_zero_block_size() {
        assert_eq!(block_entropy(&[1, 2, 3], 0), 0.0);
    }

    #[test]
    fn test_block_entropy_exact_one_block() {
        // Single block means one symbol with p=1.0, so entropy = 0.0
        assert_eq!(block_entropy(&[1, 2], 2), 0.0);
    }

    #[test]
    fn test_autocorrelation_lag_equals_len() {
        assert_eq!(autocorrelation(&[1, 2, 3], 3), 0.0);
    }

    #[test]
    fn test_autocorrelation_lag_exceeds_len() {
        assert_eq!(autocorrelation(&[1, 2], 5), 0.0);
    }

    #[test]
    fn test_chi_square_p_value_edges() {
        let p_low_chi = chi_square_p_value(0.0, 255.0);
        assert!(
            (p_low_chi - 1.0).abs() < 0.01,
            "expected p-value ~1.0 for chi_sq=0.0, got {}",
            p_low_chi
        );
        let p_high_chi = chi_square_p_value(1000.0, 255.0);
        assert!(
            p_high_chi < 0.01,
            "expected p-value ~0.0 for chi_sq=1000.0, got {}",
            p_high_chi
        );
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_min_entropy_empty() {
        assert_eq!(min_entropy(&[]), 0.0);
    }

    #[test]
    fn test_mean_byte_empty() {
        assert_eq!(mean_byte(&[]), 0.0);
    }
}
