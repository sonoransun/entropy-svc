/// Result of a single statistical test.
pub struct TestResult {
    pub name: &'static str,
    pub passed: bool,
    pub value: f64,
    pub range: (f64, f64),
    pub detail: String,
}

/// Result of the FIPS 140-2 test suite.
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
pub struct EntropyEstimates {
    pub shannon: f64,
    pub min_entropy: f64,
    pub chi_square: f64,
    pub mean: f64,
    pub serial_correlation: f64,
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
    let max_count = *freq.iter().max().unwrap() as f64;
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
    if data.len() < 2 {
        return 0.0;
    }
    let n = data.len() as f64;
    let mean = data.iter().map(|&b| b as f64).sum::<f64>() / n;

    let mut numerator = 0.0;
    for i in 0..data.len() - 1 {
        numerator += (data[i] as f64 - mean) * (data[i + 1] as f64 - mean);
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

    // --- FIPS Monobit ---

    #[test]
    fn test_monobit_zeros_fails() {
        let result = fips_monobit(&all_zeros());
        assert!(!result.passed);
        assert_eq!(result.value, 0.0);
    }

    #[test]
    fn test_monobit_aa_passes() {
        // 0xAA = 10101010, each byte has 4 ones → 2500 * 4 = 10000
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
        // All 5000 nibbles are 0xA → extreme chi-square
        let result = fips_poker(&all_aa());
        assert!(!result.passed);
    }

    // --- FIPS Runs ---

    #[test]
    fn test_runs_zeros_fails() {
        // Single run of 20000 zeros → length-1 count is 0
        let result = fips_runs(&all_zeros());
        assert!(!result.passed);
    }

    #[test]
    fn test_runs_aa_fails() {
        // 10000 runs of length 1 for each bit value, way above upper bound
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
        // Max run is 1 bit
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
        // All same values → denominator is 0, should return 0.0
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
}
