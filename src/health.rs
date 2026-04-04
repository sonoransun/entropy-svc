/// Default assumed min-entropy per 64-bit sample (in bits).
/// H=4.0 gives RCT cutoff of 11 and conservative APT thresholds.
/// This is a deliberate underestimate for defense-in-depth:
/// true hardware RNG entropy should be higher.
pub const DEFAULT_MIN_ENTROPY_BITS: f64 = 4.0;

/// Continuous health testing per NIST SP 800-90B.
///
/// Two tests run on every entropy sample:
/// - **Repetition Count Test**: detects a stuck source (same output repeated beyond cutoff)
/// - **Adaptive Proportion Test**: detects bias toward one value within a sliding window
///
/// Health test state for a single entropy source.
pub struct HealthTester {
    // Repetition Count Test state
    rct_last_value: u64,
    rct_count: u32,
    rct_cutoff: u32,

    // Adaptive Proportion Test state
    apt_window_size: usize,
    apt_candidate: u64,
    apt_count: u32,
    apt_position: usize,
    apt_cutoff: u32,

    // Counters
    rct_failures: u64,
    apt_failures: u64,
    total_samples: u64,
}

impl HealthTester {
    /// Create a new health tester.
    ///
    /// `min_entropy_bits` is the estimated min-entropy per sample (H).
    /// The RCT cutoff C = 1 + ceil(40 / H).
    /// The APT window size W = 1024, cutoff based on binomial distribution.
    pub fn new(min_entropy_bits: f64) -> Self {
        let rct_cutoff = if min_entropy_bits <= 0.0 {
            42 // very conservative for unknown entropy
        } else {
            1 + (40.0 / min_entropy_bits).ceil() as u32
        };

        // APT: window size 1024 is standard for 800-90B
        let apt_window_size = 1024;
        // APT cutoff: for H bits of entropy per sample, p_max = 2^(-H)
        // Cutoff ≈ W * p_max + 5*sqrt(W*p_max*(1-p_max)) (normal approx + margin)
        let p_max = 2.0_f64.powf(-min_entropy_bits.max(0.1));
        let expected = apt_window_size as f64 * p_max;
        let stddev = (apt_window_size as f64 * p_max * (1.0 - p_max)).sqrt();
        let apt_cutoff = (expected + 5.0 * stddev).ceil() as u32;

        Self {
            rct_last_value: 0,
            rct_count: 0,
            rct_cutoff,
            apt_window_size,
            apt_candidate: 0,
            apt_count: 0,
            apt_position: 0,
            apt_cutoff,
            rct_failures: 0,
            apt_failures: 0,
            total_samples: 0,
        }
    }

    /// Feed a 64-bit sample to the health tests.
    /// Returns `Ok(())` if the sample passes, `Err(reason)` if a test fails.
    pub fn feed(&mut self, sample: u64) -> Result<(), &'static str> {
        self.total_samples += 1;

        // --- Repetition Count Test ---
        if sample == self.rct_last_value {
            self.rct_count += 1;
            if self.rct_count >= self.rct_cutoff {
                self.rct_failures += 1;
                return Err("repetition count test failed (stuck source)");
            }
        } else {
            self.rct_last_value = sample;
            self.rct_count = 1;
        }

        // --- Adaptive Proportion Test ---
        if self.apt_position == 0 {
            // Start of new window
            self.apt_candidate = sample;
            self.apt_count = 1;
            self.apt_position = 1;
        } else {
            if sample == self.apt_candidate {
                self.apt_count += 1;
                if self.apt_count >= self.apt_cutoff {
                    self.apt_failures += 1;
                    self.apt_position = 0; // reset window
                    return Err("adaptive proportion test failed (biased source)");
                }
            }
            self.apt_position += 1;
            if self.apt_position >= self.apt_window_size {
                self.apt_position = 0; // window complete, start new one
            }
        }

        Ok(())
    }

    /// Returns the number of RCT failures.
    #[allow(dead_code)]
    pub fn rct_failures(&self) -> u64 {
        self.rct_failures
    }

    /// Returns the number of APT failures.
    #[allow(dead_code)]
    pub fn apt_failures(&self) -> u64 {
        self.apt_failures
    }

    /// Returns the total number of samples processed.
    #[allow(dead_code)]
    pub fn total_samples(&self) -> u64 {
        self.total_samples
    }

    /// Returns true if any health test has failed.
    #[allow(dead_code)]
    pub fn has_failures(&self) -> bool {
        self.rct_failures > 0 || self.apt_failures > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_samples_pass() {
        let mut ht = HealthTester::new(4.0);
        for i in 0..1000u64 {
            assert!(ht.feed(i).is_ok());
        }
        assert!(!ht.has_failures());
    }

    #[test]
    fn test_stuck_source_detected() {
        let mut ht = HealthTester::new(4.0);
        // RCT cutoff with H=4: 1 + ceil(40/4) = 11
        // Feed the same value 11 times
        for _ in 0..10 {
            let _ = ht.feed(42);
        }
        assert_eq!(ht.rct_failures(), 0);
        // 11th should fail
        assert!(ht.feed(42).is_err());
        assert_eq!(ht.rct_failures(), 1);
    }

    #[test]
    fn test_rct_resets_on_different_value() {
        let mut ht = HealthTester::new(4.0);
        for _ in 0..9 {
            assert!(ht.feed(42).is_ok());
        }
        // Different value resets counter
        assert!(ht.feed(99).is_ok());
        for _ in 0..9 {
            assert!(ht.feed(42).is_ok());
        }
        assert_eq!(ht.rct_failures(), 0);
    }

    #[test]
    fn test_apt_biased_source_detected() {
        let mut ht = HealthTester::new(1.0);
        // With H=1.0, p_max=0.5, cutoff ≈ 1024*0.5 + 5*sqrt(1024*0.25) ≈ 512+80 = 592
        // Feed mostly the same value
        let mut failed = false;
        for _ in 0..1024 {
            if ht.feed(42).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "APT should have detected bias");
    }

    #[test]
    fn test_low_entropy_conservative_cutoff() {
        let ht = HealthTester::new(0.5);
        // H=0.5: RCT cutoff = 1 + ceil(40/0.5) = 81
        assert_eq!(ht.rct_cutoff, 81);
    }

    #[test]
    fn test_has_failures_initially_false() {
        let ht = HealthTester::new(4.0);
        assert!(!ht.has_failures());
        assert_eq!(ht.rct_failures(), 0);
        assert_eq!(ht.apt_failures(), 0);
        assert_eq!(ht.total_samples(), 0);
    }

    #[test]
    fn test_rct_cutoff_zero_entropy() {
        // H=0.0 clamps to cutoff 42
        let mut ht = HealthTester::new(0.0);
        for _ in 0..41 {
            assert!(ht.feed(0).is_ok());
        }
        // 42nd identical value should fail
        assert!(ht.feed(0).is_err());
    }

    #[test]
    fn test_rct_cutoff_negative_entropy() {
        // H=-1.0 also clamps to cutoff 42
        let mut ht = HealthTester::new(-1.0);
        for _ in 0..41 {
            assert!(ht.feed(0).is_ok());
        }
        // 42nd identical value should fail
        assert!(ht.feed(0).is_err());
    }

    #[test]
    fn test_multiple_rct_failures_increment() {
        // H=4.0: cutoff = 1 + ceil(40/4) = 11
        let mut ht = HealthTester::new(4.0);
        // Feed 10 identical values — all pass (count goes 1..10, below cutoff 11)
        for _ in 0..10 {
            assert!(ht.feed(0).is_ok());
        }
        // 11th triggers first failure
        assert!(ht.feed(0).is_err());
        // 12th through 16th: each still identical, count stays >= cutoff, all fail
        for _ in 0..5 {
            assert!(ht.feed(0).is_err());
        }
        assert_eq!(ht.rct_failures(), 6);
    }

    #[test]
    fn test_apt_window_boundary() {
        let mut ht = HealthTester::new(4.0);
        // Feed 1024 unique values — should not trigger APT
        for i in 0..1024u64 {
            assert!(ht.feed(i).is_ok());
        }
    }

    #[test]
    fn test_total_samples_counter() {
        let mut ht = HealthTester::new(4.0);
        for i in 0..100u64 {
            let _ = ht.feed(i);
        }
        assert_eq!(ht.total_samples(), 100);
    }

    #[test]
    fn test_apt_reset_after_complete_window() {
        let mut ht = HealthTester::new(4.0);
        // First window: 1024 diverse samples
        for i in 0..1024u64 {
            assert!(ht.feed(i).is_ok());
        }
        // Second window: another 1024 diverse samples (offset to stay unique)
        for i in 1024..2048u64 {
            assert!(ht.feed(i).is_ok());
        }
    }
}
