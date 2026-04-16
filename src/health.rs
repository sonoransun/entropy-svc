//! Continuous health tests per NIST SP 800-90B.
//!
//! Two online tests run on every 64-bit sample fed to the tester:
//! - **Repetition Count Test (RCT)** — detects stuck outputs (same value
//!   repeated beyond a cutoff).
//! - **Adaptive Proportion Test (APT)** — detects bias toward one value
//!   across a sliding 1024-sample window.
//!
//! Cutoffs are derived from the caller's estimated min-entropy per sample.
//! Failures increment counters; the first failure for any source should
//! cause that source to be skipped by the cascade.

/// Default assumed min-entropy per 64-bit sample (in bits).
///
/// H=4.0 gives RCT cutoff of 11 and conservative APT thresholds. This is a
/// deliberate underestimate for defense in depth: true hardware RNG entropy
/// should be considerably higher, but overestimating here causes APT false
/// negatives on legitimately flawed sources.
pub const DEFAULT_MIN_ENTROPY_BITS: f64 = 4.0;

/// Health test state for a single entropy source.
///
/// Holds streaming state for both RCT and APT so the caller can feed samples
/// one at a time as they arrive from the source. Clone-free; intended to be
/// owned by the source implementation for the lifetime of the process.
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
    /// `min_entropy_bits` is the estimated min-entropy per sample (H). The
    /// RCT cutoff `C = 1 + ceil(40 / H)`. The APT window size is 1024; its
    /// cutoff is derived from a normal approximation to the binomial with a
    /// 5-sigma margin.
    ///
    /// A negative or zero `H` is clamped to a very conservative cutoff
    /// (C = 42) so the tester still progresses instead of panicking.
    ///
    /// # Examples
    ///
    /// ```
    /// use mixrand::health::HealthTester;
    /// let mut ht = HealthTester::new(4.0);
    /// assert!(ht.feed(0xdead_beef).is_ok());
    /// assert!(!ht.has_failures());
    /// ```
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

    // ---- edge-case tests for real-world pathological sources ----

    #[test]
    fn test_stuck_source_all_0xff_detected_within_cutoff() {
        // Simulates a stuck hardware source returning 0xff...ff forever.
        // H=4.0 -> RCT cutoff = 11. RCT must fail on or before the 11th sample.
        let mut ht = HealthTester::new(4.0);
        let mut failed_at = None;
        for i in 0..20 {
            if ht.feed(u64::MAX).is_err() {
                failed_at = Some(i + 1);
                break;
            }
        }
        assert_eq!(failed_at, Some(11), "expected RCT to fail at 11th sample");
        assert_eq!(ht.rct_failures(), 1);
    }

    #[test]
    fn test_stuck_source_all_zeros_detected() {
        // A source returning 0x00...00 is equally stuck.
        let mut ht = HealthTester::new(4.0);
        for _ in 0..10 {
            assert!(ht.feed(0).is_ok());
        }
        assert!(ht.feed(0).is_err(), "11th zero should trigger RCT");
    }

    #[test]
    fn test_biased_source_triggers_apt_but_not_rct() {
        // Interleave 10 zeros with 1 unique value so the longest run of the
        // candidate (0) is 10 — below RCT cutoff of 41 for H=1.0 — but the
        // window still contains ~930/1024 zeros, above APT cutoff (~592).
        let mut ht = HealthTester::new(1.0);
        let mut triggered = false;
        for i in 0u64..1200 {
            let sample = if i % 11 == 10 { 0xdead_beef + i } else { 0 };
            if ht.feed(sample).is_err() {
                triggered = true;
                break;
            }
        }
        assert!(triggered, "APT should detect strong bias toward zero");
        assert_eq!(ht.rct_failures(), 0, "should not be an RCT failure");
        assert!(ht.apt_failures() >= 1, "should be at least one APT failure");
    }

    #[test]
    fn test_apt_window_boundary_unique_values() {
        // Feed exactly 1024 unique samples — window completes cleanly. Then
        // feed another 1024 unique samples in a new window.
        let mut ht = HealthTester::new(4.0);
        for i in 0..1024u64 {
            // Use distinct values to avoid RCT trigger.
            assert!(ht.feed(i.wrapping_mul(1009) ^ 0xa5a5_a5a5).is_ok());
        }
        for i in 1024..2048u64 {
            assert!(ht.feed(i.wrapping_mul(1009) ^ 0xa5a5_a5a5).is_ok());
        }
    }

    #[test]
    fn test_rct_cutoff_formula_small_entropy() {
        // H=2.0 -> cutoff = 1 + ceil(40/2) = 21
        let ht = HealthTester::new(2.0);
        assert_eq!(ht.rct_cutoff, 21);
        // H=8.0 -> cutoff = 1 + ceil(40/8) = 6
        let ht8 = HealthTester::new(8.0);
        assert_eq!(ht8.rct_cutoff, 6);
    }

    #[test]
    fn test_rct_count_resets_on_different_then_repeats() {
        // Ensure counter resets cleanly and a fresh repetition sequence has
        // its own cutoff budget.
        let mut ht = HealthTester::new(4.0);
        for _ in 0..5 {
            assert!(ht.feed(1).is_ok());
        }
        assert!(ht.feed(2).is_ok()); // reset
        for _ in 0..10 {
            assert!(ht.feed(3).is_ok());
        }
        // 11 total repetitions of 3 triggers RCT
        assert!(ht.feed(3).is_err());
    }

    // --- Property-style monotonicity checks for cutoffs ---

    #[test]
    fn property_rct_cutoff_monotone_in_h() {
        // Lower H -> larger RCT cutoff (more tolerant of repetition because
        // repetition is more expected under low entropy).
        let hs = [0.5, 1.0, 2.0, 4.0, 8.0, 12.0];
        let cutoffs: Vec<u32> = hs
            .iter()
            .map(|&h| HealthTester::new(h).rct_cutoff)
            .collect();
        for win in cutoffs.windows(2) {
            assert!(
                win[0] >= win[1],
                "RCT cutoff should be non-increasing in H: {cutoffs:?}"
            );
        }
    }

    #[test]
    fn property_apt_cutoff_monotone_in_h() {
        // Lower H -> larger APT cutoff (more samples may match the
        // candidate under low entropy without being anomalous).
        let hs = [0.5, 1.0, 2.0, 4.0, 8.0, 12.0];
        let cutoffs: Vec<u32> = hs
            .iter()
            .map(|&h| HealthTester::new(h).apt_cutoff)
            .collect();
        for win in cutoffs.windows(2) {
            assert!(
                win[0] >= win[1],
                "APT cutoff should be non-increasing in H: {cutoffs:?}"
            );
        }
    }

    #[test]
    fn test_rct_cutoff_at_h_4_equals_11() {
        // Pin the SP 800-90B reference cutoff: 1 + ceil(40/4) = 11.
        let ht = HealthTester::new(4.0);
        assert_eq!(ht.rct_cutoff, 11);
    }

    #[test]
    fn test_apt_window_rolls_over_after_1024() {
        // Fed a candidate value for 1024 samples then a fresh value — the
        // next window restarts, so the candidate counter is not leaking
        // across boundaries.
        let mut ht = HealthTester::new(4.0);
        // First 1024 samples: all 0xAA then flip to 0xBB (two distinct
        // windows). Because RCT would trip at 11 repetitions, vary within
        // a window while still rolling the APT boundary over.
        for i in 0..1024u64 {
            let v = i; // distinct each sample — RCT-safe
            assert!(ht.feed(v).is_ok(), "sample {i} unexpectedly rejected");
        }
        // Window restart: first sample of new window becomes the new
        // candidate. One more sample is trivially OK.
        assert!(ht.feed(0xDEAD_BEEF).is_ok());
        assert!(ht.feed(0xCAFE_D00D).is_ok());
    }

    #[test]
    fn test_rct_resets_cleanly_across_distinct_samples() {
        // After a 9-run of value A, a B (reset), then repetitions of C must
        // get a fresh cutoff budget of 11.
        let mut ht = HealthTester::new(4.0);
        for _ in 0..9 {
            assert!(ht.feed(100).is_ok());
        }
        assert!(ht.feed(200).is_ok()); // reset
                                       // Build up a fresh repetition run of 300. feed(300) produces
                                       // rct_count=1, then 2, 3, ... Up to 10 remain OK; the 11th errors.
        for i in 0..10 {
            assert!(ht.feed(300).is_ok(), "iter {i} unexpectedly failed");
        }
        assert!(ht.feed(300).is_err());
    }
}
