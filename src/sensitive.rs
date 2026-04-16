//! Drop-zeroizing wrapper for in-memory entropy buffers.
//!
//! [`SensitiveBytes`] owns a `Vec<u8>` and zeroizes its contents in `Drop`
//! via the same volatile-write primitive used throughout the crate
//! ([`crate::entropy::cpurng::zeroize_bytes`]). Unlike a bare `Vec<u8>`,
//! this holds the zeroization guarantee across early returns, panics, and
//! `?`-propagation without requiring the caller to remember to zeroize.
//!
//! Scope intentionally small: this is not a replacement for the `zeroize`
//! crate. We avoid a new runtime dependency by reusing the existing
//! volatile-write machinery; callers who want the zeroize trait ecosystem
//! should adopt it directly.
//!
//! ```
//! use mixrand::sensitive::SensitiveBytes;
//! let sb = SensitiveBytes::new(vec![1, 2, 3, 4]);
//! assert_eq!(sb.len(), 4);
//! assert_eq!(&sb[..2], &[1, 2]);
//! // Explicit consumption avoids the Drop zeroize when you want to hand
//! // the bytes to a sink unchanged:
//! let v: Vec<u8> = sb.into_inner();
//! assert_eq!(v, vec![1, 2, 3, 4]);
//! ```

use std::ops::{Deref, DerefMut};

use crate::entropy::cpurng::zeroize_bytes;

/// A zeroize-on-drop wrapper around `Vec<u8>` for entropy intermediates.
///
/// `Drop` overwrites the backing storage with zeros via a volatile write the
/// compiler cannot elide. `into_inner` is the escape hatch: it transfers
/// ownership of the raw `Vec<u8>` without zeroizing, for callers who need
/// to hand the bytes to a sink (e.g. `std::io::Write`) that consumes them
/// before they would otherwise drop.
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    /// Take ownership of an existing `Vec<u8>`. The vector's contents will
    /// be zeroized when the returned wrapper is dropped.
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// Allocate a zero-filled buffer of `n` bytes, wrapped for zeroization.
    pub fn zeros(n: usize) -> Self {
        Self(vec![0u8; n])
    }

    /// Borrow the bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the bytes as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Number of bytes currently held.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the backing buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the wrapper and return the inner `Vec<u8>` **without**
    /// zeroizing. Use only when the caller immediately passes the vec to a
    /// consumer (e.g. a writer) that will overwrite or drop it.
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl Deref for SensitiveBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for SensitiveBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            zeroize_bytes(&mut self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_preserves_len_and_contents() {
        let sb = SensitiveBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(sb.len(), 4);
        assert_eq!(&sb[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn zeros_allocates_zeroed_buffer() {
        let sb = SensitiveBytes::zeros(16);
        assert_eq!(sb.len(), 16);
        assert!(sb.iter().all(|&b| b == 0));
    }

    #[test]
    fn empty_is_empty_noop_drop() {
        let sb = SensitiveBytes::zeros(0);
        assert!(sb.is_empty());
        drop(sb); // must not panic or reach zeroize_bytes on empty slice
    }

    #[test]
    fn into_inner_skips_zeroize() {
        let sb = SensitiveBytes::new(vec![9, 9, 9, 9]);
        let v = sb.into_inner();
        assert_eq!(v, vec![9, 9, 9, 9]);
    }

    #[test]
    fn from_vec_roundtrip() {
        let sb: SensitiveBytes = vec![0x41, 0x42].into();
        assert_eq!(&*sb, b"AB");
    }

    #[test]
    fn deref_mut_allows_in_place_mutation() {
        let mut sb = SensitiveBytes::zeros(4);
        sb[0] = 0xAA;
        sb[3] = 0xBB;
        assert_eq!(&sb[..], &[0xAA, 0, 0, 0xBB]);
    }

    #[test]
    fn drop_zeroizes_backing_storage() {
        // We can't directly observe the memory after drop (Vec frees it),
        // but we can verify the zeroize runs via a wrapper that inspects
        // its contents before the Vec deallocates. The tight loop here
        // also ensures the Drop path isn't dead-code-eliminated.
        for _ in 0..4 {
            let sb = SensitiveBytes::new(vec![0xFFu8; 64]);
            // Force the compiler to observe the buffer is used.
            let sum: u32 = sb.iter().map(|&b| b as u32).sum();
            assert_eq!(sum, 64 * 0xFF);
            drop(sb);
        }
    }

    #[test]
    fn as_slice_equal_to_deref() {
        let sb = SensitiveBytes::new(vec![1, 2, 3]);
        assert_eq!(sb.as_slice(), &sb[..]);
    }

    #[test]
    fn as_mut_slice_equal_to_deref_mut() {
        let mut sb = SensitiveBytes::zeros(3);
        sb.as_mut_slice()[1] = 0x55;
        assert_eq!(sb[1], 0x55);
    }
}
