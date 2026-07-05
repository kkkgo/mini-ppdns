// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! A tiny, fast, per-thread non-cryptographic PRNG (wyrand). Used for upstream
//! selection shuffling and cache eviction — never for anything security-
//! sensitive. Thread-local state keeps it lock-free under high QPS.

use std::cell::Cell;

thread_local! {
    static STATE: Cell<u64> = Cell::new(seed());
}

fn seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Mix wall-clock nanos with a per-thread-unique stack address so distinct
    // threads start from distinct streams even within the same nanosecond.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e3779b97f4a7c15);
    let local = &nanos as *const _ as u64;
    nanos ^ local.rotate_left(32) ^ 0xa0761d6478bd642f
}

#[inline]
pub fn next_u64() -> u64 {
    STATE.with(|s| {
        let mut x = s.get().wrapping_add(0xa0761d6478bd642f);
        s.set(x);
        let t = (x as u128).wrapping_mul((x ^ 0xe7037ed1a0b428db) as u128);
        x = ((t >> 64) ^ t) as u64;
        x
    })
}

/// Uniformly-distributed value in `0..n` (n must be > 0).
#[inline]
pub fn below(n: usize) -> usize {
    (next_u64() % n as u64) as usize
}

/// Partial Fisher-Yates: shuffle the first `k` positions of `idx` in place,
/// enough to pick `k` distinct random elements. `k` must be <= `idx.len()`.
pub fn partial_shuffle(idx: &mut [usize], k: usize) {
    let n = idx.len();
    for i in 0..k {
        let j = i + below(n - i);
        idx.swap(i, j);
    }
}

/// Full in-place Fisher-Yates shuffle.
pub fn shuffle<T>(slice: &mut [T]) {
    let n = slice.len();
    for i in (1..n).rev() {
        let j = below(i + 1);
        slice.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_in_range() {
        for _ in 0..1000 {
            assert!(below(7) < 7);
        }
    }

    #[test]
    fn partial_shuffle_is_permutation() {
        let mut idx = [0usize, 1, 2, 3, 4];
        partial_shuffle(&mut idx, 3);
        let mut sorted = idx;
        sorted.sort_unstable();
        assert_eq!(sorted, [0, 1, 2, 3, 4]); // still a permutation
    }
}
