// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Sharded TTL cache. Keyed by the lower-cased
//! wire name + qtype + qclass, values are `Arc<CachedMsg>` (owned records +
//! rcode). Sharding by a cheap FNV hash keeps lock contention low under load.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use domain::base::iana::Rcode;

use crate::dns::OwnedRecord;
use crate::util::{hash, hash_extend};

/// How many entries to sample when choosing a cap-eviction victim.
const EVICT_SAMPLE: usize = 8;

/// Cap on a stored entry's lifetime, whatever TTL the upstream claims: a
/// broken/hostile upstream can advertise ~136 years, which would pin the entry
/// until restart. A day matches common resolver practice (Unbound caps at a
/// day, BIND at a week).
const MAX_TTL_SECS: u32 = 86_400;

/// Hasher for a key that already carries its hash: the shard maps index on the
/// value `CacheKey::hash` writes and never touch the key bytes.
///
/// Sound only because `util::hash` is seeded per process (see its docs) — which
/// bucket a key lands in must not be attacker-predictable.
#[derive(Default)]
pub struct PreHashed(u64);

impl Hasher for PreHashed {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        // Only reached if something hashes a key we did not pre-hash; falling
        // back to a real hash keeps such a use correct rather than degenerate.
        self.0 = hash_extend(self.0, hash(bytes));
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }
}

type Shard = HashMap<CacheKey, Entry, BuildHasherDefault<PreHashed>>;

#[derive(Clone, PartialEq, Eq)]
pub struct CacheKey {
    /// `util::hash` of `name`. First field so the derived `PartialEq`
    /// rejects mismatched keys on one u64 compare before touching the name
    /// bytes. Always derived from `name` (constructor-enforced), so equality
    /// and hashing stay consistent.
    name_hash: u64,
    pub name: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

impl CacheKey {
    /// Build a key, hashing `name` here (tests only).
    #[cfg(test)]
    pub fn new(name: Vec<u8>, qtype: u16, qclass: u16) -> Self {
        let name_hash = hash(&name);
        CacheKey {
            name_hash,
            name,
            qtype,
            qclass,
        }
    }

    /// Build a key from the per-query hash computed in `dns::extract_query`,
    /// so the hot path never re-hashes the name.
    pub fn with_hash(name: Vec<u8>, qtype: u16, qclass: u16, name_hash: u64) -> Self {
        debug_assert_eq!(name_hash, hash(&name), "name_hash must be util::hash(name)");
        CacheKey {
            name_hash,
            name,
            qtype,
            qclass,
        }
    }

    /// The key's full hash: the name's hash folded over qtype/qclass, without
    /// re-reading the name. Selects the shard *and* is what the shard map
    /// indexes on (see [`PreHashed`]).
    fn key_hash(&self) -> u64 {
        hash_extend(
            self.name_hash,
            (u64::from(self.qtype) << 16) | u64::from(self.qclass),
        )
    }
}

impl std::hash::Hash for CacheKey {
    /// Writes the precomputed hash and nothing else — [`PreHashed`] takes it
    /// verbatim. Equality still compares the full key, so distinct names that
    /// happen to collide stay distinct entries.
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.key_hash());
    }
}

/// A cached response: enough to rebuild the client answer with a fresh TTL.
pub struct CachedMsg {
    pub rcode: Rcode,
    pub answers: Vec<OwnedRecord>,
    pub authority: Vec<OwnedRecord>,
    pub additional: Vec<OwnedRecord>,
}

struct Entry {
    msg: Arc<CachedMsg>,
    expires: Instant,
}

pub struct Cache {
    shards: Box<[Mutex<Shard>]>,
    shard_mask: usize,
    per_shard_cap: usize,
}

impl Cache {
    /// Build a cache with roughly `total_cap` total entries across shards.
    pub fn new(total_cap: usize) -> Self {
        const SHARDS: usize = 64; // power of two
        let per_shard_cap = (total_cap / SHARDS).max(1);
        let shards = (0..SHARDS)
            .map(|_| Mutex::new(Shard::default()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Cache {
            shards,
            shard_mask: SHARDS - 1,
            per_shard_cap,
        }
    }

    fn shard(&self, key: &CacheKey) -> &Mutex<Shard> {
        let idx = (key.key_hash() as usize) & self.shard_mask;
        &self.shards[idx]
    }

    /// Return the cached message and its remaining TTL (seconds, floored at 1)
    /// if present and unexpired.
    pub fn get(&self, key: &CacheKey) -> Option<(Arc<CachedMsg>, u32)> {
        let now = Instant::now();
        let mut shard = self.shard(key).lock().unwrap();
        match shard.get(key) {
            Some(entry) if entry.expires > now => {
                let secs = (entry.expires - now).as_secs();
                let ttl_left = if secs < 1 {
                    1
                } else {
                    secs.min(u32::MAX as u64) as u32
                };
                Some((entry.msg.clone(), ttl_left))
            }
            Some(_) => {
                // Expired: evict in place.
                shard.remove(key);
                None
            }
            None => None,
        }
    }

    /// Store `msg` under `key` for `ttl_secs`, clamped to `[1, MAX_TTL_SECS]`:
    /// a zero TTL is treated as 1s so an immediately-retried query still hits
    /// the cache, and an oversized TTL must not pin the entry (see
    /// `MAX_TTL_SECS`).
    pub fn store(&self, key: CacheKey, msg: Arc<CachedMsg>, ttl_secs: u32) {
        let ttl = ttl_secs.clamp(1, MAX_TTL_SECS);
        let expires = Instant::now() + Duration::from_secs(ttl as u64);
        let mut shard = self.shard(&key).lock().unwrap();
        if shard.len() >= self.per_shard_cap && !shard.contains_key(&key) {
            // Sample a few entries and evict the soonest-expiring one. This is a
            // cheap O(EVICT_SAMPLE) approximation of TTL-ordered eviction that
            // favors near-dead entries over long-lived ones, without the O(n)
            // scan (or a per-shard heap) that exact "evict oldest" would need.
            let victim = shard
                .iter()
                .take(EVICT_SAMPLE)
                .min_by_key(|(_, e)| e.expires)
                .map(|(k, _)| k.clone());
            if let Some(victim) = victim {
                shard.remove(&victim);
            }
        }
        shard.insert(key, Entry { msg, expires });
    }

    /// Drop every entry (used when the hook marks the main DNS down).
    pub fn flush(&self) {
        for shard in self.shards.iter() {
            shard.lock().unwrap().clear();
        }
    }

    /// Sweep expired entries; called periodically by the janitor.
    pub fn sweep(&self) {
        let now = Instant::now();
        for shard in self.shards.iter() {
            shard.lock().unwrap().retain(|_, e| e.expires > now);
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, qtype: u16) -> CacheKey {
        CacheKey::new(name.as_bytes().to_vec(), qtype, 1)
    }

    fn msg() -> Arc<CachedMsg> {
        Arc::new(CachedMsg {
            rcode: Rcode::NOERROR,
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        })
    }

    #[test]
    fn store_get_hit_and_ttl() {
        let c = Cache::new(1024);
        c.store(key("a", 1), msg(), 300);
        let (_, ttl) = c.get(&key("a", 1)).expect("hit");
        assert!((1..=300).contains(&ttl));
        assert!(c.get(&key("b", 1)).is_none());
    }

    #[test]
    fn ttl_capped() {
        let c = Cache::new(1024);
        c.store(key("a", 1), msg(), u32::MAX);
        let (_, ttl) = c.get(&key("a", 1)).expect("hit");
        assert!(ttl <= MAX_TTL_SECS, "ttl {ttl} not capped");
    }

    #[test]
    fn flush_clears() {
        let c = Cache::new(1024);
        c.store(key("a", 1), msg(), 300);
        assert_eq!(c.len(), 1);
        c.flush();
        assert!(c.is_empty());
    }

    #[test]
    fn cap_evicts() {
        // total_cap/64 shards → per-shard cap 1; second key in same shard evicts.
        let c = Cache::new(64);
        assert_eq!(c.per_shard_cap, 1);
        for i in 0..200u16 {
            c.store(key("x", i), msg(), 300);
        }
        // Never exceeds shards * per_shard_cap.
        assert!(c.len() <= 64);
    }
}
