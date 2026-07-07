// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Sharded TTL cache. Keyed by the lower-cased
//! wire name + qtype + qclass, values are `Arc<CachedMsg>` (owned records +
//! rcode). Sharding by a cheap FNV hash keeps lock contention low under load.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use domain::base::iana::Rcode;

use crate::dns::OwnedRecord;
use crate::util::{fnv1a, fnv1a_continue};

/// How many entries to sample when choosing a cap-eviction victim.
const EVICT_SAMPLE: usize = 8;

/// Cap on a stored entry's lifetime, whatever TTL the upstream claims: a
/// broken/hostile upstream can advertise ~136 years, which would pin the entry
/// until restart. A day matches common resolver practice (Unbound caps at a
/// day, BIND at a week).
const MAX_TTL_SECS: u32 = 86_400;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// `util::fnv1a` of `name`. First field so the derived `PartialEq`
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
        let name_hash = fnv1a(&name);
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
        debug_assert_eq!(name_hash, fnv1a(&name), "name_hash must be fnv1a(name)");
        CacheKey {
            name_hash,
            name,
            qtype,
            qclass,
        }
    }

    /// Shard selector: continue the name's FNV over qtype/qclass — the same
    /// value as hashing the whole key in one run, without re-reading the name.
    fn shard_hash(&self) -> u64 {
        let h = fnv1a_continue(self.name_hash, &self.qtype.to_be_bytes());
        fnv1a_continue(h, &self.qclass.to_be_bytes())
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
    shards: Box<[Mutex<HashMap<CacheKey, Entry>>]>,
    shard_mask: usize,
    per_shard_cap: usize,
}

impl Cache {
    /// Build a cache with roughly `total_cap` total entries across shards.
    pub fn new(total_cap: usize) -> Self {
        const SHARDS: usize = 64; // power of two
        let per_shard_cap = (total_cap / SHARDS).max(1);
        let shards = (0..SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Cache {
            shards,
            shard_mask: SHARDS - 1,
            per_shard_cap,
        }
    }

    fn shard(&self, key: &CacheKey) -> &Mutex<HashMap<CacheKey, Entry>> {
        let idx = (key.shard_hash() as usize) & self.shard_mask;
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
