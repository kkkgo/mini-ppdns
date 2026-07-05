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

/// How many entries to sample when choosing a cap-eviction victim.
const EVICT_SAMPLE: usize = 8;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

impl CacheKey {
    /// FNV-1a over the key, used to pick a shard.
    fn shard_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in &self.name {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for b in self.qtype.to_be_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for b in self.qclass.to_be_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
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

    /// Store `msg` under `key` for `ttl_secs`. A zero TTL is treated as 1s so an
    /// immediately-retried query still hits the cache.
    pub fn store(&self, key: CacheKey, msg: Arc<CachedMsg>, ttl_secs: u32) {
        let ttl = ttl_secs.max(1);
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

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, qtype: u16) -> CacheKey {
        CacheKey {
            name: name.as_bytes().to_vec(),
            qtype,
            qclass: 1,
        }
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
