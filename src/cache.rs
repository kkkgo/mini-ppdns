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

    /// The key's full hash (see [`key_hash`]).
    fn key_hash(&self) -> u64 {
        key_hash(self.name_hash, self.qtype, self.qclass)
    }
}

/// A key's full hash: the name's hash folded over qtype/qclass, without
/// re-reading the name. Selects the shard *and* is what the shard map indexes
/// on (see [`PreHashed`]).
fn key_hash(name_hash: u64, qtype: u16, qclass: u16) -> u64 {
    hash_extend(name_hash, (u64::from(qtype) << 16) | u64::from(qclass))
}

impl std::hash::Hash for CacheKey {
    /// Writes the precomputed hash and nothing else — [`PreHashed`] takes it
    /// verbatim. Equality still compares the full key, so distinct names that
    /// happen to collide stay distinct entries.
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.key_hash());
    }
}

/// A lookup key borrowed from the query being answered, so a lookup never has
/// to build an owned [`CacheKey`] (and copy the name into it).
#[derive(Clone, Copy)]
pub struct KeyRef<'a> {
    name: &'a [u8],
    name_hash: u64,
    qtype: u16,
    qclass: u16,
}

impl<'a> KeyRef<'a> {
    /// `name` is the lower-cased wire name and `name_hash` its `util::hash`,
    /// exactly as for [`CacheKey::with_hash`].
    pub fn new(name: &'a [u8], qtype: u16, qclass: u16, name_hash: u64) -> Self {
        debug_assert_eq!(name_hash, hash(name), "name_hash must be util::hash(name)");
        KeyRef {
            name,
            name_hash,
            qtype,
            qclass,
        }
    }
}

/// What a shard lookup reads from a key. The shard maps store owned
/// [`CacheKey`]s and are searched through this view, so a borrowed [`KeyRef`]
/// finds the same entry the owned key would.
///
/// For that to hold, both implementations must agree on everything `Hash` and
/// `Eq` see: the full hash, the name bytes, and the type and class.
pub trait KeyView {
    fn full_hash(&self) -> u64;
    fn name_bytes(&self) -> &[u8];
    fn type_class(&self) -> (u16, u16);
}

impl KeyView for CacheKey {
    fn full_hash(&self) -> u64 {
        self.key_hash()
    }
    fn name_bytes(&self) -> &[u8] {
        &self.name
    }
    fn type_class(&self) -> (u16, u16) {
        (self.qtype, self.qclass)
    }
}

impl KeyView for KeyRef<'_> {
    fn full_hash(&self) -> u64 {
        key_hash(self.name_hash, self.qtype, self.qclass)
    }
    fn name_bytes(&self) -> &[u8] {
        self.name
    }
    fn type_class(&self) -> (u16, u16) {
        (self.qtype, self.qclass)
    }
}

impl<'a> std::borrow::Borrow<dyn KeyView + 'a> for CacheKey {
    fn borrow(&self) -> &(dyn KeyView + 'a) {
        self
    }
}

impl std::hash::Hash for dyn KeyView + '_ {
    /// Must write exactly what `CacheKey`'s own `Hash` writes.
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.full_hash());
    }
}

impl PartialEq for dyn KeyView + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.type_class() == other.type_class() && self.name_bytes() == other.name_bytes()
    }
}

impl Eq for dyn KeyView + '_ {}

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
    /// How many times a negative answer for this key has been confirmed; 0 for
    /// positive entries. Kept past `expires` for [`NEG_GRACE`] — the entry is
    /// no longer served, it only remembers that this name keeps coming back
    /// negative, which is what makes the next one cache for longer.
    strikes: u8,
}

/// Where a negative answer starts: short enough that a name which only looks
/// absent (a momentary upstream failure, a record about to be published) is
/// re-checked within the minute.
pub const NEG_TTL_FLOOR: u32 = 60;
/// Each confirmation doubles the negative TTL, so a name that really does not
/// exist stops being asked about; the SOA's own ceiling (RFC 2308 §5) caps it.
/// Doubling stops here because 60 << 11 already passes [`MAX_TTL_SECS`].
const NEG_MAX_STRIKES: u8 = 12;
/// How long an expired negative entry keeps its strike count. A name asked
/// again within this window counts as a confirmation; one asked hours later
/// starts from the floor again.
const NEG_GRACE: Duration = Duration::from_secs(300);

pub struct Cache {
    shards: Box<[Mutex<Shard>]>,
    shard_mask: usize,
    per_shard_cap: usize,
}

/// Make space for `key` in a full shard. Samples a few entries and evicts the
/// soonest-expiring one: a cheap O(EVICT_SAMPLE) approximation of TTL-ordered
/// eviction that favors near-dead entries (a remembered negative expired long
/// ago, so it goes first) over long-lived ones, without the O(n) scan — or a
/// per-shard heap — that exact "evict oldest" would need.
fn make_room(shard: &mut Shard, key: &CacheKey, per_shard_cap: usize) {
    if shard.len() < per_shard_cap || shard.contains_key(key) {
        return;
    }
    let victim = shard
        .iter()
        .take(EVICT_SAMPLE)
        .min_by_key(|(_, e)| e.expires)
        .map(|(k, _)| k.clone());
    if let Some(victim) = victim {
        shard.remove(&victim);
    }
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

    fn shard(&self, key: &dyn KeyView) -> &Mutex<Shard> {
        let idx = (key.full_hash() as usize) & self.shard_mask;
        &self.shards[idx]
    }

    /// Return the cached message and its remaining TTL (seconds, floored at 1)
    /// if present and unexpired. Takes an owned [`CacheKey`] or a borrowed
    /// [`KeyRef`] alike.
    pub fn get(&self, key: &dyn KeyView) -> Option<(Arc<CachedMsg>, u32)> {
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
            // Expired, but still remembering how often this name came back
            // negative: keep it for the escalation, never serve it.
            Some(entry) if entry.strikes > 0 && entry.expires + NEG_GRACE > now => None,
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
        let mut shard = self.shard(&key).lock().unwrap();
        make_room(&mut shard, &key, self.per_shard_cap);
        shard.insert(
            key,
            Entry {
                msg,
                expires: Instant::now() + Duration::from_secs(ttl as u64),
                strikes: 0,
            },
        );
    }

    /// Store a negative answer (NXDOMAIN or NODATA) under the escalating
    /// policy, returning the TTL it was cached for.
    ///
    /// The first one lives [`NEG_TTL_FLOOR`]; each further answer that
    /// confirms it, while the name is still remembered, doubles that, up to
    /// `cap` — the RFC 2308 §5 ceiling of the SOA (the smaller of its record
    /// TTL and its MINIMUM field). So a name that genuinely does not exist is
    /// asked about a handful of times and then left alone, while one that is
    /// only *reported* absent gets rechecked within the minute.
    ///
    /// `confirmed` is false for an answer no second opinion backs — the main
    /// DNS said "no" and the fallback was unreachable. Those pin the floor and
    /// never escalate, so an upstream outage cannot make a negative stick.
    pub fn store_negative(
        &self,
        key: CacheKey,
        msg: Arc<CachedMsg>,
        cap: u32,
        confirmed: bool,
    ) -> u32 {
        let now = Instant::now();
        let mut shard = self.shard(&key).lock().unwrap();
        // A remembered entry (expired but inside its grace window) counts: the
        // name is still being asked for and still coming back negative.
        let seen = shard.get(&key).map_or(0, |e| e.strikes);
        let ttl = if confirmed {
            NEG_TTL_FLOOR.saturating_mul(1u32 << seen.min(NEG_MAX_STRIKES))
        } else {
            NEG_TTL_FLOOR
        }
        .min(cap)
        .clamp(1, MAX_TTL_SECS);
        let strikes = if confirmed {
            seen.saturating_add(1).min(NEG_MAX_STRIKES)
        } else {
            seen
        };
        make_room(&mut shard, &key, self.per_shard_cap);
        shard.insert(
            key,
            Entry {
                msg,
                expires: now + Duration::from_secs(ttl as u64),
                strikes,
            },
        );
        ttl
    }

    /// Drop every entry (used when the hook marks the main DNS down).
    pub fn flush(&self) {
        for shard in self.shards.iter() {
            shard.lock().unwrap().clear();
        }
    }

    /// Sweep expired entries; called periodically by the janitor. A negative
    /// entry inside its grace window stays: it is not served (see [`get`]),
    /// it only carries the strike count forward.
    ///
    /// [`get`]: Cache::get
    pub fn sweep(&self) {
        let now = Instant::now();
        for shard in self.shards.iter() {
            shard
                .lock()
                .unwrap()
                .retain(|_, e| e.expires > now || (e.strikes > 0 && e.expires + NEG_GRACE > now));
        }
    }

    /// Entries that would actually be served. Remembered negatives are not
    /// counted: nothing can read them.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap()
                    .values()
                    .filter(|e| e.expires > now)
                    .count()
            })
            .sum()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pretend an entry was stored `by` earlier, so a test can reach the far
    /// side of an expiry or of the grace window without waiting.
    #[cfg(test)]
    pub fn age_entry(&self, key: &dyn KeyView, by: Duration) {
        let mut shard = self.shard(key).lock().unwrap();
        if let Some(entry) = shard.get_mut(key) {
            entry.expires -= by;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_stays_small() {
        // Every byte here is multiplied by the entry ceiling (~100k on a
        // machine with memory to spare), so a new field is a memory decision,
        // not a detail.
        let size = std::mem::size_of::<Entry>();
        assert!(size <= 32, "a cache entry grew to {size} bytes");
    }

    fn negative_msg() -> Arc<CachedMsg> {
        Arc::new(CachedMsg {
            rcode: Rcode::NXDOMAIN,
            answers: vec![],
            authority: vec![],
            additional: vec![],
        })
    }

    fn neg_key(name: &str) -> CacheKey {
        CacheKey::new(name.as_bytes().to_vec(), 1, 1)
    }

    #[test]
    fn a_negative_answer_caches_longer_each_time_it_is_confirmed() {
        let c = Cache::new(1024);
        let key = neg_key("gone.example");
        // Day-long ceiling: the SOA is not what limits this one.
        let ttls: Vec<u32> = (0..6)
            .map(|_| {
                let ttl = c.store_negative(key.clone(), negative_msg(), 86_400, true);
                // Each round is the same name coming back negative again.
                c.age_entry(&key, Duration::from_secs(u64::from(ttl)));
                ttl
            })
            .collect();
        assert_eq!(
            ttls,
            vec![
                NEG_TTL_FLOOR,
                NEG_TTL_FLOOR * 2,
                NEG_TTL_FLOOR * 4,
                NEG_TTL_FLOOR * 8,
                NEG_TTL_FLOOR * 16,
                NEG_TTL_FLOOR * 32
            ],
            "a name that keeps coming back negative must be asked about less often"
        );
    }

    #[test]
    fn the_soa_ceiling_caps_the_escalation() {
        let c = Cache::new(1024);
        let key = neg_key("short.example");
        // RFC 2308 §5 ceiling below the floor, and one just above it.
        assert_eq!(c.store_negative(key.clone(), negative_msg(), 30, true), 30);
        c.age_entry(&key, Duration::from_secs(30));
        assert_eq!(c.store_negative(key.clone(), negative_msg(), 30, true), 30);

        let key = neg_key("capped.example");
        let mut seen = Vec::new();
        for _ in 0..4 {
            let ttl = c.store_negative(key.clone(), negative_msg(), 100, true);
            c.age_entry(&key, Duration::from_secs(u64::from(ttl)));
            seen.push(ttl);
        }
        assert_eq!(seen, vec![NEG_TTL_FLOOR, 100, 100, 100]);
    }

    #[test]
    fn an_unconfirmed_negative_stays_on_the_floor() {
        let c = Cache::new(1024);
        let key = neg_key("unsure.example");
        for _ in 0..4 {
            let ttl = c.store_negative(key.clone(), negative_msg(), 86_400, false);
            assert_eq!(ttl, NEG_TTL_FLOOR, "an unconfirmed negative must not grow");
            c.age_entry(&key, Duration::from_secs(u64::from(ttl)));
        }
        // And it did not bank any confirmations either: the first real one
        // still starts from the floor.
        assert_eq!(
            c.store_negative(key.clone(), negative_msg(), 86_400, true),
            NEG_TTL_FLOOR
        );
    }

    #[test]
    fn a_remembered_negative_is_never_served_and_is_forgotten_in_the_end() {
        let c = Cache::new(1024);
        let key = neg_key("expired.example");
        let ttl = c.store_negative(key.clone(), negative_msg(), 86_400, true);
        assert!(c.get(&key).is_some(), "live while it lasts");

        c.age_entry(&key, Duration::from_secs(u64::from(ttl) + 1));
        assert!(c.get(&key).is_none(), "expired entries are never served");
        c.sweep();
        assert!(c.get(&key).is_none(), "and the sweep does not resurrect it");
        assert_eq!(c.len(), 0, "nor does it count as a live entry");
        // The strike count survived, so the next one is the second rung.
        assert_eq!(
            c.store_negative(key.clone(), negative_msg(), 86_400, true),
            NEG_TTL_FLOOR * 2
        );

        // Past the grace window it is forgotten and starts over.
        c.age_entry(
            &key,
            Duration::from_secs(u64::from(NEG_TTL_FLOOR * 2) + 301),
        );
        c.sweep();
        assert_eq!(
            c.store_negative(key.clone(), negative_msg(), 86_400, true),
            NEG_TTL_FLOOR,
            "a name nobody asked about for a while is not still on probation"
        );
    }

    #[test]
    fn an_expired_positive_entry_is_swept_as_before() {
        let c = Cache::new(1024);
        let key = neg_key("positive.example");
        c.store(key.clone(), negative_msg(), 10);
        c.age_entry(&key, Duration::from_secs(11));
        c.sweep();
        // Only negatives are remembered past expiry; this one is simply gone.
        assert_eq!(c.len(), 0);
        assert_eq!(
            c.store_negative(key.clone(), negative_msg(), 86_400, true),
            NEG_TTL_FLOOR
        );
    }

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

    /// A borrowed key must land in the same shard and bucket as the owned key
    /// it stands for, and must match nothing else.
    #[test]
    fn borrowed_key_finds_what_the_owned_key_stored() {
        let c = Cache::new(4096);
        let names: [&[u8]; 3] = [
            b"\x07example\x03com\x00",
            b"\x03www\x07example\x03com\x00",
            b"\x00",
        ];
        for (i, name) in names.iter().enumerate() {
            for qtype in [1u16, 28] {
                let owned = CacheKey::new(name.to_vec(), qtype, 1);
                let borrowed = KeyRef::new(name, qtype, 1, hash(name));
                assert_eq!(
                    borrowed.full_hash(),
                    owned.key_hash(),
                    "name {i} type {qtype}"
                );
                c.store(owned, msg(), 300);
            }
        }
        for name in names {
            for qtype in [1u16, 28] {
                assert!(c.get(&KeyRef::new(name, qtype, 1, hash(name))).is_some());
            }
            // Same name, other type or class: a different entry.
            assert!(c.get(&KeyRef::new(name, 16, 1, hash(name))).is_none());
            assert!(c.get(&KeyRef::new(name, 1, 3, hash(name))).is_none());
        }
        // Keys are byte-exact: lower-casing is the caller's job.
        let upper: &[u8] = b"\x07EXAMPLE\x03com\x00";
        assert!(c.get(&KeyRef::new(upper, 1, 1, hash(upper))).is_none());
    }

    /// `Borrow` requires the borrowed form to compare exactly as the owned
    /// keys do. A lookup only compares keys whose hashes already agree, so this
    /// is checked on the comparison itself, not through a lookup.
    #[test]
    fn borrowed_key_equality_matches_owned_key_equality() {
        let names: [&[u8]; 3] = [b"\x01a\x00", b"\x01b\x00", b"\x02ab\x00"];
        let mut keys = Vec::new();
        for name in names {
            for qtype in [1u16, 28] {
                for qclass in [1u16, 3] {
                    keys.push((name, qtype, qclass));
                }
            }
        }
        for &(n1, t1, c1) in &keys {
            for &(n2, t2, c2) in &keys {
                let owned_eq =
                    CacheKey::new(n1.to_vec(), t1, c1) == CacheKey::new(n2.to_vec(), t2, c2);
                let owned = CacheKey::new(n1.to_vec(), t1, c1);
                let borrowed = KeyRef::new(n2, t2, c2, hash(n2));
                let view_eq = (&owned as &dyn KeyView) == (&borrowed as &dyn KeyView);
                assert_eq!(view_eq, owned_eq, "{n1:?}/{t1}/{c1} vs {n2:?}/{t2}/{c2}");
            }
        }
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
