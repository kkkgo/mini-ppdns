// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Sharded TTL cache. Keyed by the lower-cased
//! wire name + qtype + qclass, values are `Arc<CachedMsg>` (owned records +
//! rcode). Sharding by the per-process keyed name hash keeps lock contention
//! low under load.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use domain::base::iana::Rcode;
use domain::base::rdata::ComposeRecordData;
use hashbrown::HashTable;

use crate::dns::OwnedRecord;
use crate::util::{hash, hash_extend};

/// How many entries to sample when choosing a cap-eviction victim.
const EVICT_SAMPLE: usize = 8;

/// Heap bytes per entry that a cache's entry ceiling is sized from (see
/// `sysinfo::calculate_cache_size`). The byte budget is the entry ceiling
/// times this, so ordinary answers — a few hundred bytes each — run into the
/// entry ceiling first and the budget only binds when answers are large.
pub const ENTRY_BYTES: usize = 2048;

/// Largest single answer the cache keeps. Anything bigger is forwarded every
/// time instead: TCP answers run to 64 KiB, and a client asking for name after
/// name of those would otherwise fill the whole budget with a few dozen
/// entries, displacing everything ordinary clients rely on.
const MAX_ENTRY_BYTES: usize = 16 * 1024;

/// Cap on a stored entry's lifetime, whatever TTL the upstream claims: a
/// broken/hostile upstream can advertise ~136 years, which would pin the entry
/// until restart. A day matches common resolver practice (Unbound caps at a
/// day, BIND at a week).
const MAX_TTL_SECS: u32 = 86_400;

/// One shard: a hash table of its entries, stored inline.
///
/// Eviction samples the table's buckets directly: a random bucket that turns
/// out occupied is a uniformly random entry, since every occupied bucket
/// holds exactly one. Sampling through iteration order instead starts from
/// the same buckets every time, so the entries hashed there are evicted over
/// and over while those hashed further along are never looked at.
///
/// The table indexes on [`CacheKey::key_hash`], which is the keyed
/// `util::hash` — sound only because that is seeded per process: which bucket
/// a key lands in must not be attacker-predictable.
#[derive(Default)]
struct Shard {
    table: HashTable<Slot>,
    /// Sum of the `cost` of every entry in `table`. Every path that adds or
    /// removes a slot goes through a `Shard` method that keeps this in step.
    bytes: usize,
}

struct Slot {
    key: CacheKey,
    entry: Entry,
}

/// What one shard may hold.
#[derive(Clone, Copy)]
struct Limits {
    entries: usize,
    bytes: usize,
}

/// Slots a store pushed out of a shard, dropped by the caller once the shard
/// lock is released. Almost always none or one, which needs no allocation.
#[derive(Default)]
struct Displaced {
    first: Option<Slot>,
    rest: Vec<Slot>,
}

impl Displaced {
    fn push(&mut self, slot: Slot) {
        if self.first.is_none() {
            self.first = Some(slot);
        } else {
            self.rest.push(slot);
        }
    }

    #[cfg(test)]
    fn into_vec(self) -> Vec<Slot> {
        self.first.into_iter().chain(self.rest).collect()
    }
}

/// Approximate heap footprint of caching `msg` under a name of `name_len`
/// bytes: the slot, the key's name, the shared message and every record's
/// fixed part, owner and rdata. Deterministic, since the same figure is
/// added when an entry goes in and subtracted when it comes out.
fn entry_cost(name_len: usize, msg: &CachedMsg) -> usize {
    let records = msg
        .answers
        .iter()
        .chain(&msg.authority)
        .chain(&msg.additional)
        .map(|r| {
            std::mem::size_of::<OwnedRecord>()
                + r.owner().as_slice().len()
                + usize::from(r.data().rdlen(false).unwrap_or(u16::MAX))
        })
        .sum::<usize>();
    // Two counters precede the message in its `Arc` allocation.
    std::mem::size_of::<Slot>()
        + name_len
        + 2 * std::mem::size_of::<usize>()
        + std::mem::size_of::<CachedMsg>()
        + records
}

/// Bucket draws an eviction may spend gathering its sample. A shard is only
/// asked to evict at its cap, where at least 7/16 of the buckets are full, so
/// this all but never runs out; when it does, the first full bucket stands in.
const EVICT_DRAWS: usize = EVICT_SAMPLE * 8;

/// Whether `k` is the key `view` describes: everything `Eq` on [`KeyView`]
/// compares, which the lookups below rely on.
fn same_key(k: &CacheKey, view: &dyn KeyView) -> bool {
    (k as &dyn KeyView) == view
}

/// Test access to one entry, panicking when the key is absent.
#[cfg(test)]
impl std::ops::Index<&CacheKey> for Shard {
    type Output = Entry;
    fn index(&self, key: &CacheKey) -> &Entry {
        self.get(key).expect("no entry under this key")
    }
}

impl Shard {
    #[cfg(test)]
    fn len(&self) -> usize {
        self.table.len()
    }

    fn get(&self, key: &dyn KeyView) -> Option<&Entry> {
        self.table
            .find(key.full_hash(), |s| same_key(&s.key, key))
            .map(|s| &s.entry)
    }

    #[cfg(test)]
    fn get_mut(&mut self, key: &dyn KeyView) -> Option<&mut Entry> {
        self.table
            .find_mut(key.full_hash(), |s| same_key(&s.key, key))
            .map(|s| &mut s.entry)
    }

    /// Take `slot` out of the byte count; every removal ends here.
    fn release(&mut self, slot: Slot) -> Slot {
        self.bytes -= slot.entry.cost as usize;
        slot
    }

    /// Remove the entry under `key`, if any.
    fn remove(&mut self, key: &dyn KeyView) -> Option<Slot> {
        let slot = self
            .table
            .find_entry(key.full_hash(), |s| same_key(&s.key, key))
            .ok()?
            .remove()
            .0;
        Some(self.release(slot))
    }

    /// Store `entry` under `key`, first evicting until it fits `limits`:
    /// below the entry ceiling, and within the byte budget with it added.
    /// What was displaced — the slot it replaced and any evicted for it — is
    /// added to `out` for the caller to drop after releasing the lock.
    ///
    /// The entry must fit the budget on its own (the cache checks this), so
    /// emptying the shard always makes room.
    fn put(&mut self, key: CacheKey, entry: Entry, limits: Limits, out: &mut Displaced) {
        let hash = key.key_hash();
        // The replaced entry leaves first, so making room below never evicts
        // the one being stored.
        if let Some(old) = self.remove(&key) {
            out.push(old);
        }
        let cost = entry.cost as usize;
        while self.table.len() >= limits.entries || self.bytes + cost > limits.bytes {
            match self.evict() {
                Some(gone) => out.push(gone),
                None => break,
            }
        }
        self.bytes += cost;
        self.table
            .insert_unique(hash, Slot { key, entry }, |s| s.key.key_hash());
    }

    /// Evict one entry: the soonest-expiring of a few sampled uniformly at
    /// random. A cheap O(EVICT_SAMPLE) approximation of TTL-ordered eviction
    /// that favors near-dead entries (a remembered negative expired long ago,
    /// so it goes first) over long-lived ones, without the O(n) scan — or a
    /// per-shard heap — that exact "evict soonest" would need.
    fn evict(&mut self) -> Option<Slot> {
        let buckets = self.table.num_buckets();
        if buckets == 0 {
            return None;
        }
        let mut victim: Option<(usize, Instant)> = None;
        let mut sampled = 0;
        for _ in 0..EVICT_DRAWS {
            let b = crate::rng::below(buckets);
            let Some(slot) = self.table.get_bucket(b) else {
                continue;
            };
            if victim.is_none_or(|(_, soonest)| slot.entry.expires < soonest) {
                victim = Some((b, slot.entry.expires));
            }
            sampled += 1;
            if sampled == EVICT_SAMPLE {
                break;
            }
        }
        let b = match victim {
            Some((b, _)) => b,
            None => (0..buckets).find(|&b| self.table.get_bucket(b).is_some())?,
        };
        let slot = self.table.get_bucket_entry(b).ok()?.remove().0;
        Some(self.release(slot))
    }

    /// Remove every entry `keep` rejects, handing them back to be dropped
    /// outside the lock.
    fn drain_unwanted(&mut self, keep: impl Fn(&Entry) -> bool, out: &mut Vec<Slot>) {
        let start = out.len();
        out.extend(self.table.extract_if(|s| !keep(&s.entry)));
        self.bytes -= out[start..]
            .iter()
            .map(|s| s.entry.cost as usize)
            .sum::<usize>();
    }
}

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
/// re-reading the name. Selects the shard *and* is what the shard's index
/// table files the entry under (see [`Shard`]). Equality still compares the
/// full key, so distinct names that happen to collide stay distinct entries.
fn key_hash(name_hash: u64, qtype: u16, qclass: u16) -> u64 {
    hash_extend(name_hash, (u64::from(qtype) << 16) | u64::from(qclass))
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

/// What a shard lookup reads from a key. The shards store owned
/// [`CacheKey`]s and are searched through this view, so a borrowed [`KeyRef`]
/// finds the same entry the owned key would.
///
/// For that to hold, both implementations must agree on everything the lookup
/// sees: the full hash, the name bytes, and the type and class.
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
    /// When the records were received: what each record's own TTL counts
    /// down from (see [`Hit::age`]).
    pub stored: Instant,
}

impl CachedMsg {
    /// A message whose records were received just now.
    pub fn new(
        rcode: Rcode,
        answers: Vec<OwnedRecord>,
        authority: Vec<OwnedRecord>,
        additional: Vec<OwnedRecord>,
    ) -> Self {
        CachedMsg {
            rcode,
            answers,
            authority,
            additional,
            stored: Instant::now(),
        }
    }
}

/// A live cache entry, as a lookup returns it.
pub struct Hit {
    pub msg: Arc<CachedMsg>,
    /// Seconds the entry has left, floored at 1.
    pub ttl_left: u32,
    /// Whole seconds since the records were received. The entry's lifetime
    /// is the shortest answer TTL, not every record's: a record outside the
    /// answer section can run out sooner.
    pub age: u32,
}

struct Entry {
    msg: Arc<CachedMsg>,
    expires: Instant,
    /// [`entry_cost`] of this entry, as counted in [`Shard::bytes`].
    cost: u32,
    /// How many times a negative answer for this key has been confirmed; 0 for
    /// positive entries. Kept past `expires` for [`NEG_GRACE`] — the entry is
    /// no longer served, it only remembers that this name keeps coming back
    /// negative, which is what makes the next one cache for longer.
    strikes: u8,
    /// Whether this live cache period has already contributed a strike. An
    /// unconfirmed period can still carry strikes from earlier periods.
    confirmed: bool,
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
    /// Byte budget of each shard: its entry ceiling times [`ENTRY_BYTES`].
    per_shard_bytes: usize,
    /// Answers costing more than this are not cached: [`MAX_ENTRY_BYTES`],
    /// or a whole shard's budget when that is smaller.
    max_entry_bytes: usize,
}

impl Cache {
    /// Build a cache with roughly `total_cap` total entries across shards,
    /// and `total_cap` × [`ENTRY_BYTES`] of records.
    pub fn new(total_cap: usize) -> Self {
        const SHARDS: usize = 64; // power of two
        let per_shard_cap = (total_cap / SHARDS).max(1);
        let per_shard_bytes = per_shard_cap.saturating_mul(ENTRY_BYTES);
        let shards = (0..SHARDS)
            .map(|_| Mutex::new(Shard::default()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Cache {
            shards,
            shard_mask: SHARDS - 1,
            per_shard_cap,
            per_shard_bytes,
            max_entry_bytes: MAX_ENTRY_BYTES.min(per_shard_bytes),
        }
    }

    /// The most bytes of records the cache holds, for the startup log.
    pub fn byte_budget(&self) -> usize {
        self.per_shard_bytes.saturating_mul(self.shards.len())
    }

    fn limits(&self) -> Limits {
        Limits {
            entries: self.per_shard_cap,
            bytes: self.per_shard_bytes,
        }
    }

    /// What caching `msg` under `key` costs, or `None` when it is too large
    /// to cache at all.
    fn admit(&self, key: &CacheKey, msg: &CachedMsg) -> Option<u32> {
        let cost = entry_cost(key.name.len(), msg);
        (cost <= self.max_entry_bytes).then_some(cost as u32)
    }

    fn shard(&self, key: &dyn KeyView) -> &Mutex<Shard> {
        let idx = (key.full_hash() as usize) & self.shard_mask;
        &self.shards[idx]
    }

    /// Return the cached message and its remaining TTL (seconds, floored at 1)
    /// if present and unexpired. Takes an owned [`CacheKey`] or a borrowed
    /// [`KeyRef`] alike.
    pub fn get(&self, key: &dyn KeyView) -> Option<(Arc<CachedMsg>, u32)> {
        self.hit(key).map(|h| (h.msg, h.ttl_left))
    }

    /// [`get`](Self::get), and how long the records have been held.
    pub fn hit(&self, key: &dyn KeyView) -> Option<Hit> {
        let now = Instant::now();
        let mut shard = self.shard(key).lock().unwrap();
        let entry = shard.get(key)?;
        if entry.expires > now {
            let secs = (entry.expires - now).as_secs();
            let ttl_left = if secs < 1 {
                1
            } else {
                secs.min(u32::MAX as u64) as u32
            };
            let age = now.saturating_duration_since(entry.msg.stored).as_secs();
            return Some(Hit {
                msg: entry.msg.clone(),
                ttl_left,
                age: age.min(u64::from(u32::MAX)) as u32,
            });
        }
        // Expired, but still remembering how often this name came back
        // negative: keep it for the escalation, never serve it.
        if entry.strikes > 0 && entry.expires + NEG_GRACE > now {
            return None;
        }
        // Expired: evict in place, and free it once the lock is released. A
        // second probe, so the hit path above stays a plain lookup.
        let dead = shard.remove(key);
        drop(shard);
        drop(dead);
        None
    }

    /// Store `msg` under `key` for `ttl_secs`, clamped to `[1, MAX_TTL_SECS]`:
    /// a zero TTL is treated as 1s so an immediately-retried query still hits
    /// the cache, and an oversized TTL must not pin the entry (see
    /// `MAX_TTL_SECS`). An answer too large to cache (see
    /// [`MAX_ENTRY_BYTES`]) is not stored.
    pub fn store(&self, key: CacheKey, msg: Arc<CachedMsg>, ttl_secs: u32) {
        let Some(cost) = self.admit(&key, &msg) else {
            return;
        };
        let ttl = ttl_secs.clamp(1, MAX_TTL_SECS);
        let entry = Entry {
            msg,
            expires: Instant::now() + Duration::from_secs(ttl as u64),
            cost,
            strikes: 0,
            confirmed: false,
        };
        let mut displaced = Displaced::default();
        let mut shard = self.shard(&key).lock().unwrap();
        shard.put(key, entry, self.limits(), &mut displaced);
        drop(shard);
        drop(displaced);
    }

    /// Store a negative answer (NXDOMAIN or NODATA) under the escalating
    /// policy, returning the TTL it was cached for.
    ///
    /// The first one lives [`NEG_TTL_FLOOR`]; each confirmation after expiry,
    /// while the name is still remembered, doubles that, up to
    /// `cap` — the RFC 2308 §5 ceiling of the SOA (the smaller of its record
    /// TTL and its MINIMUM field). So a name that genuinely does not exist is
    /// asked about a handful of times and then left alone, while one that is
    /// only *reported* absent gets rechecked within the minute.
    ///
    /// `confirmed` is false for an answer no second opinion backs — the main
    /// DNS said "no" and the fallback was unreachable. Those pin the floor and
    /// never escalate, so an upstream outage cannot make a negative stick.
    /// Replies arriving in the same live cache period may shorten its lifetime,
    /// but never extend it or count as another round of confirmation. In that
    /// case the return value is the remaining TTL, as with [`Self::get`].
    ///
    /// An answer too large to cache is not stored, and returns 0.
    pub fn store_negative(
        &self,
        key: CacheKey,
        msg: Arc<CachedMsg>,
        cap: u32,
        confirmed: bool,
    ) -> u32 {
        let Some(cost) = self.admit(&key, &msg) else {
            return 0;
        };
        let mut shard = self.shard(&key).lock().unwrap();
        let now = Instant::now();
        let live_negative = shard.get(&key).is_some_and(|e| {
            e.expires > now
                && (e.msg.rcode == Rcode::NXDOMAIN
                    || (e.msg.rcode == Rcode::NOERROR && e.msg.answers.is_empty()))
        });
        if live_negative {
            // Taken out and stored again, so a larger message makes room
            // through `put` like any other store.
            let Slot { key, mut entry } = shard.remove(&key).expect("found above");
            // Several cold misses can finish together. They all belong to the
            // existing cache period, even if their SOA ceilings differ. Keep
            // the earlier deadline, respecting a newly shorter ceiling or an
            // unconfirmed answer's floor without restarting the clock.
            let ceiling = if confirmed {
                cap
            } else {
                cap.min(NEG_TTL_FLOOR)
            }
            .clamp(1, MAX_TTL_SECS);
            entry.expires = entry
                .expires
                .min(now + Duration::from_secs(u64::from(ceiling)));
            if confirmed && !entry.confirmed {
                entry.strikes = entry.strikes.saturating_add(1).min(NEG_MAX_STRIKES);
                entry.confirmed = true;
            }
            let ttl_left = (entry.expires - now).as_secs().max(1) as u32;
            let old = std::mem::replace(&mut entry.msg, msg);
            entry.cost = cost;
            let mut displaced = Displaced::default();
            shard.put(key, entry, self.limits(), &mut displaced);
            drop(shard);
            drop(old);
            drop(displaced);
            return ttl_left;
        }
        // A remembered entry (expired but inside its grace window) counts: the
        // name is still being asked for and still coming back negative. Check
        // the window here too: a store need not be preceded by get or sweep.
        let seen = shard
            .get(&key)
            .filter(|e| e.expires + NEG_GRACE > now)
            .map_or(0, |e| e.strikes);
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
        let entry = Entry {
            msg,
            expires: now + Duration::from_secs(ttl as u64),
            cost,
            strikes,
            confirmed,
        };
        let mut displaced = Displaced::default();
        shard.put(key, entry, self.limits(), &mut displaced);
        drop(shard);
        drop(displaced);
        ttl
    }

    /// Drop every entry (used when the hook marks the main DNS down).
    pub fn flush(&self) {
        for shard in self.shards.iter() {
            // Freed after the lock is released, like everything else removed.
            let all = std::mem::take(&mut *shard.lock().unwrap());
            drop(all);
        }
    }

    /// Sweep expired entries; called periodically by the janitor. A negative
    /// entry inside its grace window stays: it is not served (see [`get`]),
    /// it only carries the strike count forward.
    ///
    /// Removed entries are freed after each shard's lock is released: a large
    /// batch expiring together must not hold up the lookups queued on it.
    ///
    /// [`get`]: Cache::get
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut dead = Vec::new();
        for shard in self.shards.iter() {
            shard.lock().unwrap().drain_unwanted(
                |e| e.expires > now || (e.strikes > 0 && e.expires + NEG_GRACE > now),
                &mut dead,
            );
            dead.clear();
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
                    .table
                    .iter()
                    .filter(|s| s.entry.expires > now)
                    .count()
            })
            .sum()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pretend an entry was stored `by` earlier, so a test can reach the far
    /// side of an expiry or of the grace window without waiting. The records'
    /// receive time moves back with it.
    #[cfg(test)]
    pub fn age_entry(&self, key: &dyn KeyView, by: Duration) {
        let mut shard = self.shard(key).lock().unwrap();
        if let Some(entry) = shard.get_mut(key) {
            entry.expires -= by;
            let m = &entry.msg;
            entry.msg = Arc::new(CachedMsg {
                rcode: m.rcode,
                answers: m.answers.clone(),
                authority: m.authority.clone(),
                additional: m.additional.clone(),
                stored: m.stored.checked_sub(by).unwrap_or(m.stored),
            });
        }
    }

    /// Bytes held across every shard, checked against the entries they hold.
    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                let s = s.lock().unwrap();
                for slot in s.table.iter() {
                    assert_eq!(
                        slot.entry.cost as usize,
                        entry_cost(slot.key.name.len(), &slot.entry.msg),
                        "an entry's cost is not what it holds"
                    );
                }
                let counted: usize = s.table.iter().map(|e| e.entry.cost as usize).sum();
                assert_eq!(s.bytes, counted, "a shard's byte count drifted");
                assert!(s.bytes <= self.per_shard_bytes, "a shard is over budget");
                s.bytes
            })
            .sum()
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
            stored: std::time::Instant::now(),
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
    fn concurrent_negative_replies_only_confirm_one_cache_period() {
        let cache = Arc::new(Cache::new(1024));
        let key = neg_key("burst.example");
        let barrier = Arc::new(std::sync::Barrier::new(12));
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..12 {
                let cache = cache.clone();
                let key = key.clone();
                let barrier = barrier.clone();
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    cache.store_negative(key, negative_msg(), 86_400, true)
                }));
            }
            for worker in workers {
                assert!(worker.join().unwrap() <= NEG_TTL_FLOOR);
            }
        });
        let (expires, strikes) = {
            let shard = cache.shard(&key).lock().unwrap();
            let entry = shard.get(&key).unwrap();
            (entry.expires, entry.strikes)
        };
        assert_eq!(strikes, 1, "one burst is only one confirmation period");

        // A late reply must not restart that period's clock, either.
        cache.store_negative(key.clone(), negative_msg(), 86_400, true);
        assert_eq!(cache.shard(&key).lock().unwrap()[&key].expires, expires);
        cache.age_entry(&key, Duration::from_secs(u64::from(NEG_TTL_FLOOR)));
        assert_eq!(
            cache.store_negative(key, negative_msg(), 86_400, true),
            NEG_TTL_FLOOR * 2,
            "a new confirmation after expiry still advances the policy"
        );
    }

    #[test]
    fn negative_history_expires_even_without_a_lookup_or_sweep() {
        let cache = Cache::new(1024);
        let key = neg_key("forgotten.example");
        cache.store_negative(key.clone(), negative_msg(), 86_400, true);
        cache.age_entry(
            &key,
            Duration::from_secs(u64::from(NEG_TTL_FLOOR)) + NEG_GRACE + Duration::from_secs(1),
        );
        assert_eq!(
            cache.store_negative(key, negative_msg(), 86_400, true),
            NEG_TTL_FLOOR
        );
    }

    #[test]
    fn live_negative_replies_can_shorten_but_never_extend_the_deadline() {
        let cache = Cache::new(1024);
        let key = neg_key("shortened.example");
        cache.store_negative(key.clone(), negative_msg(), 86_400, true);
        cache.age_entry(&key, Duration::from_secs(u64::from(NEG_TTL_FLOOR)));
        assert_eq!(
            cache.store_negative(key.clone(), negative_msg(), 86_400, true),
            NEG_TTL_FLOOR * 2
        );
        assert!(cache.store_negative(key.clone(), negative_msg(), 86_400, false) <= NEG_TTL_FLOOR);
        assert!(cache.store_negative(key.clone(), negative_msg(), 5, true) <= 5);
        let expires = cache.shard(&key).lock().unwrap()[&key].expires;
        cache.store_negative(key.clone(), negative_msg(), 86_400, true);
        let shard = cache.shard(&key).lock().unwrap();
        assert_eq!(shard[&key].expires, expires);
        assert_eq!(shard[&key].strikes, 2);
    }

    #[test]
    fn confirming_a_live_unconfirmed_negative_counts_once() {
        let cache = Cache::new(1024);
        let key = neg_key("first-confirmation.example");
        cache.store_negative(key.clone(), negative_msg(), 86_400, false);
        let expires = cache.shard(&key).lock().unwrap()[&key].expires;
        for _ in 0..3 {
            assert!(
                cache.store_negative(key.clone(), negative_msg(), 86_400, true) <= NEG_TTL_FLOOR
            );
        }
        let shard = cache.shard(&key).lock().unwrap();
        assert_eq!(shard[&key].expires, expires);
        assert_eq!(shard[&key].strikes, 1);
    }

    #[test]
    fn a_new_period_can_be_confirmed_after_an_unconfirmed_reply() {
        let cache = Cache::new(1024);
        let key = neg_key("late-confirmation.example");
        cache.store_negative(key.clone(), negative_msg(), 86_400, true);
        cache.age_entry(&key, Duration::from_secs(u64::from(NEG_TTL_FLOOR)));
        cache.store_negative(key.clone(), negative_msg(), 86_400, false);
        for _ in 0..3 {
            assert!(
                cache.store_negative(key.clone(), negative_msg(), 86_400, true) <= NEG_TTL_FLOOR
            );
        }
        cache.age_entry(&key, Duration::from_secs(u64::from(NEG_TTL_FLOOR)));
        assert_eq!(
            cache.store_negative(key, negative_msg(), 86_400, true),
            NEG_TTL_FLOOR * 4,
            "each of the two prior periods was confirmed exactly once"
        );
    }

    #[test]
    fn a_positive_answer_resets_history_before_a_nodata_burst() {
        use domain::base::{Name, Ttl};
        use domain::rdata::{AllRecordData, A};
        let cache = Cache::new(1024);
        let key = neg_key("published.example");
        cache.store_negative(key.clone(), negative_msg(), 86_400, true);
        cache.age_entry(&key, Duration::from_secs(u64::from(NEG_TTL_FLOOR)));
        cache.store_negative(key.clone(), negative_msg(), 86_400, true);
        cache.store(
            key.clone(),
            Arc::new(CachedMsg {
                stored: std::time::Instant::now(),
                rcode: Rcode::NOERROR,
                answers: vec![OwnedRecord::new(
                    Name::from_octets(b"\x09published\x07example\x00".to_vec()).unwrap(),
                    domain::base::iana::Class::IN,
                    Ttl::from_secs(10),
                    AllRecordData::A(A::from_octets(1, 2, 3, 4)),
                )],
                authority: vec![],
                additional: vec![],
            }),
            10,
        );
        assert_eq!(cache.shard(&key).lock().unwrap()[&key].strikes, 0);
        let nodata = msg();
        // The live positive answer must not be mistaken for a live negative.
        assert_eq!(
            cache.store_negative(key.clone(), nodata.clone(), 86_400, true),
            NEG_TTL_FLOOR
        );
        let expires = cache.shard(&key).lock().unwrap()[&key].expires;
        for _ in 0..12 {
            assert!(
                cache.store_negative(key.clone(), nodata.clone(), 86_400, true) <= NEG_TTL_FLOOR
            );
        }
        let shard = cache.shard(&key).lock().unwrap();
        assert_eq!(shard[&key].expires, expires);
        assert_eq!(shard[&key].strikes, 1);
        assert!(shard[&key].msg.answers.is_empty());
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
            stored: std::time::Instant::now(),
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
                // And the comparison the shard lookup actually runs.
                assert_eq!(
                    same_key(&owned, &borrowed),
                    owned_eq,
                    "lookup: {n1:?}/{t1}/{c1} vs {n2:?}/{t2}/{c2}"
                );
            }
        }
    }

    fn entry_expiring(at: Instant) -> Entry {
        Entry {
            msg: msg(),
            expires: at,
            cost: 0,
            strikes: 0,
            confirmed: false,
        }
    }

    /// An entry ceiling with no byte budget to speak of.
    fn cap(entries: usize) -> Limits {
        Limits {
            entries,
            bytes: usize::MAX,
        }
    }

    /// `Shard::put`, returning everything it displaced.
    fn put(shard: &mut Shard, key: CacheKey, entry: Entry, limits: Limits) -> Vec<Slot> {
        let mut out = Displaced::default();
        shard.put(key, entry, limits, &mut out);
        out.into_vec()
    }

    /// The shard against a plain map, over random puts (with eviction at the
    /// cap), direct evictions, sweeps and lookups. A slip in what eviction or
    /// the sweep hands back would leave the two populations apart, so every
    /// step is checked.
    #[test]
    fn a_shard_agrees_with_a_reference_map_under_random_operations() {
        use std::collections::HashMap;
        const CAP: usize = 24;
        let base = Instant::now();
        let mut shard = Shard::default();
        // name → expiry offset in seconds, which doubles as the entry's identity.
        // Every key here shares one type and class, so the name identifies it.
        let mut model: HashMap<Vec<u8>, u64> = HashMap::new();
        let key_of = |n: usize| CacheKey::new(format!("k{n}").into_bytes(), 1, 1);
        for step in 0..20_000u64 {
            let k = key_of(crate::rng::below(40));
            match crate::rng::below(10) {
                0..=5 => {
                    let at = 1 + crate::rng::below(1000) as u64;
                    let mut displaced = put(
                        &mut shard,
                        k.clone(),
                        entry_expiring(base + Duration::from_secs(at)),
                        cap(CAP),
                    );
                    assert!(displaced.len() <= 1, "step {step}: one slot out at most");
                    match displaced.pop() {
                        Some(old) if old.key == k => {
                            assert!(
                                model.contains_key(&k.name),
                                "step {step}: replaced a stored key"
                            );
                        }
                        Some(old) => {
                            assert_eq!(model.len(), CAP, "step {step}: evicted below the cap");
                            assert!(
                                !model.contains_key(&k.name),
                                "step {step}: evicted for a new key"
                            );
                            assert_eq!(
                                model.remove(&old.key.name),
                                Some((old.entry.expires - base).as_secs()),
                                "step {step}: evicted an entry that was stored"
                            );
                        }
                        None => assert!(
                            model.len() < CAP || model.contains_key(&k.name),
                            "step {step}: a full shard took a new key without evicting"
                        ),
                    }
                    model.insert(k.name.clone(), at);
                }
                6 => match shard.evict() {
                    Some(gone) => {
                        assert!(model.remove(&gone.key.name).is_some(), "step {step}")
                    }
                    None => assert!(model.is_empty(), "step {step}: nothing evicted"),
                },
                7 => {
                    let cutoff = base + Duration::from_secs(crate::rng::below(1000) as u64);
                    let mut dead = Vec::new();
                    shard.drain_unwanted(|e| e.expires > cutoff, &mut dead);
                    for d in &dead {
                        assert!(d.entry.expires <= cutoff, "step {step}: swept a live entry");
                        assert!(model.remove(&d.key.name).is_some(), "step {step}");
                    }
                    model.retain(|_, at| base + Duration::from_secs(*at) > cutoff);
                }
                _ => {
                    let got = shard.get(&k).map(|e| (e.expires - base).as_secs());
                    assert_eq!(got, model.get(&k.name).copied(), "step {step}: lookup");
                }
            }
            assert!(shard.len() <= CAP, "step {step}: past the cap");
            assert_eq!(shard.len(), model.len(), "step {step}: same population");
            if step % 64 == 0 {
                for (name, at) in &model {
                    let k = CacheKey::new(name.clone(), 1, 1);
                    let e = shard.get(&k).expect("every stored key is found");
                    assert_eq!((e.expires - base).as_secs(), *at, "step {step}");
                }
            }
        }
    }

    /// Of what it samples, eviction takes the entry closest to expiring: in a
    /// full shard half near death and half long-lived, new keys must displace
    /// mostly the near-dead half. Evicting a random entry instead would take
    /// as many long-lived entries as near-dead ones.
    #[test]
    fn eviction_prefers_the_entries_closest_to_expiring() {
        const CAP: usize = 256;
        let now = Instant::now();
        let soon = now + Duration::from_secs(10);
        let late = now + Duration::from_secs(3600);
        let mut shard = Shard::default();
        for i in 0..CAP {
            let at = if i % 2 == 0 { soon } else { late };
            put(
                &mut shard,
                key(&format!("old{i}"), 1),
                entry_expiring(at),
                cap(CAP),
            );
        }
        let mut late_evicted = 0;
        for i in 0..CAP / 2 {
            let gone = put(
                &mut shard,
                key(&format!("new{i}"), 1),
                entry_expiring(late),
                cap(CAP),
            )
            .pop()
            .expect("a full shard evicts");
            if gone.entry.expires == late {
                late_evicted += 1;
            }
        }
        // Sampling 8 of a half-and-half shard finds a near-dead entry 255
        // times in 256 at first; random eviction would take ~64 long-lived.
        assert!(
            late_evicted < CAP / 8,
            "{late_evicted} of {} evictions took a long-lived entry",
            CAP / 2
        );
    }

    /// A lookup that finds its entry expired removes it on the spot — the
    /// janitor's sweep is a backstop, not the only way dead entries go.
    #[test]
    fn a_lookup_drops_the_expired_entry_it_finds() {
        let c = Cache::new(1024);
        let k = key("stale.example", 1);
        c.store(k.clone(), msg(), 5);
        c.age_entry(&k, Duration::from_secs(6));
        assert!(c.get(&k).is_none(), "an expired entry is never served");
        assert_eq!(c.shard(&k).lock().unwrap().len(), 0, "and it is gone");
    }

    /// No entry is out of eviction's reach. With every expiry equal, the
    /// victim is whichever entry the sample hit first, so a full shard that
    /// keeps taking new keys must, before long, have evicted every one of its
    /// original entries — wherever in the table they hashed.
    #[test]
    fn eviction_reaches_every_entry_of_a_full_shard() {
        const CAP: usize = 64;
        let at = Instant::now() + Duration::from_secs(300);
        let mut shard = Shard::default();
        for i in 0..CAP {
            put(
                &mut shard,
                key(&format!("orig{i}"), 1),
                entry_expiring(at),
                cap(CAP),
            );
        }
        // Each put evicts a uniformly drawn entry: an original survives all
        // of these with probability (63/64)^1024, about 1e-7.
        for i in 0..CAP * 16 {
            assert_eq!(
                put(
                    &mut shard,
                    key(&format!("new{i}"), 1),
                    entry_expiring(at),
                    cap(CAP)
                )
                .len(),
                1,
                "a full shard evicts for every new key"
            );
        }
        let survivors: Vec<usize> = (0..CAP)
            .filter(|i| shard.get(&key(&format!("orig{i}"), 1)).is_some())
            .collect();
        assert!(
            survivors.is_empty(),
            "entries eviction never reached: {survivors:?}"
        );
    }

    /// When the popular names change, the new ones must displace the old ones
    /// wherever they hash. Eviction that always samples the same region of a
    /// shard keeps evicting the new names that land there and never reaches
    /// the stale ones elsewhere, so the new hot set never fits.
    #[test]
    fn a_new_hot_set_displaces_the_old_one() {
        const PER_SHARD: usize = 256;
        const KEYS: usize = 64 * PER_SHARD;
        let c = Cache::new(KEYS);
        assert_eq!(c.per_shard_cap, PER_SHARD);
        let old: Vec<CacheKey> = (0..KEYS).map(|i| key(&format!("old{i}"), 1)).collect();
        let hot: Vec<CacheKey> = (0..KEYS).map(|i| key(&format!("hot{i}"), 1)).collect();
        for k in &old {
            c.store(k.clone(), msg(), 300);
        }
        let mut order: Vec<usize> = (0..KEYS).collect();
        let mut hits = 0;
        for _round in 0..8 {
            crate::rng::shuffle(&mut order);
            hits = 0;
            for &i in &order {
                if c.get(&hot[i]).is_some() {
                    hits += 1;
                } else {
                    c.store(hot[i].clone(), msg(), 300);
                }
            }
        }
        let stale = old.iter().filter(|k| c.get(*k).is_some()).count();
        let hit_rate = hits as f64 / KEYS as f64;
        assert!(
            hit_rate > 0.85,
            "after 8 rounds only {:.1}% of the hot set hits",
            hit_rate * 100.0
        );
        assert!(
            stale < KEYS / 10,
            "{stale} of {KEYS} stale entries survived 8 rounds of a new hot set"
        );
    }

    /// A message holding one TXT record of about `len` bytes.
    fn txt_msg(len: usize) -> Arc<CachedMsg> {
        use domain::base::{Name, Ttl};
        use std::str::FromStr;
        let txt = domain::rdata::Txt::build_from_slice(&vec![b'x'; len]).unwrap();
        Arc::new(CachedMsg::new(
            Rcode::NOERROR,
            vec![OwnedRecord::new(
                Name::<Vec<u8>>::from_str("big.example.").unwrap(),
                domain::base::iana::Class::IN,
                Ttl::from_secs(300),
                domain::rdata::AllRecordData::Txt(txt),
            )],
            Vec::new(),
            Vec::new(),
        ))
    }

    /// Ordinary answers must run into the entry ceiling long before the byte
    /// budget: the budget is there for large answers, not to shrink the cache
    /// for everyone else.
    #[test]
    fn an_ordinary_answer_costs_well_under_the_per_entry_figure() {
        use domain::base::{Name, Ttl};
        use std::str::FromStr;
        let a = |ip: u8| {
            OwnedRecord::new(
                Name::<Vec<u8>>::from_str("www.example.com.").unwrap(),
                domain::base::iana::Class::IN,
                Ttl::from_secs(300),
                domain::rdata::AllRecordData::A(domain::rdata::A::from_octets(10, 0, 0, ip)),
            )
        };
        let msg = CachedMsg::new(Rcode::NOERROR, (1..=4).map(a).collect(), vec![], vec![]);
        let cost = entry_cost(17, &msg);
        assert!(
            cost < ENTRY_BYTES / 2,
            "four A records cost {cost} bytes against a per-entry figure of {ENTRY_BYTES}"
        );
    }

    /// An answer past the per-entry ceiling is forwarded, not cached: a few
    /// dozen 60 KiB TXT answers would otherwise hold more than the whole cache
    /// was sized for.
    #[test]
    fn an_answer_too_large_to_cache_is_not_stored() {
        let c = Cache::new(102_400);
        c.store(key("huge", 16), txt_msg(MAX_ENTRY_BYTES + 1), 300);
        assert!(
            c.get(&key("huge", 16)).is_none(),
            "a huge answer was cached"
        );
        assert_eq!(
            c.store_negative(key("huge-neg", 16), txt_msg(MAX_ENTRY_BYTES + 1), 300, true),
            0
        );
        assert!(c.get(&key("huge-neg", 16)).is_none());
        // Just under the ceiling is still cached.
        c.store(key("big", 16), txt_msg(MAX_ENTRY_BYTES / 2), 300);
        assert!(c.get(&key("big", 16)).is_some());
        assert_eq!(c.bytes(), entry_cost(3, &txt_msg(MAX_ENTRY_BYTES / 2)));
    }

    /// The cache holds no more record bytes than its entry ceiling was sized
    /// for, however large each answer is: an entry count alone lets large
    /// answers hold many times the memory the ceiling assumed.
    #[test]
    fn large_answers_are_held_to_the_byte_budget() {
        const RDATA: usize = 10_000;
        let c = Cache::new(1024);
        for i in 0..4000 {
            c.store(key(&format!("big{i}"), 16), txt_msg(RDATA), 300);
        }
        let held = c.len();
        assert!(
            held * RDATA <= c.byte_budget(),
            "{held} answers of {RDATA} bytes held against a {} byte budget",
            c.byte_budget()
        );
        assert!(c.bytes() <= c.byte_budget());
        // Every shard still holds what fits: the budget is a cap, not a purge.
        assert!(held >= 64, "only {held} answers left");
    }

    /// Byte accounting stays exact through every way an entry leaves —
    /// replacement, eviction, sweep, lookup of an expired entry, a negative
    /// refreshed in place, and flush — and no shard ever ends a store over
    /// its budget.
    #[test]
    fn byte_accounting_follows_every_way_an_entry_comes_and_goes() {
        let c = Cache::new(64 * 8);
        for step in 0..6000u32 {
            let k = key(&format!("k{}", crate::rng::below(300)), 1);
            let size = [0usize, 100, 1500, 4000][crate::rng::below(4)];
            match crate::rng::below(8) {
                0..=3 => c.store(k, txt_msg(size), 1 + crate::rng::below(600) as u32),
                4 => {
                    let neg = Arc::new(CachedMsg::new(
                        Rcode::NXDOMAIN,
                        vec![],
                        txt_msg(size).answers.clone(),
                        vec![],
                    ));
                    c.store_negative(k, neg, 300, crate::rng::below(2) == 0);
                }
                5 => c.age_entry(&k, Duration::from_secs(crate::rng::below(700) as u64)),
                6 => {
                    let _ = c.get(&k);
                }
                _ => c.sweep(),
            }
            if step % 50 == 0 {
                c.bytes();
            }
        }
        c.bytes();
        c.flush();
        assert_eq!(c.bytes(), 0);
    }

    /// A hit says how long its records have been held, which is what the
    /// records outside the answer section count down by.
    #[test]
    fn a_hit_reports_the_age_of_its_records() {
        let c = Cache::new(1024);
        let k = key("aged", 1);
        c.store(k.clone(), msg(), 300);
        let fresh = c.hit(&k).expect("hit");
        assert_eq!(fresh.age, 0);
        assert!(fresh.ttl_left >= 299);
        c.age_entry(&k, Duration::from_secs(40));
        let old = c.hit(&k).expect("hit");
        assert_eq!(old.age, 40);
        assert!((259..=260).contains(&old.ttl_left), "ttl {}", old.ttl_left);
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
