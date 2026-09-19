// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! The request-processing pipeline.
//!
//! Order: static rewrites → route decision → cache → main DNS → fallback.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use domain::base::iana::{Class, Opcode, Rcode, Rtype};
use domain::base::CharStr;
use domain::base::{Message, Ttl};
use domain::rdata::{Aaaa, AllRecordData, Hinfo, Ptr, A};

use crate::cache::{Cache, CacheKey, CachedMsg, KeyRef};
use crate::dns::{
    self, ClientEdns, OwnedName, OwnedQueryInfo, OwnedRecord, QueryInfo, QueryScratch, ResponseData,
};
use crate::forcefall::ForceFallMatcher;
use crate::local_resolver::{hostname_to_name, is_private_ptr_name, PtrResolver};
use crate::log;
use crate::pplog::{
    dur_to_ms, RCODE_NODATA, RCODE_TIMEOUT, ROUTE_CACHE, ROUTE_FALL, ROUTE_FORCE_FALL,
    ROUTE_HOOK_FALL, ROUTE_HOSTS, ROUTE_LOCAL,
};
use crate::upstream::Forwarder;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AaaaMode {
    No,
    Yes,
    NoError,
}

impl AaaaMode {
    pub fn parse(s: &str) -> Self {
        match s {
            "yes" => AaaaMode::Yes,
            "noerror" => AaaaMode::NoError,
            _ => AaaaMode::No,
        }
    }
}

pub struct Handler {
    /// Behind an `Arc` because a hedged main query keeps running after the
    /// client already has the fallback's answer (see `query_main_hedged`).
    pub main: Arc<Forwarder>,
    pub fallback: Forwarder,
    /// How long the main DNS gets on its own before the fallback is started
    /// alongside it. The main query is *not* cancelled at this point — it can
    /// still win the race, which is the whole point: its answer is the one the
    /// client asked for.
    pub hedge_after: Duration,
    /// Answers that came from the main DNS. Read by main-preferring clients.
    pub cache: Arc<Cache>,
    /// Answers that came from the fallback DNS. Read by force_fall clients and,
    /// while the hook says the main DNS is down, by everyone. The two caches
    /// are partitioned by *which upstream produced the answer*, never by which
    /// client asked — that is what makes sharing this one safe: every entry in
    /// it is a faithful fallback-upstream answer, which is exactly what both
    /// kinds of reader are supposed to get.
    pub fall_cache: Arc<Cache>,
    pub force_fall: ForceFallMatcher,
    pub aaaa_mode: AaaaMode,
    pub lite: bool,
    pub boguspriv: bool,
    pub block_svcb: bool,
    pub trust_rcodes: HashSet<u8>,
    pub resolver: Option<Arc<PtrResolver>>,
    pub hook_failed: Option<Arc<std::sync::atomic::AtomicBool>>,
    pub pplog: Option<Arc<crate::pplog::Reporter>>,
}

/// The sectioned, owned records of an upstream response.
struct Parts {
    rcode: Rcode,
    answers: Vec<OwnedRecord>,
    authority: Vec<OwnedRecord>,
    additional: Vec<OwnedRecord>,
}

/// Label reported for a fallback stage that was answered out of the fallback
/// cache instead of the network.
const FALL_CACHE_LABEL: &str = "cache-fall";

impl Parts {
    /// Re-own a cached message so it can go through the same NODATA-preference
    /// and lite handling as a freshly fetched one. Costs a clone of the record
    /// set, which is small next to the upstream round trip it saves.
    fn from_cached(c: &CachedMsg) -> Self {
        Parts {
            rcode: c.rcode,
            answers: c.answers.clone(),
            authority: c.authority.clone(),
            additional: c.additional.clone(),
        }
    }

    fn from_msg(msg: &Message<Vec<u8>>) -> Self {
        Parts {
            rcode: msg.header().rcode(),
            answers: dns::answers_owned(msg),
            authority: dns::authority_owned(msg),
            additional: dns::additional_owned(msg),
        }
    }

    fn is_nodata(&self) -> bool {
        self.rcode == Rcode::NOERROR && self.answers.is_empty()
    }
    /// A definite "no": NXDOMAIN, or NOERROR with nothing in the answer
    /// section. These are the answers the negative-cache policy governs.
    fn is_negative(&self) -> bool {
        self.answers.is_empty() && matches!(self.rcode, Rcode::NOERROR | Rcode::NXDOMAIN)
    }

    fn min_ttl(&self) -> u32 {
        // Positive entries live as long as their answers; negative/NODATA
        // entries as long as the authority (SOA). Padding sections must not
        // shorten the entry: an additional record with TTL 0 would otherwise
        // collapse a long-lived answer to 1s.
        dns::min_ttl(&self.answers)
            .or_else(|| dns::min_ttl(&self.authority))
            .or_else(|| dns::min_ttl(&self.additional))
            .unwrap_or(0)
    }
}

/// Outcome of the main-DNS stage.
struct LocalResult {
    /// A ready-to-send response (trust_rcode / NOERROR+answer / aaaa=noerror).
    handled: Option<Vec<u8>>,
    /// A main-DNS response to reconsider on the fallback path.
    carry: Option<Parts>,
    /// Whether `carry` is a NODATA (preferred over a NODATA fallback).
    carry_is_nodata: bool,
    /// Whether `carry` is any definite negative (NODATA or NXDOMAIN), which is
    /// preferred over a fallback that answered with an error code.
    carry_is_negative: bool,
    /// What the hedge already obtained from the fallback, so the fallback
    /// stage does not ask a second time.
    hedged: Option<Hedged>,
}
/// A fallback answer the hedge already has in hand.
enum Hedged {
    /// Straight from the fallback cache, which the hedge checks first.
    Cached(Arc<CachedMsg>),
    /// From a fallback query the hedge started and that finished first.
    Fresh(crate::upstream::ForwardResult),
}

impl LocalResult {
    fn none() -> Self {
        LocalResult {
            handled: None,
            carry: None,
            carry_is_nodata: false,
            carry_is_negative: false,
            hedged: None,
        }
    }
}

/// The routing decision: whether to bypass the main DNS, the log label to use
/// when the fallback answers, and how a fallback-sourced answer is aged.
struct RouteDecision {
    /// Skip the main DNS entirely (force_fall policy, or hook-detected outage).
    /// Also selects which cache this query reads: forced routes read the
    /// fallback cache, everyone else the main one.
    force: bool,
    fall_label: &'static str,
    /// Whether a fallback-sourced answer is handed to the *client* with TTL=1.
    /// True for failover (so recovery switches back fast), false for force_fall
    /// — permanent policy routing, where those clients keep the upstream TTLs.
    /// This governs only what the client sees; the cache always stores the
    /// upstream's own TTL.
    fallback_ttl1: bool,
}

/// Human-readable rcode label for logs. Borrowed for every label known
/// statically: labels are built on the cache-hit and upstream-response paths
/// *before* `dlog` gets to check whether debug logging is on (arguments are
/// evaluated first), so an owned `String` here would allocate on every query
/// whether or not the line is ever emitted.
/// Main queries still running after the client was answered from the fallback.
/// Each holds an upstream socket, so the number that may linger is capped.
static HEDGE_TASKS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(64)));
/// What the main stage reports when it never produced an answer of its own:
/// the fallback won the race, or the query was dropped.
fn lost_race() -> crate::upstream::ForwardResult {
    crate::upstream::ForwardResult {
        response: None,
        upstream: Arc::from("timeout/err"),
        duration: Duration::ZERO,
        had_error: true,
    }
}
/// Rcodes that mean the upstream could not answer, as opposed to answering
/// that the name or record does not exist.
fn is_upstream_error(rcode: Rcode) -> bool {
    matches!(
        rcode,
        Rcode::SERVFAIL | Rcode::REFUSED | Rcode::NOTIMP | Rcode::FORMERR
    )
}
fn rcode_label(rcode: Rcode, empty_answer: bool) -> Cow<'static, str> {
    match rcode {
        Rcode::NOERROR if empty_answer => Cow::Borrowed("NODATA"),
        Rcode::NOERROR => Cow::Borrowed("NOERROR"),
        Rcode::NXDOMAIN => Cow::Borrowed("NXDOMAIN"),
        Rcode::SERVFAIL => Cow::Borrowed("SERVFAIL"),
        Rcode::REFUSED => Cow::Borrowed("REFUSED"),
        Rcode::FORMERR => Cow::Borrowed("FORMERR"),
        other => Cow::Owned(format!("RCODE_{}", u8::from(other))),
    }
}

const PAOPAO_DNS_WIRE: &[u8] = b"\x06paopao\x03dns\x00";

/// TTL on the synthesised ANY answer. Long enough that a client which insists
/// on asking gets the same cheap answer from its own cache.
const ANY_HINFO_TTL: u32 = 3600;

/// TTL on answers synthesised from local tables (hosts/lease entries). Short
/// enough that a client picks up an edited table within minutes.
const LOCAL_TTL: u32 = 300;

/// Parsed state carried from the synchronous fast path to the upstream (slow)
/// path, so nothing is parsed twice. Opaque outside this module.
pub struct PendingQuery {
    msg: Message<Vec<u8>>,
    query: OwnedQueryInfo,
    route: RouteDecision,
    udp_limit: Option<u16>,
}

/// Result of the synchronous fast path.
pub enum FastOutcome {
    /// Answered without upstream IO; the response is in the caller's buffer.
    Reply,
    /// Dropped without an answer.
    Drop,
    /// Needs upstream IO; finish with `process_slow`. Boxed so the answered
    /// outcomes stay small.
    Pending(Box<PendingQuery>),
}

/// Turn a response into what the cache holds: the key for this question, and
/// the records with their slack handed back.
fn seal(info: &QueryInfo<'_>, mut parts: Parts) -> (CacheKey, Arc<CachedMsg>) {
    // The record vectors were built by pushing and filtering, so they hold
    // spare capacity (a filter keeps what it removed — every upstream OPT
    // leaves an empty but allocated additional section behind). A cached
    // entry can live for a day; hand the slack back first.
    parts.answers.shrink_to_fit();
    parts.authority.shrink_to_fit();
    parts.additional.shrink_to_fit();
    let cached = Arc::new(CachedMsg {
        rcode: parts.rcode,
        answers: parts.answers,
        authority: parts.authority,
        additional: parts.additional,
    });
    let key = CacheKey::with_hash(
        info.lower().to_vec(),
        info.qtype.to_int(),
        info.qclass.to_int(),
        info.name_hash,
    );
    (key, cached)
}

impl Handler {
    /// Every cache the handler stores answers in. Callers that maintain all of
    /// them — the janitor sweeping expired entries — go through this, so a
    /// cache added here cannot be left unmaintained.
    pub fn caches(&self) -> [Arc<Cache>; 2] {
        [self.cache.clone(), self.fall_cache.clone()]
    }

    /// Process one query, returning the wire response to send (None = drop).
    /// Both front-ends drive the two halves separately — the fast one inline,
    /// the slow one in a task — so this whole-query form is for tests.
    #[cfg(test)]
    pub async fn process(&self, req: Vec<u8>, client: IpAddr, is_udp: bool) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        match self.process_fast(&req, client, is_udp, &mut out) {
            FastOutcome::Reply => Some(out),
            FastOutcome::Drop => None,
            FastOutcome::Pending(p) => self.process_slow(p, client).await,
        }
    }

    /// The no-IO paths: parse, FORMERR, static rewrite (block/hosts/PTR), and
    /// cache hit. Synchronous and bounded (~µs), so the UDP receive loop can
    /// run it inline without spawning a task; only a `Pending` result pays the
    /// per-task scheduling cost.
    ///
    /// A reply is written into `out`, replacing its contents, so a loop that
    /// answers query after query can keep one buffer. The query name is parsed
    /// onto the stack and the cache is searched with a borrowed key, which
    /// leaves the cache-hit and block paths nothing to allocate.
    pub fn process_fast(
        &self,
        req: &[u8],
        client: IpAddr,
        is_udp: bool,
        out: &mut Vec<u8>,
    ) -> FastOutcome {
        let Ok(msg) = Message::from_octets(req) else {
            return FastOutcome::Drop;
        };
        // A response must never be processed as a query (RFC 1035 §7.3):
        // answering one would forward it upstream and reply to the "client".
        if msg.header().qr() {
            return FastOutcome::Drop;
        }
        // Non-QUERY opcodes (IQUERY/STATUS/NOTIFY/UPDATE) are not supported;
        // forwarding them as plain queries would silently change semantics.
        if msg.header().opcode() != Opcode::QUERY {
            self.reject(&msg, Rcode::NOTIMP, is_udp, out);
            return FastOutcome::Reply;
        }
        let mut scratch = QueryScratch::new();
        let Some(info) = dns::extract_query(&msg, &mut scratch) else {
            // No sole question → FORMERR.
            self.reject(&msg, Rcode::FORMERR, is_udp, out);
            return FastOutcome::Reply;
        };

        let udp_limit = if is_udp {
            Some(dns::udp_response_limit(info.client_edns))
        } else {
            None
        };

        if self.try_static_rewrite(&msg, &info, client, udp_limit, out) {
            return FastOutcome::Reply;
        }

        let route = self.resolve_route(info.lower(), client);

        // Forced routes read the fallback cache, everyone else the main one.
        let (cache, cache_label) = if route.force {
            (&self.fall_cache, "cache-fall")
        } else {
            (&self.cache, "cache")
        };
        {
            if let Some((cached, ttl_left)) = cache.get(&key_of(&info)) {
                // The stored TTL is always the upstream's own. Only what the
                // client sees is capped, and only for failover — so a hook-down
                // hit still serves TTL=1 and the client re-asks (and lands back
                // on the main DNS) as soon as the hook clears.
                let ttl_left = if route.force && route.fallback_ttl1 {
                    1
                } else {
                    ttl_left
                };
                let empty = cached.rcode == Rcode::NOERROR && cached.answers.is_empty();
                self.dlog(
                    cache_label,
                    &info,
                    client,
                    None,
                    &rcode_label(cached.rcode, empty),
                    None,
                    None,
                );
                let rcode_byte = if empty {
                    RCODE_NODATA
                } else {
                    u8::from(cached.rcode)
                };
                self.preport(
                    ROUTE_CACHE,
                    rcode_byte,
                    0,
                    "",
                    &cached.answers,
                    &cached.additional,
                    &info,
                    client,
                );
                self.build_cached(&msg, &info, &cached, ttl_left, udp_limit, out);
                return FastOutcome::Reply;
            }
        }

        // Only here do we need owned copies of the message and the names: this
        // query is going to an upstream, which means a task spawn and a network
        // round trip — the copies are noise. The answered-inline paths above
        // never pay for them.
        let query = info.detach();
        let Ok(msg) = Message::from_octets(req.to_vec()) else {
            return FastOutcome::Drop;
        };
        FastOutcome::Pending(Box::new(PendingQuery {
            msg,
            query,
            route,
            udp_limit,
        }))
    }

    /// Finish a query the fast path couldn't answer: forward to the main DNS
    /// and/or fallback upstreams.
    pub async fn process_slow(&self, p: Box<PendingQuery>, client: IpAddr) -> Option<Vec<u8>> {
        let PendingQuery {
            msg,
            query: owned,
            route,
            udp_limit,
        } = *p;
        let info = owned.info();
        // Mutable: each upstream stage stamps its own transaction ID into it.
        // The main stage takes its own copy, because a hedged main query can
        // still be running when the fallback stage uses this one.
        let mut query = dns::build_upstream_query(&info);
        let local = if route.force {
            LocalResult::none()
        } else {
            self.exec_local(&msg, &info, query.clone(), client, udp_limit)
                .await
        };
        if let Some(resp) = local.handled {
            return Some(resp);
        }
        Some(
            self.exec_fallback(&msg, &info, &mut query, &route, client, local, udp_limit)
                .await,
        )
    }

    /// Build a question-echoing error response (FORMERR/NOTIMP). The client's
    /// EDNS is still echoed even though the query wasn't processed
    /// (RFC 6891 §7), and the UDP size budget still applies.
    fn reject<Octs: domain::dep::octseq::Octets + ?Sized>(
        &self,
        msg: &Message<Octs>,
        rcode: Rcode,
        is_udp: bool,
        out: &mut Vec<u8>,
    ) {
        let edns = dns::edns_of(msg);
        let udp_limit = is_udp.then(|| dns::udp_response_limit(edns));
        self.build_into(
            msg,
            rcode,
            &Parts::empty(),
            edns,
            udp_limit,
            None,
            None,
            out,
        );
    }

    /// Answers needing no upstream: AAAA/SVCB/HTTPS blocking, hosts forward
    /// lookups, local PTR, and bogus-priv. Returns whether it answered, in
    /// which case the response is in `out`.
    fn try_static_rewrite<Octs: domain::dep::octseq::Octets + ?Sized>(
        &self,
        msg: &Message<Octs>,
        info: &QueryInfo<'_>,
        client: IpAddr,
        udp_limit: Option<u16>,
        out: &mut Vec<u8>,
    ) -> bool {
        let qt = info.qtype;

        // RFC 8482: a conventional ANY response — every RRset a name has — is
        // deprecated, and a forwarder is the wrong place to assemble one. Answer
        // with the synthesised HINFO the RFC defines instead of asking upstream.
        if qt == Rtype::ANY {
            self.dlog("any", info, client, None, "RFC8482", None, None);
            self.preport(ROUTE_HOSTS, 0, 0, "rfc8482", &[], &[], info, client);
            let parts = Parts {
                rcode: Rcode::NOERROR,
                answers: vec![OwnedRecord::new(
                    info.qname_owned(),
                    info.qclass,
                    Ttl::from_secs(ANY_HINFO_TTL),
                    AllRecordData::Hinfo(Hinfo::new(
                        CharStr::from_octets(b"RFC8482".to_vec()).expect("7 bytes"),
                        CharStr::from_octets(Vec::new()).expect("empty"),
                    )),
                )],
                authority: Vec::new(),
                additional: Vec::new(),
            };
            self.build_into(
                msg,
                Rcode::NOERROR,
                &parts,
                info.client_edns,
                udp_limit,
                None,
                Some(info.qtype),
                out,
            );
            return true;
        }

        // Blocking is checked first (an AAAA block shadows a hosts AAAA entry).
        let block = (self.block_svcb && (qt == Rtype::SVCB || qt == Rtype::HTTPS))
            || (self.aaaa_mode == AaaaMode::No && qt == Rtype::AAAA);
        if block {
            let (route, up_label) = match qt {
                Rtype::SVCB => ("block-svcb", "block-svcb"),
                Rtype::HTTPS => ("block-https", "block-https"),
                _ => ("block", "block-aaaa"),
            };
            self.dlog(route, info, client, None, "BLOCKED", None, None);
            self.preport(
                ROUTE_HOSTS,
                RCODE_NODATA,
                0,
                up_label,
                &[],
                &[],
                info,
                client,
            );
            self.build_into(
                msg,
                Rcode::NOERROR,
                &Parts::empty(),
                info.client_edns,
                udp_limit,
                None,
                Some(info.qtype),
                out,
            );
            return true;
        }

        // Forward lookup from hosts files / [hosts] config. A locally defined
        // name is authoritative for *every* type, as it is in dnsmasq: when the
        // entry holds no address of the queried family the answer is an empty
        // NOERROR, not a fall-through. Falling through would resolve the name
        // upstream for real, so an IPv4-only entry — the shape every ad-blocking
        // hosts list uses — would be bypassed over IPv6, and an internal name
        // would leak.
        if qt == Rtype::A || qt == Rtype::AAAA {
            if let Some(res) = &self.resolver {
                let mut ips = res.lookup_ip(info.lower(), info.name_hash);
                if !ips.is_empty() {
                    // A name the table defines answers only with addresses of
                    // the queried family; the rest of the entry is not an
                    // answer to this question.
                    ips.retain(|ip| ip.is_ipv4() == (qt == Rtype::A));
                    if self.hosts_response(msg, info, client, ips.as_slice(), udp_limit, out) {
                        self.dlog("hosts", info, client, None, "NOERROR", None, None);
                    } else {
                        self.dlog("hosts", info, client, None, "NODATA", None, None);
                        self.preport(
                            ROUTE_HOSTS,
                            RCODE_NODATA,
                            0,
                            "hosts",
                            &[],
                            &[],
                            info,
                            client,
                        );
                        self.build_into(
                            msg,
                            Rcode::NOERROR,
                            &Parts::empty(),
                            info.client_edns,
                            udp_limit,
                            None,
                            Some(info.qtype),
                            out,
                        );
                    }
                    return true;
                }
            }
        }

        // Local PTR, then bogus-priv.
        if qt == Rtype::PTR {
            if let Some(res) = &self.resolver {
                if let Some(host) = res.lookup(info.lower()) {
                    if self.ptr_response(msg, info, client, &host, udp_limit, out) {
                        self.dlog(
                            "local-ptr",
                            info,
                            client,
                            None,
                            "NOERROR",
                            None,
                            Some(&host),
                        );
                        return true;
                    }
                }
            }
            if self.boguspriv && is_private_ptr_name(info.lower()) {
                self.dlog("bogus-priv", info, client, None, "NXDOMAIN", None, None);
                self.preport(
                    ROUTE_HOSTS,
                    u8::from(Rcode::NXDOMAIN),
                    0,
                    "bogus-priv",
                    &[],
                    &[],
                    info,
                    client,
                );
                self.build_into(
                    msg,
                    Rcode::NXDOMAIN,
                    &Parts::empty(),
                    info.client_edns,
                    udp_limit,
                    None,
                    Some(info.qtype),
                    out,
                );
                return true;
            }
        }
        false
    }

    /// Build a NOERROR response with A/AAAA records (TTL [`LOCAL_TTL`]) for a
    /// hosts hit into `out`. `ips` holds the queried family only. Returns
    /// false, leaving `out` untouched, when there is nothing to answer with.
    fn hosts_response<Octs: domain::dep::octseq::Octets + ?Sized>(
        &self,
        msg: &Message<Octs>,
        info: &QueryInfo<'_>,
        client: IpAddr,
        ips: &[std::net::IpAddr],
        udp_limit: Option<u16>,
        out: &mut Vec<u8>,
    ) -> bool {
        if ips.is_empty() {
            return false;
        }
        // Straight to the wire, with no records to allocate. Telemetry wants
        // the records themselves, so a reporting build takes the path below.
        if self.pplog.is_none() {
            let data = dns::AddrAnswers {
                owner: info.name_bytes(),
                ips,
                qtype: info.qtype,
                ttl: LOCAL_TTL,
                edns: info.client_edns,
            };
            if dns::build_addr_response_into(msg, &data, udp_limit, out) {
                return true;
            }
        }
        let mut answers = Vec::with_capacity(ips.len());
        for ip in ips {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    let o = v4.octets();
                    answers.push(OwnedRecord::new(
                        info.qname_owned(),
                        Class::IN,
                        Ttl::from_secs(LOCAL_TTL),
                        AllRecordData::A(A::from_octets(o[0], o[1], o[2], o[3])),
                    ));
                }
                std::net::IpAddr::V6(v6) => {
                    answers.push(OwnedRecord::new(
                        info.qname_owned(),
                        Class::IN,
                        Ttl::from_secs(LOCAL_TTL),
                        AllRecordData::Aaaa(Aaaa::new(*v6)),
                    ));
                }
            }
        }
        let parts = Parts {
            rcode: Rcode::NOERROR,
            answers,
            authority: Vec::new(),
            additional: Vec::new(),
        };
        self.build_into(
            msg,
            Rcode::NOERROR,
            &parts,
            info.client_edns,
            udp_limit,
            None,
            Some(info.qtype),
            out,
        );
        self.preport(
            ROUTE_HOSTS,
            0,
            0,
            "hosts",
            &parts.answers,
            &[],
            info,
            client,
        );
        true
    }

    /// Build a NOERROR PTR response (TTL [`LOCAL_TTL`]) for a local reverse hit into
    /// `out`. Returns false, leaving `out` untouched, if the hostname is not a
    /// usable domain name.
    fn ptr_response<Octs: domain::dep::octseq::Octets + ?Sized>(
        &self,
        msg: &Message<Octs>,
        info: &QueryInfo<'_>,
        client: IpAddr,
        hostname: &str,
        udp_limit: Option<u16>,
        out: &mut Vec<u8>,
    ) -> bool {
        let Some(target) = hostname_to_name(hostname) else {
            return false;
        };
        let rec = OwnedRecord::new(
            info.qname_owned(),
            Class::IN,
            Ttl::from_secs(LOCAL_TTL),
            AllRecordData::Ptr(Ptr::new(target)),
        );
        let parts = Parts {
            rcode: Rcode::NOERROR,
            answers: vec![rec],
            authority: Vec::new(),
            additional: Vec::new(),
        };
        self.build_into(
            msg,
            Rcode::NOERROR,
            &parts,
            info.client_edns,
            udp_limit,
            None,
            Some(info.qtype),
            out,
        );
        self.preport(
            ROUTE_HOSTS,
            0,
            0,
            "local-ptr",
            &parts.answers,
            &[],
            info,
            client,
        );
        true
    }

    /// force_fall matcher + hook-down forcing + the `paopao.dns` always-main
    /// special case. `fall_label` is the route label used when the query is
    /// answered from the fallback ("fall" / "force_fall" / "hook_fall").
    fn resolve_route(&self, qname_lower: &[u8], client: IpAddr) -> RouteDecision {
        let ff = self.force_fall.matches(client);
        let hook_down = self
            .hook_failed
            .as_ref()
            .map(|h| h.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false);
        let mut force = ff || hook_down;
        // paopao.dns always uses the primary DNS, overriding force_fall/hook.
        if force && qname_lower.eq_ignore_ascii_case(PAOPAO_DNS_WIRE) {
            force = false;
            return RouteDecision {
                force,
                fall_label: "fall",
                fallback_ttl1: true,
            };
        }
        let (fall_label, fallback_ttl1) = if !force {
            ("fall", true)
        } else if hook_down {
            ("hook_fall", true)
        } else {
            ("force_fall", false)
        };
        RouteDecision {
            force,
            fall_label,
            fallback_ttl1,
        }
    }

    /// Emit a pplog telemetry entry (no-op unless pplog is enabled).
    #[allow(clippy::too_many_arguments)]
    fn preport(
        &self,
        route: u8,
        rcode: u8,
        dur_ms: u16,
        upstream: &str,
        answers: &[OwnedRecord],
        additional: &[OwnedRecord],
        info: &QueryInfo<'_>,
        client: IpAddr,
    ) {
        let Some(rep) = &self.pplog else {
            return;
        };
        let lvl = rep.level();
        let entry = crate::pplog::QueryEntry {
            client,
            qtype: info.qtype.to_int(),
            rcode,
            route,
            duration_ms: dur_ms,
            qname_wire: info.name_bytes(),
            upstream: if lvl >= 2 { upstream } else { "" },
            answers: if lvl >= 3 { answers } else { &[] },
            additional: if lvl >= 4 { additional } else { &[] },
        };
        rep.report(&entry);
    }

    /// Emit a debug query log line (no-op unless debug is enabled).
    #[allow(clippy::too_many_arguments)]
    fn dlog(
        &self,
        route: &str,
        info: &QueryInfo<'_>,
        client: IpAddr,
        upstream: Option<&str>,
        rcode: &str,
        dur: Option<Duration>,
        extra: Option<&str>,
    ) {
        if !log::debug_enabled() {
            return;
        }
        let domain = info.qname().to_string();
        log::query(&log::Query {
            route,
            client,
            upstream,
            qtype: info.qtype,
            domain: &domain,
            rcode,
            dur,
            extra,
        });
    }

    /// Ask the main DNS, and once [`Handler::hedge_after`] has passed with no
    /// answer, start the fallback *alongside* it rather than giving up on it.
    /// Whichever answers first wins the race.
    ///
    /// Not cancelling the main query is the point: a self-hosted recursive
    /// resolver often needs longer than `qtime` for a cold name, and its
    /// answer — not the fallback's — is the one the client asked for. It also
    /// fixes what the breaker sees: a main that is merely slow no longer looks
    /// like a failure, only one that misses the whole deadline does.
    ///
    /// Returns the main's result (an error result when the fallback won the
    /// race) and whatever the hedge already obtained from the fallback.
    async fn query_main_hedged(
        &self,
        info: &QueryInfo<'_>,
        query: Vec<u8>,
    ) -> (crate::upstream::ForwardResult, Option<Hedged>) {
        // The main query runs as its own task so it can outlive this one: when
        // the fallback wins, the main still has to finish for the breaker to
        // learn whether the main DNS is actually down — abandoning it there
        // would blind the breaker during exactly the outage it exists for.
        // Each lingering query holds an upstream socket, so their number is
        // capped; past the cap the query runs inline and is dropped at the
        // threshold, which is what happened before hedging.
        let mut main_fut: std::pin::Pin<
            Box<dyn std::future::Future<Output = crate::upstream::ForwardResult> + Send + '_>,
        > = match HEDGE_TASKS.clone().try_acquire_owned() {
            Ok(permit) => {
                let main = self.main.clone();
                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    let mut query = query;
                    main.exec(&mut query).await
                });
                Box::pin(async move { handle.await.unwrap_or_else(|_| lost_race()) })
            }
            Err(_) => Box::pin(async move {
                let mut query = query;
                self.main.exec(&mut query).await
            }),
        };
        match tokio::time::timeout(self.hedge_after, &mut main_fut).await {
            Ok(result) => (result, None),
            Err(_) => {
                // The main is slow. An answer the fallback cache already holds
                // costs nothing, so take that and stop waiting.
                if let Some((cached, _)) = self.fall_cache.get(&key_of(info)) {
                    return (lost_race(), Some(Hedged::Cached(cached)));
                }
                let mut fall_query = dns::build_upstream_query(info);
                let fall_fut = self.fallback.exec(&mut fall_query);
                tokio::pin!(fall_fut);
                tokio::select! {
                    // The main came through after all: its answer is the one
                    // this client wanted. The fallback query is dropped.
                    result = &mut main_fut => (result, None),
                    // The fallback got there first. Dropping `main_fut` detaches
                    // the spawned query rather than cancelling it.
                    fall = &mut fall_fut => (lost_race(), Some(Hedged::Fresh(fall))),
                }
            }
        }
    }
    async fn exec_local(
        &self,
        msg: &Message<Vec<u8>>,
        info: &QueryInfo<'_>,
        query: Vec<u8>,
        client: IpAddr,
        udp_limit: Option<u16>,
    ) -> LocalResult {
        // Destructured so the label moves out alongside `response`, which is
        // consumed below.
        let (
            crate::upstream::ForwardResult {
                response,
                upstream: up,
                duration,
                ..
            },
            hedged,
        ) = self.query_main_hedged(info, query).await;
        let dur = Some(duration);
        let dms = dur_to_ms(duration);
        let Some(resp) = response else {
            self.dlog("local", info, client, Some(&up), "timeout/error", dur, None);
            self.preport(ROUTE_LOCAL, RCODE_TIMEOUT, dms, &up, &[], &[], info, client);
            return LocalResult {
                hedged,
                ..LocalResult::none()
            };
        };
        let mut parts = Parts::from_msg(&resp);
        if self.lite {
            self.apply_lite(&mut parts, info);
        }
        let log_local = |label: &str| self.dlog("local", info, client, Some(&up), label, dur, None);

        // trust_rcode: accept directly, skip fallback.
        if !self.trust_rcodes.is_empty() && self.trust_rcodes.contains(&u8::from(parts.rcode)) {
            let out = self.build(
                msg,
                parts.rcode,
                &parts,
                info.client_edns,
                udp_limit,
                None,
                Some(info.qtype),
            );
            // `dlog` guards on debug_enabled() itself, but the "(trusted)"
            // suffix has to be formatted before the call, so hoist the check.
            if log::debug_enabled() {
                let base = rcode_label(parts.rcode, false);
                if parts.answers.is_empty() {
                    log_local(&format!("{base}(trusted)"));
                } else {
                    log_local(&base);
                }
            }
            // Report the true rcode; only a NOERROR with no answers is NODATA.
            // Using `answers.is_empty()` alone would mislabel a trusted empty
            // NXDOMAIN/REFUSED as NODATA (0xFF) to the pplog collector.
            let rcode_byte = if parts.is_nodata() {
                RCODE_NODATA
            } else {
                u8::from(parts.rcode)
            };
            self.preport(
                ROUTE_LOCAL,
                rcode_byte,
                dms,
                &up,
                &parts.answers,
                &parts.additional,
                info,
                client,
            );
            self.store_answer(&self.cache, info, parts, true);
            return LocalResult {
                handled: Some(out),
                carry: None,
                carry_is_nodata: false,
                carry_is_negative: false,
                hedged,
            };
        }

        if parts.rcode == Rcode::NOERROR && !parts.answers.is_empty() {
            let out = self.build(
                msg,
                parts.rcode,
                &parts,
                info.client_edns,
                udp_limit,
                None,
                Some(info.qtype),
            );
            log_local("NOERROR");
            self.preport(
                ROUTE_LOCAL,
                0,
                dms,
                &up,
                &parts.answers,
                &parts.additional,
                info,
                client,
            );
            self.store_answer(&self.cache, info, parts, true);
            return LocalResult {
                handled: Some(out),
                carry: None,
                carry_is_nodata: false,
                carry_is_negative: false,
                hedged,
            };
        }

        if parts.is_nodata() {
            // aaaa=noerror: trust the main DNS's empty NOERROR for AAAA.
            if self.aaaa_mode == AaaaMode::NoError && info.qtype == Rtype::AAAA {
                let out = self.build(
                    msg,
                    parts.rcode,
                    &parts,
                    info.client_edns,
                    udp_limit,
                    None,
                    Some(info.qtype),
                );
                log_local("NODATA(trusted)");
                self.preport(
                    ROUTE_LOCAL,
                    RCODE_NODATA,
                    dms,
                    &up,
                    &parts.answers,
                    &parts.additional,
                    info,
                    client,
                );
                self.store_answer(&self.cache, info, parts, true);
                return LocalResult {
                    handled: Some(out),
                    carry: None,
                    carry_is_nodata: false,
                    carry_is_negative: false,
                    hedged,
                };
            }
            log_local("NODATA");
            self.preport(
                ROUTE_LOCAL,
                RCODE_NODATA,
                dms,
                &up,
                &parts.answers,
                &parts.additional,
                info,
                client,
            );
            return LocalResult {
                handled: None,
                carry: Some(parts),
                carry_is_nodata: true,
                carry_is_negative: true,
                hedged,
            };
        }

        // Non-success rcode (NXDOMAIN/REFUSED/…): keep as fallback-failure fallback.
        log_local(&rcode_label(parts.rcode, false));
        self.preport(
            ROUTE_LOCAL,
            u8::from(parts.rcode),
            dms,
            &up,
            &parts.answers,
            &parts.additional,
            info,
            client,
        );
        let carry_is_negative = parts.is_negative();
        LocalResult {
            handled: None,
            carry: Some(parts),
            carry_is_nodata: false,
            carry_is_negative,
            hedged,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn exec_fallback(
        &self,
        msg: &Message<Vec<u8>>,
        info: &QueryInfo<'_>,
        query: &mut [u8],
        route: &RouteDecision,
        client: IpAddr,
        local: LocalResult,
        udp_limit: Option<u16>,
    ) -> Vec<u8> {
        // Try the fallback cache before the network. Its entries are faithful
        // fallback-upstream answers, so this is what stops a main-DNS outage
        // from turning every client retry into an upstream query — and it works
        // whether or not a hook is configured (the hook is optional and off by
        // default, so the hookless outage is the common case). The client still
        // gets TTL=1 below and re-checks the main DNS a second later.
        // The hedge may already have what this stage would go and fetch: it
        // checks the same cache and, failing that, runs the same query. Asking
        // again would double the fallback's load for every slow main query.
        let (fall, up, duration, had_error, from_cache) = match local.hedged {
            Some(Hedged::Cached(c)) => (
                Some(Parts::from_cached(&c)),
                Arc::<str>::from(FALL_CACHE_LABEL),
                Duration::ZERO,
                false,
                true,
            ),
            Some(Hedged::Fresh(r)) => (
                r.response.as_ref().map(Parts::from_msg),
                r.upstream,
                r.duration,
                r.had_error,
                false,
            ),
            None => {
                let cached_fall = self.fall_cache.get(&key_of(info));
                let from_cache = cached_fall.is_some();
                match cached_fall {
                    Some((c, _)) => (
                        Some(Parts::from_cached(&c)),
                        Arc::<str>::from(FALL_CACHE_LABEL),
                        Duration::ZERO,
                        false,
                        from_cache,
                    ),
                    None => {
                        let crate::upstream::ForwardResult {
                            response,
                            upstream,
                            duration,
                            had_error,
                        } = self.fallback.exec(query).await;
                        (
                            response.as_ref().map(Parts::from_msg),
                            upstream,
                            duration,
                            had_error,
                            false,
                        )
                    }
                }
            }
        };
        let dur = Some(duration);
        let fall_is_nodata = fall.as_ref().map(Parts::is_nodata).unwrap_or(false);
        let flabel = route.fall_label;

        // pplog reports the fallback query outcome (route byte from the label),
        // regardless of which response is ultimately served to the client.
        let flabel_byte = match flabel {
            "hook_fall" => ROUTE_HOOK_FALL,
            "force_fall" => ROUTE_FORCE_FALL,
            _ => ROUTE_FALL,
        };
        let dms = dur_to_ms(duration);
        match &fall {
            Some(fp) => {
                let rc = if fp.is_nodata() {
                    RCODE_NODATA
                } else {
                    u8::from(fp.rcode)
                };
                self.preport(
                    flabel_byte,
                    rc,
                    dms,
                    &up,
                    &fp.answers,
                    &fp.additional,
                    info,
                    client,
                );
            }
            None => self.preport(flabel_byte, RCODE_TIMEOUT, dms, &up, &[], &[], info, client),
        }

        let mut carry = local.carry;

        // The main DNS wins over a fallback that did not really answer:
        //   * its NODATA over a NODATA or absent fallback (they agree, or
        //     there is nothing to disagree with), and
        //   * any definite negative over an error code, which says "ask
        //     someone else", not "this record does not exist" — handing that
        //     to the client turns a definite answer into a retry.
        let fall_is_error = fall.as_ref().is_some_and(|p| is_upstream_error(p.rcode));
        if (local.carry_is_nodata && (fall_is_nodata || fall.is_none()))
            || (local.carry_is_negative && fall_is_error)
        {
            let np = carry.take().expect("nodata implies carry");
            let out = self.build(
                msg,
                np.rcode,
                &np,
                info.client_edns,
                udp_limit,
                None,
                Some(info.qtype),
            );
            self.dlog(flabel, info, client, Some(&up), "NODATA", dur, None);
            // This answer came from the *main* DNS, so it belongs in the main
            // cache — a forced route never reaches here (it carries nothing).
            // Only a fallback that said NODATA as well confirms it; one that
            // could not answer leaves this negative on the floor TTL, so a
            // flaky fallback cannot make it stick.
            self.store_answer(&self.cache, info, np, fall_is_nodata);
            return out;
        }

        if let Some(mut fp) = fall {
            // Cached entries were already lite-filtered on the way in.
            if self.lite && !from_cache {
                self.apply_lite(&mut fp, info);
            }
            let label = rcode_label(fp.rcode, fp.answers.is_empty());
            // Failover answers (main failed / hook-down) reach the *client*
            // with TTL=1 so recovery switches back fast. force_fall is policy
            // routing, not failover: those clients always use the fallback, so
            // they keep the upstream TTLs.
            let ttl_override = if route.fallback_ttl1 { Some(1) } else { None };
            let out = self.build(
                msg,
                fp.rcode,
                &fp,
                info.client_edns,
                udp_limit,
                ttl_override,
                Some(info.qtype),
            );
            self.dlog(flabel, info, client, Some(&up), &label, dur, None);
            // The client got TTL=1, but the cache keeps the upstream's own TTL:
            // that split is what lets the fallback cache actually absorb load
            // during an outage while every client still re-checks the main DNS
            // one second later. Always the fallback cache — the answer is a
            // fallback-upstream answer whoever asked for it.
            //
            // Never write back something we just read: the stored records carry
            // their *original* TTLs, so re-storing would reset the entry's
            // expiry and a name queried every second would never expire.
            // An error code is the fallback failing to answer, not an answer:
            // caching it would hand the same failure to every force_fall and
            // hook-down client that asks next.
            if !from_cache && !is_upstream_error(fp.rcode) {
                self.store_answer(&self.fall_cache, info, fp, true);
            }
            return out;
        }

        // Fallback failed entirely: surface the main-DNS response if we have one.
        if had_error {
            if let Some(lp) = carry.take() {
                let out = self.build(
                    msg,
                    lp.rcode,
                    &lp,
                    info.client_edns,
                    udp_limit,
                    None,
                    Some(info.qtype),
                );
                let label = rcode_label(lp.rcode, lp.answers.is_empty());
                self.dlog(flabel, info, client, Some(&up), &label, dur, None);
                // Main-DNS answer again, and nothing corroborated it: a
                // negative here is held at the floor TTL only.
                self.store_answer(&self.cache, info, lp, false);
                return out;
            }
        }
        self.dlog(flabel, info, client, Some(&up), "timeout/error", dur, None);

        self.build(
            msg,
            Rcode::SERVFAIL,
            &Parts::empty(),
            info.client_edns,
            udp_limit,
            None,
            Some(info.qtype),
        )
    }

    /// lite mode: keep only qtype records (following any CNAME chain and
    /// rewriting the final owner back to the query name), keep only SOA in the
    /// authority section, and drop the additional section.
    fn apply_lite(&self, parts: &mut Parts, info: &QueryInfo<'_>) {
        let qtype = info.qtype;
        let qname_lower = info.lower();
        if qtype == Rtype::CNAME {
            parts.answers.retain(|r| r.rtype() == Rtype::CNAME);
            parts.authority.retain(|r| r.rtype() == Rtype::SOA);
            parts.additional.clear();
            return;
        }

        let final_name = resolve_cname_chain(&parts.answers, qname_lower);
        let has_chain = final_name != qname_lower;
        if has_chain {
            let ok = parts
                .answers
                .iter()
                .any(|r| r.rtype() == qtype && name_eq_lower(r.owner(), &final_name));
            if !ok {
                // Chain end can't be validated in-response → don't filter (compat).
                return;
            }
        }

        let mut out = Vec::new();
        for r in parts.answers.drain(..) {
            if r.rtype() != qtype {
                continue;
            }
            if has_chain {
                if !name_eq_lower(r.owner(), &final_name) {
                    continue;
                }
                out.push(OwnedRecord::new(
                    info.qname_owned(),
                    r.class(),
                    r.ttl(),
                    r.data().clone(),
                ));
            } else {
                out.push(r);
            }
        }
        parts.answers = out;
        parts.authority.retain(|r| r.rtype() == Rtype::SOA);
        parts.additional.clear();
    }

    /// Store `parts` in the cache that matches the upstream it came from —
    /// `self.cache` for main-DNS answers, `self.fall_cache` for fallback ones.
    /// Cache `parts` under the policy its kind calls for: a definite negative
    /// goes through the escalating negative TTL, anything else keeps the
    /// records' own lifetime.
    ///
    /// `confirmed` tells the negative policy whether this "no" is one the
    /// resolver stands behind — the upstream that owns this cache said so and
    /// nothing contradicted it — or one it is only holding because the other
    /// upstream had nothing to say (see [`Cache::store_negative`]).
    fn store_answer(&self, cache: &Cache, info: &QueryInfo<'_>, parts: Parts, confirmed: bool) {
        // A negative with no SOA has no cacheable lifetime of its own
        // (RFC 2308 §5); it falls through to the record TTLs, which leaves it
        // at the cache's 1s floor.
        if parts.is_negative() {
            if let Some(cap) = dns::negative_ttl_cap(&parts.authority) {
                let (key, cached) = seal(info, parts);
                cache.store_negative(key, cached, cap, confirmed);
                return;
            }
        }
        self.store(cache, info, parts, None);
    }
    fn store(&self, cache: &Cache, info: &QueryInfo<'_>, parts: Parts, ttl_override: Option<u32>) {
        let ttl = ttl_override.unwrap_or_else(|| parts.min_ttl());
        let (key, cached) = seal(info, parts);
        cache.store(key, cached, ttl);
    }

    fn build_cached<Octs: domain::dep::octseq::Octets + ?Sized>(
        &self,
        msg: &Message<Octs>,
        info: &QueryInfo<'_>,
        cached: &CachedMsg,
        ttl_left: u32,
        udp_limit: Option<u16>,
        out: &mut Vec<u8>,
    ) {
        let data = ResponseData {
            rcode: cached.rcode,
            answers: &cached.answers,
            authority: &cached.authority,
            additional: &cached.additional,
            ttl_override: Some(ttl_left),
            edns: info.client_edns,
            shuffle_qtype: Some(info.qtype),
        };
        dns::build_response_into(msg, &data, udp_limit, out);
    }

    #[allow(clippy::too_many_arguments)]
    fn build<Octs: domain::dep::octseq::Octets + ?Sized>(
        &self,
        msg: &Message<Octs>,
        rcode: Rcode,
        parts: &Parts,
        edns: Option<ClientEdns>,
        udp_limit: Option<u16>,
        ttl_override: Option<u32>,
        shuffle_qtype: Option<Rtype>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        self.build_into(
            msg,
            rcode,
            parts,
            edns,
            udp_limit,
            ttl_override,
            shuffle_qtype,
            &mut out,
        );
        out
    }

    /// `build` into a caller-owned buffer, replacing its contents.
    #[allow(clippy::too_many_arguments)]
    fn build_into<Octs: domain::dep::octseq::Octets + ?Sized>(
        &self,
        msg: &Message<Octs>,
        rcode: Rcode,
        parts: &Parts,
        edns: Option<ClientEdns>,
        udp_limit: Option<u16>,
        ttl_override: Option<u32>,
        shuffle_qtype: Option<Rtype>,
        out: &mut Vec<u8>,
    ) {
        let data = ResponseData {
            rcode,
            answers: &parts.answers,
            authority: &parts.authority,
            additional: &parts.additional,
            ttl_override,
            edns,
            shuffle_qtype,
        };
        dns::build_response_into(msg, &data, udp_limit, out);
    }
}

/// The cache key for `info`, borrowed from the query itself.
fn key_of<'a>(info: &QueryInfo<'a>) -> KeyRef<'a> {
    KeyRef::new(
        info.lower(),
        info.qtype.to_int(),
        info.qclass.to_int(),
        info.name_hash,
    )
}

impl Parts {
    fn empty() -> Self {
        Parts {
            rcode: Rcode::NOERROR,
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
}

/// Follow the CNAME chain from `start_lower` (lower-cased wire name), returning
/// the final target as lower-cased wire bytes. One pass builds an owner→target
/// map so long chains stay O(n) — rescanning the answers per hop is O(n²),
/// measurable on a hostile 64 KiB TCP response. The hop count is bounded by
/// the link count, which also terminates cycles.
fn resolve_cname_chain(answers: &[OwnedRecord], start_lower: &[u8]) -> Vec<u8> {
    let mut links: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    for r in answers {
        if r.rtype() != Rtype::CNAME {
            continue;
        }
        if let AllRecordData::Cname(c) = r.data() {
            // First record wins on a duplicate owner, like the scan it replaces.
            links
                .entry(lower_wire(r.owner().as_slice()))
                .or_insert_with(|| lower_wire(c.cname().as_slice()));
        }
    }
    let mut current = start_lower.to_vec();
    for _ in 0..links.len() {
        match links.get(&current) {
            Some(next) => current = next.clone(),
            None => break,
        }
    }
    current
}

/// Case-insensitive comparison of an owner name against lower-cased wire bytes.
fn name_eq_lower(name: &OwnedName, lower: &[u8]) -> bool {
    let s = name.as_slice();
    s.len() == lower.len()
        && s.iter()
            .zip(lower)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn lower_wire(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.make_ascii_lowercase();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachedMsg;
    use crate::forcefall::parse_prefix;
    use crate::local_resolver::{AutoDetect, PtrResolver};
    use crate::upstream::{Forwarder, Upstream};
    use domain::base::name::ToName;
    use domain::base::{MessageBuilder, Name};
    use domain::rdata::Cname;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, AtomicU32};

    /// Counts the heap allocations each thread makes, so a test can pin down
    /// that a code path makes none. Counters are per thread, so tests running
    /// in parallel do not see each other's allocations.
    mod alloc_count {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        thread_local! {
            static COUNT: Cell<usize> = const { Cell::new(0) };
        }

        struct Counting;

        unsafe impl GlobalAlloc for Counting {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                let _ = COUNT.try_with(|c| c.set(c.get() + 1));
                unsafe { System.alloc(layout) }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                unsafe { System.dealloc(ptr, layout) }
            }

            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                let _ = COUNT.try_with(|c| c.set(c.get() + 1));
                unsafe { System.realloc(ptr, layout, new_size) }
            }
        }

        #[global_allocator]
        static GLOBAL: Counting = Counting;

        /// Allocations (and reallocations) this thread has made so far.
        pub fn allocations() -> usize {
            COUNT.with(|c| c.get())
        }
    }

    // ---- builders / helpers ----

    fn mk(main: Vec<String>, fall: Vec<String>) -> Handler {
        mk_timed(main, fall, 300, 1100, 800)
    }

    /// `mk` with the timings spelled out: the hedge threshold, the main's whole
    /// deadline, and the fallback's, in milliseconds. `app` derives the same
    /// shape from `qtime`.
    fn mk_timed(
        main: Vec<String>,
        fall: Vec<String>,
        hedge_ms: u64,
        main_ms: u64,
        fall_ms: u64,
    ) -> Handler {
        let fwd = |addrs: Vec<String>, to: u64| {
            Forwarder::new(
                addrs
                    .iter()
                    .map(|u| Arc::new(Upstream::parse(u).unwrap()))
                    .collect(),
                Duration::from_millis(to),
            )
        };
        let breaking = |addrs: Vec<String>, to: u64| {
            Forwarder::with_breaker(
                addrs
                    .iter()
                    .map(|u| Arc::new(Upstream::parse(u).unwrap()))
                    .collect(),
                Duration::from_millis(to),
            )
        };
        Handler {
            main: Arc::new(breaking(main, main_ms)),
            hedge_after: Duration::from_millis(hedge_ms),
            fallback: fwd(fall, fall_ms),
            cache: Arc::new(Cache::new(1024)),
            fall_cache: Arc::new(Cache::new(1024)),
            force_fall: ForceFallMatcher::default(),
            aaaa_mode: AaaaMode::No,
            lite: true,
            boguspriv: true,
            block_svcb: true,
            trust_rcodes: HashSet::new(),
            resolver: None,
            hook_failed: None,
            pplog: None,
        }
    }

    #[test]
    fn caches_lists_every_cache_the_handler_stores_into() {
        let h = mk(dead(), dead());
        let listed = h.caches();
        // The janitor sweeps exactly this list, so a store target missing from
        // it would keep expired entries until capacity evicted them.
        for c in [&h.cache, &h.fall_cache] {
            assert!(
                listed.iter().any(|l| Arc::ptr_eq(l, c)),
                "a cache the handler stores into is not listed"
            );
        }
    }

    /// A pair of unreachable upstreams (port 1) for paths that must not forward.
    fn dead() -> Vec<String> {
        vec!["udp://127.0.0.1:1".to_string()]
    }

    fn client_query(name: &str, qtype: Rtype) -> Vec<u8> {
        let mut b = MessageBuilder::new_vec();
        b.header_mut().set_rd(true);
        let mut q = b.question();
        q.push((Name::<Vec<u8>>::from_str(name).unwrap(), qtype))
            .unwrap();
        q.finish()
    }

    async fn ask(h: &Handler, name: &str, qtype: Rtype, client: &str) -> Vec<u8> {
        h.process(client_query(name, qtype), client.parse().unwrap(), true)
            .await
            .expect("a response")
    }

    fn a_rec(name: &str, ip: [u8; 4], ttl: u32) -> OwnedRecord {
        OwnedRecord::new(
            Name::<Vec<u8>>::from_str(name).unwrap(),
            Class::IN,
            Ttl::from_secs(ttl),
            AllRecordData::A(A::from_octets(ip[0], ip[1], ip[2], ip[3])),
        )
    }

    fn cname_rec(owner: &str, target: &str) -> OwnedRecord {
        OwnedRecord::new(
            Name::<Vec<u8>>::from_str(owner).unwrap(),
            Class::IN,
            Ttl::from_secs(300),
            AllRecordData::Cname(Cname::new(Name::<Vec<u8>>::from_str(target).unwrap())),
        )
    }

    /// Build an answer to `q` with the given rcode and A records (echoing the
    /// query's id + question, so the forwarder's id check accepts it).
    fn answer(q: &Message<Vec<u8>>, rcode: Rcode, a: &[([u8; 4], u32)]) -> Vec<u8> {
        let mut b = MessageBuilder::new_vec().start_answer(q, rcode).unwrap();
        let name = q.sole_question().unwrap().qname().to_vec();
        for (ip, ttl) in a {
            b.push((
                &name,
                Class::IN,
                Ttl::from_secs(*ttl),
                A::from_octets(ip[0], ip[1], ip[2], ip[3]),
            ))
            .unwrap();
        }
        b.finish()
    }

    /// Spawn a UDP mock upstream; returns its `udp://ip:port` label.
    async fn spawn_mock<F>(f: F) -> String
    where
        F: Fn(&Message<Vec<u8>>) -> Vec<u8> + Send + Sync + 'static,
    {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if let Some(msg) = crate::dns::parse(buf[..n].to_vec()) {
                    let _ = sock.send_to(&f(&msg), peer).await;
                }
            }
        });
        format!("udp://{addr}")
    }

    fn parse_resp(bytes: &[u8]) -> Message<Vec<u8>> {
        crate::dns::parse(bytes.to_vec()).unwrap()
    }
    fn answer_count(bytes: &[u8]) -> usize {
        parse_resp(bytes)
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .count()
    }
    fn first_ttl(bytes: &[u8]) -> Option<u32> {
        parse_resp(bytes)
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .next()
            .and_then(|r| r.ok())
            .map(|r| r.ttl().as_secs())
    }

    /// A negative answer with an SOA in authority, which is what RFC 2308 §5
    /// caps its cache lifetime by.
    fn negative(q: &Message<Vec<u8>>, rcode: Rcode, soa_ttl: u32, minimum: u32) -> Vec<u8> {
        use domain::base::Serial;
        use domain::rdata::Soa;
        let name = q.sole_question().unwrap().qname().to_vec();
        let n = |s: &str| Name::<Vec<u8>>::from_str(s).unwrap();
        let mut b = MessageBuilder::new_vec()
            .start_answer(q, rcode)
            .unwrap()
            .authority();
        b.push((
            &name,
            Class::IN,
            Ttl::from_secs(soa_ttl),
            Soa::new(
                n("ns.example.com."),
                n("hostmaster.example.com."),
                Serial(1),
                Ttl::from_secs(7200),
                Ttl::from_secs(3600),
                Ttl::from_secs(1_209_600),
                Ttl::from_secs(minimum),
            ),
        ))
        .unwrap();
        b.finish()
    }

    fn cache_key(name: &str, qtype: Rtype) -> CacheKey {
        let mut lower = Name::<Vec<u8>>::from_str(name).unwrap().as_slice().to_vec();
        lower.make_ascii_lowercase();
        CacheKey::new(lower, qtype.to_int(), Class::IN.to_int())
    }

    /// Remaining lifetime of what a cache holds for this question.
    fn cached_ttl(cache: &Cache, name: &str, qtype: Rtype) -> Option<u32> {
        cache.get(&cache_key(name, qtype)).map(|(_, ttl)| ttl)
    }

    /// What the *next* confirmation of this negative would cache for. Reads
    /// back whether the answer already banked a confirmation, which is the
    /// difference between "both upstreams said no" and "the other one was
    /// unreachable".
    fn next_negative_ttl(cache: &Cache, name: &str, qtype: Rtype) -> u32 {
        let msg = Arc::new(CachedMsg {
            rcode: Rcode::NXDOMAIN,
            answers: vec![],
            authority: vec![],
            additional: vec![],
        });
        cache.store_negative(cache_key(name, qtype), msg, 86_400, true)
    }

    #[tokio::test]
    async fn a_negative_the_fallback_could_not_confirm_is_held_only_briefly() {
        // The main DNS says so with a day-long SOA; the fallback, which would
        // normally get the last word, times out. Both kinds of "no" take their
        // own route through the fallback stage, so both are checked.
        for rcode in [Rcode::NXDOMAIN, Rcode::NOERROR] {
            let main = spawn_mock(move |q| negative(q, rcode, 86_400, 86_400)).await;
            let mut h = mk(vec![main], dead());
            h.aaaa_mode = AaaaMode::Yes;
            let out = ask(&h, "gone.example.com.", Rtype::AAAA, "127.0.0.1").await;
            assert_eq!(parse_resp(&out).header().rcode(), rcode);

            let ttl = cached_ttl(&h.cache, "gone.example.com.", Rtype::AAAA).expect("cached");
            assert!(
                ttl <= crate::cache::NEG_TTL_FLOOR,
                "{rcode}: an unconfirmed negative must not stick for the SOA's lifetime ({ttl}s)"
            );
            assert_eq!(
                next_negative_ttl(&h.cache, "gone.example.com.", Rtype::AAAA),
                crate::cache::NEG_TTL_FLOOR,
                "{rcode}: it must not bank a confirmation the fallback never gave"
            );
        }
    }

    #[tokio::test]
    async fn a_negative_both_upstreams_agree_on_starts_short_and_counts() {
        let main = spawn_mock(|q| negative(q, Rcode::NXDOMAIN, 86_400, 86_400)).await;
        let fall = spawn_mock(|q| negative(q, Rcode::NXDOMAIN, 86_400, 86_400)).await;
        let h = mk(vec![main], vec![fall]);
        let out = ask(&h, "gone.example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NXDOMAIN);

        // The fallback answered, so its cache holds it — briefly at first.
        let ttl = cached_ttl(&h.fall_cache, "gone.example.com.", Rtype::A).expect("cached");
        assert!(
            ttl <= crate::cache::NEG_TTL_FLOOR,
            "the first negative must be short-lived (got {ttl}s)"
        );
        assert_eq!(
            next_negative_ttl(&h.fall_cache, "gone.example.com.", Rtype::A),
            crate::cache::NEG_TTL_FLOOR * 2,
            "a confirmed negative escalates when it comes back again"
        );
    }

    #[tokio::test]
    async fn a_definite_main_answer_beats_a_fallback_that_only_errored() {
        for (main_rcode, fall_rcode) in [
            (Rcode::NOERROR, Rcode::SERVFAIL),
            (Rcode::NOERROR, Rcode::REFUSED),
            (Rcode::NXDOMAIN, Rcode::SERVFAIL),
            (Rcode::NXDOMAIN, Rcode::REFUSED),
        ] {
            let main = spawn_mock(move |q| negative(q, main_rcode, 900, 900)).await;
            let fall = spawn_mock(move |q| {
                MessageBuilder::new_vec()
                    .start_answer(q, fall_rcode)
                    .unwrap()
                    .finish()
            })
            .await;
            let mut h = mk(vec![main], vec![fall]);
            h.aaaa_mode = AaaaMode::Yes;
            let out = ask(&h, "nodata.example.com.", Rtype::AAAA, "127.0.0.1").await;
            assert_eq!(
                parse_resp(&out).header().rcode(),
                main_rcode,
                "{main_rcode} from the main DNS must survive a {fall_rcode} fallback"
            );
            assert_eq!(answer_count(&out), 0);
            assert!(
                cached_ttl(&h.fall_cache, "nodata.example.com.", Rtype::AAAA).is_none(),
                "an error code is not an answer to cache"
            );
        }
    }

    #[tokio::test]
    async fn a_fallback_error_is_still_served_when_the_main_dns_has_nothing() {
        let fall = spawn_mock(|q| {
            MessageBuilder::new_vec()
                .start_answer(q, Rcode::SERVFAIL)
                .unwrap()
                .finish()
        })
        .await;
        let h = mk(dead(), vec![fall]);
        let out = ask(&h, "broken.example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::SERVFAIL);
        // Served, but not remembered: the next client must get a fresh try
        // rather than the same failure out of the cache.
        assert!(
            cached_ttl(&h.fall_cache, "broken.example.com.", Rtype::A).is_none(),
            "an error code must not be cached"
        );
    }

    /// force_fall clients never consult the main DNS, so `fall_cache` is the
    /// only cache they read: the negative policy has to reach it too.
    #[tokio::test]
    async fn a_fallback_only_client_gets_the_same_negative_policy() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([1, 2, 3, 4], 300)])).await;
        let fall = spawn_mock(|q| negative(q, Rcode::NXDOMAIN, 86_400, 86_400)).await;
        let mut h = mk(vec![main], vec![fall]);
        h.force_fall = ForceFallMatcher {
            include: vec![crate::forcefall::IpPrefix::new(
                "127.0.0.1".parse().unwrap(),
                32,
            )],
            negate: vec![],
        };
        let out = ask(&h, "gone.example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NXDOMAIN);
        assert!(
            h.cache.is_empty(),
            "a forced route must not touch the main cache"
        );
        let ttl = cached_ttl(&h.fall_cache, "gone.example.com.", Rtype::A).expect("cached");
        assert!(
            ttl <= crate::cache::NEG_TTL_FLOOR,
            "a fallback-only client's negative must not stick for a day either (got {ttl}s)"
        );
        assert_eq!(
            next_negative_ttl(&h.fall_cache, "gone.example.com.", Rtype::A),
            crate::cache::NEG_TTL_FLOOR * 2,
            "and it escalates the same way when the name keeps coming back"
        );
    }

    /// A UDP mock that waits before answering with `ip`, and counts how many
    /// queries it was asked.
    async fn spawn_delayed_mock(delay: Duration, ip: [u8; 4]) -> (String, Arc<AtomicU32>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let asked = Arc::new(AtomicU32::new(0));
        let seen = asked.clone();
        let sock = Arc::new(sock);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(msg) = crate::dns::parse(buf[..n].to_vec()) else {
                    continue;
                };
                let sock = sock.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock
                        .send_to(&answer(&msg, Rcode::NOERROR, &[(ip, 300)]), peer)
                        .await;
                });
            }
        });
        (format!("udp://{addr}"), asked)
    }

    /// A UDP mock that never answers, but counts.
    async fn spawn_silent_mock() -> (String, Arc<AtomicU32>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let asked = Arc::new(AtomicU32::new(0));
        let seen = asked.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while sock.recv_from(&mut buf).await.is_ok() {
                seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        (format!("udp://{addr}"), asked)
    }

    fn first_addr(bytes: &[u8]) -> Option<[u8; 4]> {
        parse_resp(bytes)
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .next()
            .and_then(|r| r.ok())
            .and_then(|r| match r.data() {
                AllRecordData::A(a) => Some(a.addr().octets()),
                _ => None,
            })
    }

    /// The point of hedging: past the threshold the main query is not thrown
    /// away, so an answer that arrives while the fallback is still in flight
    /// is still the one the client gets.
    #[tokio::test]
    async fn a_slow_main_still_wins_when_it_beats_the_fallback() {
        let (main, _) = spawn_delayed_mock(Duration::from_millis(250), [1, 1, 1, 1]).await;
        let (fall, fall_asked) = spawn_delayed_mock(Duration::from_millis(600), [2, 2, 2, 2]).await;
        let h = mk_timed(vec![main], vec![fall], 100, 1500, 1200);

        let out = ask(&h, "slow.example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(
            first_addr(&out),
            Some([1, 1, 1, 1]),
            "the main answered before the fallback and must win"
        );
        assert_eq!(
            fall_asked.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the fallback was started at the threshold"
        );
        // A main answer is a main answer: it belongs in the main cache, with
        // its own TTL, not in the failover one.
        assert_eq!(first_ttl(&out), Some(300));
        assert!(!h.cache.is_empty(), "cached as a main answer");
        assert!(h.fall_cache.is_empty(), "and not as a fallback answer");
    }

    #[tokio::test]
    async fn the_fallback_wins_when_the_main_stays_silent() {
        let (main, _) = spawn_silent_mock().await;
        let (fall, _) = spawn_delayed_mock(Duration::from_millis(10), [2, 2, 2, 2]).await;
        let h = mk_timed(vec![main], vec![fall], 120, 1500, 1200);

        let started = std::time::Instant::now();
        let out = ask(&h, "silent.example.com.", Rtype::A, "127.0.0.1").await;
        let took = started.elapsed();
        assert_eq!(first_addr(&out), Some([2, 2, 2, 2]));
        // Failover answers reach the client with TTL=1 so it rechecks soon.
        assert_eq!(first_ttl(&out), Some(1));
        assert!(
            took < Duration::from_millis(600),
            "the client must not wait past the threshold plus the fallback's own time ({took:?})"
        );
    }

    /// Hedging must not add upstream load: a main that answers in time means
    /// the fallback is never asked at all.
    #[tokio::test]
    async fn a_main_that_answers_in_time_never_reaches_the_fallback() {
        let (main, _) = spawn_delayed_mock(Duration::from_millis(10), [1, 1, 1, 1]).await;
        let (fall, fall_asked) = spawn_delayed_mock(Duration::from_millis(10), [2, 2, 2, 2]).await;
        let h = mk_timed(vec![main], vec![fall], 300, 1500, 1200);

        for _ in 0..3 {
            let out = ask(&h, "quick.example.com.", Rtype::A, "127.0.0.1").await;
            assert_eq!(first_addr(&out), Some([1, 1, 1, 1]));
        }
        assert_eq!(
            fall_asked.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "no fallback query may be sent while the main is answering in time"
        );
    }

    /// The hedge checks the fallback cache before putting a query on the wire,
    /// and the fallback stage must not then ask a second time.
    #[tokio::test]
    async fn the_hedge_takes_the_fallback_cache_over_a_second_query() {
        let (main, _) = spawn_silent_mock().await;
        let (fall, fall_asked) = spawn_delayed_mock(Duration::from_millis(10), [2, 2, 2, 2]).await;
        let h = mk_timed(vec![main], vec![fall], 100, 1500, 1200);

        let out = ask(&h, "cached.example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(first_addr(&out), Some([2, 2, 2, 2]));
        assert_eq!(fall_asked.load(std::sync::atomic::Ordering::Relaxed), 1);

        let out = ask(&h, "cached.example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(first_addr(&out), Some([2, 2, 2, 2]));
        assert_eq!(
            fall_asked.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the cached fallback answer must be reused, not re-fetched"
        );
    }

    /// The breaker is what keeps a dead main DNS from costing every query the
    /// threshold. Hedging must not blind it: the abandoned main queries still
    /// run to their deadline and report back.
    #[tokio::test]
    async fn a_dead_main_still_trips_the_breaker() {
        let (main, _) = spawn_silent_mock().await;
        let (fall, _) = spawn_delayed_mock(Duration::from_millis(5), [2, 2, 2, 2]).await;
        let h = mk_timed(vec![main], vec![fall], 60, 250, 1200);

        for i in 0..6 {
            let out = ask(&h, &format!("dead{i}.example.com."), Rtype::A, "127.0.0.1").await;
            assert_eq!(first_addr(&out), Some([2, 2, 2, 2]));
        }
        // The queries the fallback outran are still running; they trip the
        // breaker when they hit the main's deadline.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            h.main.breaker_is_open(),
            "a main that never answers must still be recognised as down"
        );
    }

    /// The other half of that bargain: a main that is merely slower than the
    /// threshold is alive, and must not be cut off.
    #[tokio::test]
    async fn a_slow_but_alive_main_never_trips_the_breaker() {
        let (main, _) = spawn_delayed_mock(Duration::from_millis(120), [1, 1, 1, 1]).await;
        let (fall, _) = spawn_delayed_mock(Duration::from_millis(500), [2, 2, 2, 2]).await;
        let h = mk_timed(vec![main], vec![fall], 60, 900, 1200);

        for i in 0..6 {
            let out = ask(&h, &format!("slow{i}.example.com."), Rtype::A, "127.0.0.1").await;
            assert_eq!(
                first_addr(&out),
                Some([1, 1, 1, 1]),
                "query {i}: the main answered, late but alive"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !h.main.breaker_is_open(),
            "being slower than the threshold is not a failure"
        );
    }

    // ---- static rewrites (no upstream) ----

    #[tokio::test]
    async fn aaaa_block_returns_empty_noerror() {
        let h = mk(dead(), dead());
        let out = ask(&h, "example.com.", Rtype::AAAA, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NOERROR);
        assert_eq!(answer_count(&out), 0);
    }

    #[tokio::test]
    async fn svcb_blocked() {
        let h = mk(dead(), dead());
        let out = ask(&h, "example.com.", Rtype::SVCB, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NOERROR);
        assert_eq!(answer_count(&out), 0);
    }

    #[tokio::test]
    async fn hosts_forward_hit() {
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert("host.lan.".to_string(), vec!["1.2.3.4".parse().unwrap()]);
        let resolver = PtrResolver::new(vec![], vec![], AutoDetect::none(), &statics).map(Arc::new);
        let mut h = mk(dead(), dead());
        h.resolver = resolver;
        let out = ask(&h, "host.lan.", Rtype::A, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NOERROR);
        assert_eq!(answer_count(&out), 1);
        assert_eq!(first_ttl(&out), Some(300));
    }

    /// A name whose entry holds both families answers each question with its
    /// own family only, and echoes the question's name as the client wrote it
    /// (some resolvers compare the echo case-sensitively as a spoofing check).
    #[tokio::test]
    async fn a_hosts_answer_carries_one_family_and_the_clients_own_name() {
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert(
            "both.lan.".to_string(),
            vec![
                "10.1.2.3".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                "10.1.2.4".parse().unwrap(),
            ],
        );
        let mut h = mk(dead(), dead());
        h.aaaa_mode = AaaaMode::Yes;
        h.resolver = PtrResolver::new(vec![], vec![], AutoDetect::none(), &statics).map(Arc::new);

        for (qtype, want) in [(Rtype::A, 2), (Rtype::AAAA, 1)] {
            let out = ask(&h, "BoTh.LaN.", qtype, "127.0.0.1").await;
            assert_eq!(answer_count(&out), want, "{qtype}");
            let resp = parse_resp(&out);
            for rec in resp.answer().unwrap().limit_to::<AllRecordData<_, _>>() {
                let rec = rec.unwrap();
                assert_eq!(rec.rtype(), qtype, "answered with the other family");
                assert_eq!(
                    rec.owner().to_name::<Vec<u8>>().as_slice(),
                    Name::<Vec<u8>>::from_str("BoTh.LaN.").unwrap().as_slice(),
                    "the owner must echo the question's own bytes"
                );
            }
        }
    }

    /// Several addresses for one name are handed out in varying order, which
    /// is the only load balancing a hosts entry gets.
    #[tokio::test]
    async fn a_multi_address_hosts_answer_is_ordered_differently_over_time() {
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert(
            "many.lan.".to_string(),
            (0..4)
                .map(|i| IpAddr::V4(std::net::Ipv4Addr::new(10, 4, 0, i)))
                .collect(),
        );
        let mut h = mk(dead(), dead());
        h.resolver = PtrResolver::new(vec![], vec![], AutoDetect::none(), &statics).map(Arc::new);
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let out = ask(&h, "many.lan.", Rtype::A, "127.0.0.1").await;
            assert_eq!(answer_count(&out), 4);
            let resp = parse_resp(&out);
            let order: Vec<u8> = resp
                .answer()
                .unwrap()
                .limit_to::<AllRecordData<_, _>>()
                .map(|r| match r.unwrap().data() {
                    AllRecordData::A(a) => a.addr().octets()[3],
                    other => panic!("unexpected record {other}"),
                })
                .collect();
            seen.insert(order);
        }
        assert!(seen.len() > 1, "every answer came back in the same order");
    }

    /// An entry too large for the inline writer still gets answered: the
    /// record path picks it up, including the compression and truncation the
    /// writer has no way to do.
    #[tokio::test]
    async fn a_hosts_entry_past_the_inline_writer_is_still_answered() {
        let ips: Vec<IpAddr> = (0..40)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, i)))
            .collect();
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert("wide.lan.".to_string(), ips);
        let mut h = mk(dead(), dead());
        h.resolver = PtrResolver::new(vec![], vec![], AutoDetect::none(), &statics).map(Arc::new);

        let tcp = h
            .process(
                client_query("wide.lan.", Rtype::A),
                "127.0.0.1".parse().unwrap(),
                false,
            )
            .await
            .expect("a response");
        assert_eq!(parse_resp(&tcp).header().rcode(), Rcode::NOERROR);
        assert_eq!(answer_count(&tcp), 40);
        assert_eq!(first_ttl(&tcp), Some(LOCAL_TTL));

        // Over UDP the same answer overflows and comes back truncated.
        let udp = h
            .process(
                client_query("wide.lan.", Rtype::A),
                "127.0.0.1".parse().unwrap(),
                true,
            )
            .await
            .expect("a response");
        let resp = parse_resp(&udp);
        assert_eq!(resp.header().rcode(), Rcode::NOERROR);
        assert!(udp.len() <= usize::from(dns::MAX_UDP_RESPONSE));
        assert!(
            answer_count(&udp) > 0 && (answer_count(&udp) < 40) == resp.header().tc(),
            "a dropped record must set TC"
        );
    }

    #[tokio::test]
    async fn bogus_priv_nxdomain() {
        let h = mk(dead(), dead());
        let out = ask(&h, "1.1.168.192.in-addr.arpa.", Rtype::PTR, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NXDOMAIN);
    }

    // ---- message hygiene ----

    #[tokio::test]
    async fn qr_response_is_dropped() {
        let h = mk(dead(), dead());
        let mut q = client_query("example.com.", Rtype::A);
        q[2] |= 0x80; // QR=1: a response, not a query
        let out = h.process(q, "127.0.0.1".parse().unwrap(), true).await;
        assert!(out.is_none(), "a response must be dropped, not answered");
    }

    #[tokio::test]
    async fn non_query_opcode_gets_notimp() {
        let h = mk(dead(), dead());
        let mut q = client_query("example.com.", Rtype::A);
        q[2] |= 0x28; // opcode 5 (UPDATE), RD preserved
        let out = h
            .process(q, "127.0.0.1".parse().unwrap(), true)
            .await
            .expect("a response");
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NOTIMP);
        assert_eq!(answer_count(&out), 0);
    }

    #[tokio::test]
    async fn formerr_echoes_edns() {
        // Two questions → FORMERR, but the client's OPT is still echoed
        // (RFC 6891 §7).
        let h = mk(dead(), dead());
        let mut b = MessageBuilder::new_vec();
        b.header_mut().set_rd(true);
        let mut q = b.question();
        q.push((Name::<Vec<u8>>::from_str("a.example.").unwrap(), Rtype::A))
            .unwrap();
        q.push((Name::<Vec<u8>>::from_str("b.example.").unwrap(), Rtype::A))
            .unwrap();
        let mut add = q.additional();
        add.opt(|opt| {
            opt.set_udp_payload_size(1232);
            Ok(())
        })
        .unwrap();
        let out = h
            .process(add.finish(), "127.0.0.1".parse().unwrap(), true)
            .await
            .expect("a response");
        let resp = parse_resp(&out);
        assert_eq!(resp.header().rcode(), Rcode::FORMERR);
        assert!(resp.opt().is_some(), "OPT echoed per RFC 6891");
    }

    // ---- routing / forwarding (mock upstreams) ----

    #[tokio::test]
    async fn forward_noerror_is_cached() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([1, 2, 3, 4], 60)])).await;
        let h = mk(vec![main], dead());
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(answer_count(&out), 1);
        assert_eq!(first_ttl(&out), Some(60));
        // The NOERROR+answer was stored.
        let key = CacheKey::new(
            b"\x07example\x03com\x00".to_vec(),
            Rtype::A.to_int(),
            Class::IN.to_int(),
        );
        assert!(h.cache.get(&key).is_some());
    }

    #[tokio::test]
    async fn cache_hit_served_without_upstream() {
        // Pre-populate; upstreams are dead, so a response proves a cache read.
        let h = mk(dead(), dead());
        let key = CacheKey::new(
            b"\x07example\x03com\x00".to_vec(),
            Rtype::A.to_int(),
            Class::IN.to_int(),
        );
        h.cache.store(
            key,
            Arc::new(CachedMsg {
                rcode: Rcode::NOERROR,
                answers: vec![a_rec("example.com.", [9, 9, 9, 9], 200)],
                authority: vec![],
                additional: vec![],
            }),
            200,
        );
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(answer_count(&out), 1);
        // Cache read rewrites TTL to the remaining lifetime (<= stored).
        assert!(matches!(first_ttl(&out), Some(t) if (1..=200).contains(&t)));
    }

    #[tokio::test]
    async fn force_fall_uses_the_fallback_cache_not_the_main_one() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([1, 1, 1, 1], 60)])).await;
        let fall = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])).await;
        let mut h = mk(vec![main], vec![fall]);
        h.force_fall
            .include
            .push(parse_prefix("127.0.0.1/32").unwrap());
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        // Policy-routed clients keep the upstream TTL (only failover gets 1).
        assert_eq!(first_ttl(&out), Some(60));
        // The main cache stays clean: a fallback answer must never be visible
        // to main-preferring clients.
        assert!(h.cache.is_empty());
        // …but the answer is cached, in the fallback cache, with the upstream's
        // own TTL, so repeat queries from policy-routed clients are served
        // locally instead of hitting the fallback upstream every time.
        assert_eq!(h.fall_cache.len(), 1);
    }

    #[tokio::test]
    async fn hook_down_fallback_ttl_stays_short() {
        let fall = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])).await;
        let mut h = mk(dead(), vec![fall]);
        h.hook_failed = Some(Arc::new(AtomicBool::new(true)));
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        // Failover (hook-down) answers stay TTL=1 for fast switch-back.
        assert_eq!(first_ttl(&out), Some(1));
    }

    #[tokio::test]
    async fn main_nodata_prefers_fallback_answer() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[])).await; // NODATA
        let fall = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])).await;
        let h = mk(vec![main], vec![fall]);
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(answer_count(&out), 1);
        assert_eq!(first_ttl(&out), Some(1)); // served from fallback
    }

    #[tokio::test]
    async fn both_nodata_yields_nodata() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[])).await;
        let fall = spawn_mock(|q| answer(q, Rcode::NOERROR, &[])).await;
        let h = mk(vec![main], vec![fall]);
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NOERROR);
        assert_eq!(answer_count(&out), 0);
    }

    #[tokio::test]
    async fn trust_rcode_skips_fallback() {
        // Main NXDOMAIN is trusted; fallback (which would answer) must be ignored.
        let main = spawn_mock(|q| answer(q, Rcode::NXDOMAIN, &[])).await;
        let fall = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])).await;
        let mut h = mk(vec![main], vec![fall]);
        h.trust_rcodes.insert(u8::from(Rcode::NXDOMAIN));
        let out = ask(&h, "nope.example.", Rtype::A, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NXDOMAIN);
        assert_eq!(answer_count(&out), 0);
    }

    #[tokio::test]
    async fn paopao_dns_forces_main_even_under_force_fall() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([1, 1, 1, 1], 60)])).await;
        let fall = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])).await;
        let mut h = mk(vec![main], vec![fall]);
        h.force_fall
            .include
            .push(parse_prefix("127.0.0.1/32").unwrap());
        let out = ask(&h, "paopao.dns.", Rtype::A, "127.0.0.1").await;
        // Main is used, so the TTL is preserved (not the fallback's forced 1).
        assert_eq!(first_ttl(&out), Some(60));
    }

    // ---- pure logic ----

    #[test]
    fn rcode_label_maps() {
        assert_eq!(rcode_label(Rcode::NOERROR, false), "NOERROR");
        assert_eq!(rcode_label(Rcode::NOERROR, true), "NODATA");
        assert_eq!(rcode_label(Rcode::NXDOMAIN, false), "NXDOMAIN");
    }

    #[test]
    fn cname_chain_followed() {
        let answers = vec![
            cname_rec("www.example.com.", "cdn.example.net."),
            cname_rec("cdn.example.net.", "edge.example.org."),
            a_rec("edge.example.org.", [5, 6, 7, 8], 60),
        ];
        let end = resolve_cname_chain(&answers, b"\x03www\x07example\x03com\x00");
        assert_eq!(end, b"\x04edge\x07example\x03org\x00".to_vec());
    }

    #[test]
    fn cname_chain_cycle_terminates() {
        let answers = vec![
            cname_rec("a.example.", "b.example."),
            cname_rec("b.example.", "a.example."),
        ];
        // Hop count is bounded by the link count (2): a → b → a, then stop.
        let end = resolve_cname_chain(&answers, b"\x01a\x07example\x00");
        assert_eq!(end, b"\x01a\x07example\x00".to_vec());
    }

    fn info_for(name: &str, qtype: Rtype) -> OwnedQueryInfo {
        let req = Message::from_octets(client_query(name, qtype)).unwrap();
        let mut scratch = QueryScratch::new();
        dns::extract_query(&req, &mut scratch).unwrap().detach()
    }

    #[test]
    fn lite_collapses_cname_chain() {
        let h = mk(dead(), dead());
        let mut parts = Parts {
            rcode: Rcode::NOERROR,
            answers: vec![
                cname_rec("www.example.com.", "edge.example.org."),
                a_rec("edge.example.org.", [5, 6, 7, 8], 60),
            ],
            authority: vec![],
            additional: vec![],
        };
        let owned = info_for("www.example.com.", Rtype::A);
        h.apply_lite(&mut parts, &owned.info());
        assert_eq!(parts.answers.len(), 1);
        let r = &parts.answers[0];
        assert_eq!(r.rtype(), Rtype::A);
        // Owner rewritten back to the original qname.
        assert!(name_eq_lower(r.owner(), b"\x03www\x07example\x03com\x00"));
    }

    #[test]
    fn lite_keeps_all_when_chain_unresolvable() {
        // Final A missing → chain can't validate → no filtering (compat).
        let h = mk(dead(), dead());
        let mut parts = Parts {
            rcode: Rcode::NOERROR,
            answers: vec![cname_rec("www.example.com.", "edge.example.org.")],
            authority: vec![],
            additional: vec![],
        };
        let owned = info_for("www.example.com.", Rtype::A);
        h.apply_lite(&mut parts, &owned.info());
        assert_eq!(parts.answers.len(), 1);
        assert_eq!(parts.answers[0].rtype(), Rtype::CNAME);
    }

    #[test]
    fn hook_down_forces_fallback_route() {
        let flag = Arc::new(AtomicBool::new(true));
        let mut h = mk(dead(), dead());
        h.hook_failed = Some(flag);
        let owned = info_for("example.com.", Rtype::A);
        let route = h.resolve_route(owned.info().lower(), "127.0.0.1".parse().unwrap());
        assert!(route.force);
        assert_eq!(route.fall_label, "hook_fall");
    }

    // ---- local authority for hosts-defined names ----

    /// A name defined in `[hosts]`/hosts_file is authoritative for both A and
    /// AAAA. An IPv4-only entry — what every ad-blocking list looks like — must
    /// answer AAAA locally, or the block leaks over IPv6.
    #[tokio::test]
    async fn hosts_entry_is_authoritative_for_aaaa() {
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert(
            "ads.example.com.".to_string(),
            vec!["0.0.0.0".parse().unwrap()],
        );
        let hit = Arc::new(AtomicBool::new(false));
        let flag = hit.clone();
        // The mock would happily answer; reaching it at all is the failure.
        let main = spawn_mock(move |q| {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
            answer(q, Rcode::NOERROR, &[([1, 2, 3, 4], 60)])
        })
        .await;
        let mut h = mk(vec![main], dead());
        h.aaaa_mode = AaaaMode::Yes;
        h.resolver = PtrResolver::new(vec![], vec![], AutoDetect::none(), &statics).map(Arc::new);

        let a = ask(&h, "ads.example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(answer_count(&a), 1, "A comes from hosts");
        assert_eq!(first_ttl(&a), Some(300));

        let aaaa = ask(&h, "ads.example.com.", Rtype::AAAA, "127.0.0.1").await;
        assert_eq!(parse_resp(&aaaa).header().rcode(), Rcode::NOERROR);
        assert_eq!(answer_count(&aaaa), 0, "AAAA is a local NODATA");
        assert!(
            !hit.load(std::sync::atomic::Ordering::Relaxed),
            "a hosts-defined name must never reach the upstream"
        );

        // Matching is case-insensitive (the key owns the lower-cased name).
        let mixed = ask(&h, "ADS.Example.COM.", Rtype::AAAA, "127.0.0.1").await;
        assert_eq!(answer_count(&mixed), 0);
        assert!(
            !hit.load(std::sync::atomic::Ordering::Relaxed),
            "case must not change local-authority matching"
        );

        // The local NODATA is not cached: hosts answers are always live.
        assert!(h.cache.is_empty());
    }

    /// The authority is scoped to names the resolver actually knows: anything
    /// else must still be forwarded.
    #[tokio::test]
    async fn name_absent_from_hosts_still_forwards() {
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert(
            "ads.example.com.".to_string(),
            vec!["0.0.0.0".parse().unwrap()],
        );
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([1, 2, 3, 4], 60)])).await;
        let mut h = mk(vec![main], dead());
        h.aaaa_mode = AaaaMode::Yes;
        h.resolver = PtrResolver::new(vec![], vec![], AutoDetect::none(), &statics).map(Arc::new);

        let out = ask(&h, "other.example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(answer_count(&out), 1);
        assert_eq!(first_ttl(&out), Some(60), "answer came from the upstream");
    }

    /// The CNAME-chain walk in `apply_lite` matches lower-cased wire names, so
    /// it must be handed the lower-cased query name (which now lives in the
    /// cache key). A mixed-case query is the case that catches getting this
    /// wrong: the chain would silently fail to resolve and the final record
    /// would keep the chain-end owner instead of the queried name.
    #[tokio::test]
    async fn lite_collapses_cname_chain_for_mixed_case_query() {
        let main = spawn_mock(|q| {
            let name = q.sole_question().unwrap().qname().to_vec();
            let target = Name::<Vec<u8>>::from_str("edge.example.org.").unwrap();
            let mut b = MessageBuilder::new_vec()
                .start_answer(q, Rcode::NOERROR)
                .unwrap();
            b.push((
                &name,
                Class::IN,
                Ttl::from_secs(60),
                Cname::new(target.clone()),
            ))
            .unwrap();
            b.push((
                &target,
                Class::IN,
                Ttl::from_secs(60),
                A::from_octets(5, 6, 7, 8),
            ))
            .unwrap();
            b.finish()
        })
        .await;
        let h = mk(vec![main], dead()); // mk() enables lite
        let out = ask(&h, "WWW.Example.COM.", Rtype::A, "127.0.0.1").await;
        assert_eq!(answer_count(&out), 1, "lite keeps only the qtype record");
        let msg = parse_resp(&out);
        let rec = msg
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .next()
            .unwrap()
            .unwrap();
        let owner = rec.owner().to_string().to_ascii_lowercase();
        assert_eq!(
            owner.trim_end_matches('.'),
            "www.example.com",
            "chain end must be rewritten back to the queried name"
        );
    }

    // ---- fallback cache / failover behaviour ----

    fn answer_ip(bytes: &[u8]) -> [u8; 4] {
        let msg = parse_resp(bytes);
        let rec = msg
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .next()
            .expect("an answer")
            .expect("a parsable answer");
        match rec.data() {
            AllRecordData::A(a) => a.addr().octets(),
            _ => panic!("expected an A record"),
        }
    }

    /// While the hook says the main DNS is down, repeat queries are served from
    /// the fallback cache instead of hammering the fallback upstream — but the
    /// client still sees TTL=1 so it re-asks and lands back on the main DNS as
    /// soon as the hook clears.
    #[tokio::test]
    async fn hook_down_serves_repeat_queries_from_the_fallback_cache() {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = hits.clone();
        let fall = spawn_mock(move |q| {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])
        })
        .await;
        let mut h = mk(dead(), vec![fall]);
        h.hook_failed = Some(Arc::new(AtomicBool::new(true)));

        let a = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        let b = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the second query must come from the fallback cache"
        );
        assert_eq!(first_ttl(&a), Some(1), "failover answers stay TTL=1");
        assert_eq!(first_ttl(&b), Some(1), "including the cached one");
        assert!(h.cache.is_empty(), "main cache untouched during an outage");

        // The entry itself keeps the upstream's TTL — that split is the point.
        let key = CacheKey::new(
            b"\x07example\x03com\x00".to_vec(),
            Rtype::A.to_int(),
            Class::IN.to_int(),
        );
        let (_, ttl_left) = h
            .fall_cache
            .get(&key)
            .expect("stored in the fallback cache");
        assert!(
            ttl_left > 1,
            "cache holds the upstream TTL ({ttl_left}), not the client's 1"
        );
    }

    /// The two caches are partitioned by which upstream produced the answer, so
    /// a policy-routed client and a main-preferring client asking the same name
    /// must keep getting their own upstream's answer.
    #[tokio::test]
    async fn main_and_fallback_caches_do_not_cross_contaminate() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([1, 1, 1, 1], 60)])).await;
        let fall = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])).await;
        let mut h = mk(vec![main], vec![fall]);
        h.force_fall
            .include
            .push(parse_prefix("127.0.0.2/32").unwrap());

        // Policy-routed client primes the fallback cache…
        assert_eq!(
            answer_ip(&ask(&h, "example.com.", Rtype::A, "127.0.0.2").await),
            [2, 2, 2, 2]
        );
        // …a main-preferring client still gets the main DNS's answer…
        assert_eq!(
            answer_ip(&ask(&h, "example.com.", Rtype::A, "127.0.0.1").await),
            [1, 1, 1, 1]
        );
        // …and the main answer never leaks back to the policy-routed client.
        assert_eq!(
            answer_ip(&ask(&h, "example.com.", Rtype::A, "127.0.0.2").await),
            [2, 2, 2, 2]
        );
        assert_eq!(h.cache.len(), 1);
        assert_eq!(h.fall_cache.len(), 1);
    }

    /// Every upstream hop draws its own transaction ID (RFC 5452 §9). Sampled
    /// over several queries so a chance 1-in-65536 collision cannot fail the
    /// run, while a shared ID — which makes *every* pair identical — does.
    #[tokio::test]
    async fn each_upstream_hop_draws_its_own_transaction_id() {
        let ids: Arc<std::sync::Mutex<Vec<(bool, u16)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let i1 = ids.clone();
        let main = spawn_mock(move |q| {
            i1.lock().unwrap().push((true, q.header().id()));
            answer(q, Rcode::SERVFAIL, &[])
        })
        .await;
        let i2 = ids.clone();
        let fall = spawn_mock(move |q| {
            i2.lock().unwrap().push((false, q.header().id()));
            answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])
        })
        .await;
        let h = mk(vec![main], vec![fall]);

        const ROUNDS: usize = 5;
        for i in 0..ROUNDS {
            let name = format!("q{i}.example.com.");
            let _ = ask(&h, &name, Rtype::A, "127.0.0.1").await;
        }
        let seen = ids.lock().unwrap().clone();
        assert_eq!(seen.len(), ROUNDS * 2, "both hops ran every round");
        let main_ids: Vec<u16> = seen.iter().filter(|(m, _)| *m).map(|(_, id)| *id).collect();
        let fall_ids: Vec<u16> = seen
            .iter()
            .filter(|(m, _)| !*m)
            .map(|(_, id)| *id)
            .collect();
        let shared = main_ids
            .iter()
            .zip(&fall_ids)
            .filter(|(a, b)| a == b)
            .count();
        assert!(
            shared <= 1,
            "hops reused the same id in {shared}/{ROUNDS} rounds: {main_ids:?} vs {fall_ids:?}"
        );
    }

    /// With no hook configured — the default — a dead main DNS must not turn
    /// every client retry into a fallback-upstream query. The fallback stage
    /// reads the fallback cache first.
    #[tokio::test]
    async fn fallback_stage_reads_the_fallback_cache() {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = hits.clone();
        let fall = spawn_mock(move |q| {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])
        })
        .await;
        let h = mk(dead(), vec![fall]); // main unreachable, no hook
        for i in 0..3 {
            let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
            assert_eq!(answer_count(&out), 1, "round {i}");
            assert_eq!(first_ttl(&out), Some(1), "failover answers stay TTL=1");
        }
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the fallback upstream must be asked once, not once per retry"
        );
    }

    /// An answer served *from* the fallback cache must not be written back:
    /// the stored records carry their original TTLs, so re-storing would reset
    /// the entry's expiry and a name queried every second would never age out.
    #[tokio::test]
    async fn serving_from_the_fallback_cache_does_not_extend_the_entry() {
        let h = mk(dead(), dead()); // both dead: only a cache hit can answer
        let key = CacheKey::new(
            b"\x07example\x03com\x00".to_vec(),
            Rtype::A.to_int(),
            Class::IN.to_int(),
        );
        // Records carry a long TTL, but this entry only has 2s of life left.
        h.fall_cache.store(
            key.clone(),
            Arc::new(CachedMsg {
                rcode: Rcode::NOERROR,
                answers: vec![a_rec("example.com.", [2, 2, 2, 2], 300)],
                authority: vec![],
                additional: vec![],
            }),
            2,
        );
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(answer_count(&out), 1, "served from the fallback cache");
        assert_eq!(first_ttl(&out), Some(1), "failover answers stay TTL=1");
        let (_, ttl_left) = h.fall_cache.get(&key).expect("entry survives");
        assert!(
            ttl_left <= 2,
            "expiry must not be pushed out by a cache-served answer (ttl_left={ttl_left})"
        );
    }

    /// RFC 8482: an ANY query is answered with a synthesised HINFO and never
    /// forwarded.
    ///
    /// Checked under both `lite` settings: the answer is produced in the static
    /// rewrite stage, before any route decision or upstream query, so the two
    /// must be indistinguishable.
    #[tokio::test]
    async fn any_queries_get_the_rfc8482_hinfo_whatever_lite_says() {
        for lite in [true, false] {
            let hit = Arc::new(AtomicBool::new(false));
            let flag = hit.clone();
            let main = spawn_mock(move |q| {
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
                answer(q, Rcode::NOERROR, &[([1, 2, 3, 4], 60)])
            })
            .await;
            let mut h = mk(vec![main], dead());
            h.lite = lite;
            let out = ask(&h, "example.com.", Rtype::ANY, "127.0.0.1").await;

            let msg = parse_resp(&out);
            assert_eq!(msg.header().rcode(), Rcode::NOERROR, "lite={lite}");
            assert!(
                !hit.load(std::sync::atomic::Ordering::Relaxed),
                "ANY must not reach the upstream (lite={lite})"
            );
            let rec = msg
                .answer()
                .unwrap()
                .limit_to::<AllRecordData<_, _>>()
                .next()
                .expect("one answer")
                .expect("parses");
            assert_eq!(rec.rtype(), Rtype::HINFO, "lite={lite}");
            assert_eq!(rec.ttl().as_secs(), ANY_HINFO_TTL);
            match rec.data() {
                AllRecordData::Hinfo(hi) => {
                    assert_eq!(hi.cpu().as_slice(), b"RFC8482");
                    assert!(hi.os().as_slice().is_empty());
                }
                other => panic!("expected HINFO, got {other:?}"),
            }
            // Synthesised, so nothing goes into either cache.
            assert!(h.cache.is_empty() && h.fall_cache.is_empty(), "lite={lite}");
        }
    }

    /// The ANY handling must not touch any other qtype.
    #[tokio::test]
    async fn non_any_queries_still_forward() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([1, 2, 3, 4], 60)])).await;
        let h = mk(vec![main], dead());
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        assert_eq!(answer_count(&out), 1);
        assert_eq!(first_ttl(&out), Some(60));
    }

    // ---- hot-path resource use ----

    fn client_query_with_edns(name: &str, qtype: Rtype) -> Vec<u8> {
        let mut b = MessageBuilder::new_vec();
        b.header_mut().set_rd(true);
        let mut q = b.question();
        q.push((Name::<Vec<u8>>::from_str(name).unwrap(), qtype))
            .unwrap();
        let mut add = q.additional();
        add.opt(|opt| {
            opt.set_udp_payload_size(1232);
            Ok(())
        })
        .unwrap();
        add.finish()
    }

    /// The paths answered inline in the UDP receive loop must not touch the
    /// heap: with one reply buffer kept by the loop, every allocation there is
    /// one more trip through the process-wide allocator for every datagram,
    /// on every core.
    #[test]
    fn answered_inline_queries_do_not_allocate() {
        let mut h = mk(dead(), dead());
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert(
            "blocked.ads.example.".to_string(),
            vec!["0.0.0.0".parse().unwrap(), "10.1.2.3".parse().unwrap()],
        );
        statics.insert(
            "six.ads.example.".to_string(),
            vec!["2001:db8::1".parse().unwrap()],
        );
        h.resolver = PtrResolver::new(vec![], vec![], AutoDetect::none(), &statics).map(Arc::new);
        let store = |name: &str, answers: usize| {
            let mut lower = Name::<Vec<u8>>::from_str(name).unwrap().as_slice().to_vec();
            lower.make_ascii_lowercase();
            h.cache.store(
                CacheKey::new(lower, Rtype::A.to_int(), Class::IN.to_int()),
                Arc::new(CachedMsg {
                    rcode: Rcode::NOERROR,
                    answers: (0..answers)
                        .map(|i| a_rec(name, [10, 0, 0, i as u8], 300))
                        .collect(),
                    authority: vec![],
                    additional: vec![],
                }),
                300,
            );
        };
        store("one.example.com.", 1);
        store("many.example.com.", 6);

        let mut notimp = client_query("one.example.com.", Rtype::A);
        notimp[2] |= 0x28; // opcode 5 (UPDATE)
        let cases: [(&str, Vec<u8>); 12] = [
            ("cache hit", client_query("one.example.com.", Rtype::A)),
            (
                "cache hit, mixed case, EDNS",
                client_query_with_edns("ONE.Example.com.", Rtype::A),
            ),
            (
                "cache hit, shuffled answers",
                client_query("many.example.com.", Rtype::A),
            ),
            (
                "AAAA block",
                client_query_with_edns("blocked.example.com.", Rtype::AAAA),
            ),
            (
                "SVCB block",
                client_query("blocked.example.com.", Rtype::SVCB),
            ),
            (
                "HTTPS block",
                client_query_with_edns("blocked.example.com.", Rtype::HTTPS),
            ),
            (
                "bogus-priv v4",
                client_query("5.1.168.192.in-addr.arpa.", Rtype::PTR),
            ),
            (
                "bogus-priv v6",
                client_query(
                    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
                    Rtype::PTR,
                ),
            ),
            ("NOTIMP", notimp),
            ("hosts hit", client_query("blocked.ads.example.", Rtype::A)),
            (
                "hosts hit, several addresses, EDNS",
                client_query_with_edns("Blocked.Ads.Example.", Rtype::A),
            ),
            (
                "hosts hit, AAAA",
                client_query_with_edns("six.ads.example.", Rtype::AAAA),
            ),
        ];

        let client: IpAddr = "192.168.1.20".parse().unwrap();
        let mut out = Vec::with_capacity(usize::from(dns::MAX_UDP_RESPONSE));
        // The counter itself must work, or every check below passes vacuously.
        let before = alloc_count::allocations();
        drop(std::hint::black_box(Vec::<u8>::with_capacity(16)));
        assert!(
            alloc_count::allocations() > before,
            "allocation counter is dead"
        );

        for (label, query) in &cases {
            // First pass settles anything initialized lazily on first use.
            assert!(
                matches!(
                    h.process_fast(query, client, true, &mut out),
                    FastOutcome::Reply
                ),
                "{label}: expected an inline reply"
            );
            let before = alloc_count::allocations();
            for _ in 0..16 {
                let outcome = h.process_fast(query, client, true, &mut out);
                assert!(matches!(outcome, FastOutcome::Reply), "{label}");
            }
            assert_eq!(
                alloc_count::allocations(),
                before,
                "{label}: the inline path allocated"
            );
            assert!(parse_resp(&out).header().qr(), "{label}: a real response");
        }
    }

    /// A cached entry can live for a day, so it must not keep the spare
    /// capacity its record vectors picked up while being built and filtered —
    /// in particular the additional section an upstream OPT leaves behind
    /// empty, which every EDNS-speaking upstream produces.
    #[tokio::test]
    async fn cached_entries_hold_no_spare_capacity() {
        let main = spawn_mock(|q| {
            let mut b = MessageBuilder::new_vec()
                .start_answer(q, Rcode::NOERROR)
                .unwrap();
            let name = q.sole_question().unwrap().qname().to_vec();
            b.push((
                &name,
                Class::IN,
                Ttl::from_secs(60),
                A::from_octets(1, 2, 3, 4),
            ))
            .unwrap();
            let mut add = b.additional();
            add.opt(|opt| {
                opt.set_udp_payload_size(1232);
                Ok(())
            })
            .unwrap();
            add.finish()
        })
        .await;
        for lite in [true, false] {
            let mut h = mk(vec![main.clone()], dead());
            h.lite = lite;
            let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
            assert_eq!(answer_count(&out), 1);
            let key = CacheKey::new(
                b"\x07example\x03com\x00".to_vec(),
                Rtype::A.to_int(),
                Class::IN.to_int(),
            );
            let (entry, _) = h.cache.get(&key).expect("cached");
            assert_eq!(entry.answers.len(), 1, "lite={lite}");
            assert!(entry.additional.is_empty(), "lite={lite}");
            for (section, records) in [
                ("answer", &entry.answers),
                ("authority", &entry.authority),
                ("additional", &entry.additional),
            ] {
                assert_eq!(
                    records.capacity(),
                    records.len(),
                    "lite={lite}: {section} section keeps spare capacity"
                );
            }
        }
    }
}
