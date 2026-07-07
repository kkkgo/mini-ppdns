// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! The request-processing pipeline.
//!
//! Order: static rewrites → route decision → cache → main DNS → fallback.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use domain::base::iana::{Class, Opcode, Rcode, Rtype};
use domain::base::{Message, Ttl};
use domain::rdata::{Aaaa, AllRecordData, Ptr, A};

use crate::cache::{Cache, CacheKey, CachedMsg};
use crate::dns::{self, ClientEdns, OwnedName, OwnedRecord, QueryInfo, ResponseData};
use crate::forcefall::ForceFallMatcher;
use crate::local_resolver::{hostname_to_name, is_private_ptr, PtrResolver};
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
    pub main: Forwarder,
    pub fallback: Forwarder,
    pub cache: Arc<Cache>,
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

impl Parts {
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
}

impl LocalResult {
    fn none() -> Self {
        LocalResult {
            handled: None,
            carry: None,
            carry_is_nodata: false,
        }
    }
}

/// The routing decision: whether to bypass the main DNS, and the log label to
/// use when the fallback answers.
struct RouteDecision {
    force: bool,
    fall_label: &'static str,
}

/// Human-readable rcode label for logs.
fn rcode_label(rcode: Rcode, empty_answer: bool) -> String {
    match rcode {
        Rcode::NOERROR if empty_answer => "NODATA".to_string(),
        Rcode::NOERROR => "NOERROR".to_string(),
        Rcode::NXDOMAIN => "NXDOMAIN".to_string(),
        Rcode::SERVFAIL => "SERVFAIL".to_string(),
        Rcode::REFUSED => "REFUSED".to_string(),
        Rcode::FORMERR => "FORMERR".to_string(),
        other => format!("RCODE_{}", u8::from(other)),
    }
}

const PAOPAO_DNS_WIRE: &[u8] = b"\x06paopao\x03dns\x00";

/// Parsed state carried from the synchronous fast path to the upstream (slow)
/// path, so nothing is parsed twice. Opaque outside this module.
pub struct PendingQuery {
    msg: Message<Vec<u8>>,
    info: QueryInfo,
    route: RouteDecision,
    key: CacheKey,
    udp_limit: Option<u16>,
}

/// Result of the synchronous fast path.
pub enum FastOutcome {
    /// Answered without upstream IO (None = drop the query).
    Done(Option<Vec<u8>>),
    /// Needs upstream IO; finish with `process_slow`. Boxed so the hot
    /// `Done` variant stays small.
    Pending(Box<PendingQuery>),
}

impl Handler {
    /// Process one query, returning the wire response to send (None = drop).
    pub async fn process(&self, req: Vec<u8>, client: IpAddr, is_udp: bool) -> Option<Vec<u8>> {
        match self.process_fast(req, client, is_udp) {
            FastOutcome::Done(resp) => resp,
            FastOutcome::Pending(p) => self.process_slow(p, client).await,
        }
    }

    /// The no-IO paths: parse, FORMERR, static rewrite (block/hosts/PTR), and
    /// cache hit. Synchronous and bounded (~µs), so the UDP receive loop can
    /// run it inline without spawning a task; only a `Pending` result pays the
    /// per-task scheduling cost.
    pub fn process_fast(&self, req: Vec<u8>, client: IpAddr, is_udp: bool) -> FastOutcome {
        let Ok(msg) = Message::from_octets(req) else {
            return FastOutcome::Done(None);
        };
        // A response must never be processed as a query (RFC 1035 §7.3):
        // answering one would forward it upstream and reply to the "client".
        if msg.header().qr() {
            return FastOutcome::Done(None);
        }
        // Non-QUERY opcodes (IQUERY/STATUS/NOTIFY/UPDATE) are not supported;
        // forwarding them as plain queries would silently change semantics.
        if msg.header().opcode() != Opcode::QUERY {
            return FastOutcome::Done(Some(self.reject(&msg, Rcode::NOTIMP, is_udp)));
        }
        let Some(info) = dns::extract_query(&msg) else {
            // No sole question → FORMERR.
            return FastOutcome::Done(Some(self.reject(&msg, Rcode::FORMERR, is_udp)));
        };

        let udp_limit = if is_udp {
            Some(dns::udp_response_limit(info.client_edns))
        } else {
            None
        };

        if let Some(resp) = self.try_static_rewrite(&msg, &info, client, udp_limit) {
            return FastOutcome::Done(Some(resp));
        }

        let route = self.resolve_route(&info, client);
        let key = CacheKey::with_hash(
            info.qname_lower.clone(),
            info.qtype.to_int(),
            info.qclass.to_int(),
            info.name_hash,
        );

        if !route.force {
            if let Some((cached, ttl_left)) = self.cache.get(&key) {
                let empty = cached.rcode == Rcode::NOERROR && cached.answers.is_empty();
                self.dlog(
                    "cache",
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
                return FastOutcome::Done(Some(
                    self.build_cached(&msg, &info, &cached, ttl_left, udp_limit),
                ));
            }
        }

        FastOutcome::Pending(Box::new(PendingQuery {
            msg,
            info,
            route,
            key,
            udp_limit,
        }))
    }

    /// Finish a query the fast path couldn't answer: forward to the main DNS
    /// and/or fallback upstreams.
    pub async fn process_slow(&self, p: Box<PendingQuery>, client: IpAddr) -> Option<Vec<u8>> {
        let PendingQuery {
            msg,
            info,
            route,
            key,
            udp_limit,
        } = *p;
        let query = dns::build_upstream_query(&info);
        let local = if route.force {
            LocalResult::none()
        } else {
            self.exec_local(&msg, &info, &key, &query, client, udp_limit)
                .await
        };
        if let Some(resp) = local.handled {
            return Some(resp);
        }
        Some(
            self.exec_fallback(&msg, &info, &key, &query, &route, client, local, udp_limit)
                .await,
        )
    }

    /// Build a question-echoing error response (FORMERR/NOTIMP). The client's
    /// EDNS is still echoed even though the query wasn't processed
    /// (RFC 6891 §7), and the UDP size budget still applies.
    fn reject(&self, msg: &Message<Vec<u8>>, rcode: Rcode, is_udp: bool) -> Vec<u8> {
        let edns = dns::edns_of(msg);
        let udp_limit = is_udp.then(|| dns::udp_response_limit(edns));
        self.build(msg, rcode, &Parts::empty(), edns, udp_limit, None, None)
    }

    /// Answers needing no upstream: AAAA/SVCB/HTTPS blocking, hosts forward
    /// lookups, local PTR, and bogus-priv.
    fn try_static_rewrite(
        &self,
        msg: &Message<Vec<u8>>,
        info: &QueryInfo,
        client: IpAddr,
        udp_limit: Option<u16>,
    ) -> Option<Vec<u8>> {
        let qt = info.qtype;
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
            return Some(self.build(
                msg,
                Rcode::NOERROR,
                &Parts::empty(),
                info.client_edns,
                udp_limit,
                None,
                Some(info.qtype),
            ));
        }

        // Forward lookup from hosts files / [hosts] config.
        if qt == Rtype::A || qt == Rtype::AAAA {
            if let Some(res) = &self.resolver {
                let ips = res.lookup_ip(&info.qname_lower, info.name_hash);
                if !ips.is_empty() {
                    if let Some(out) = self.hosts_response(msg, info, client, &ips, udp_limit) {
                        self.dlog("hosts", info, client, None, "NOERROR", None, None);
                        return Some(out);
                    }
                }
            }
        }

        // Local PTR, then bogus-priv.
        if qt == Rtype::PTR {
            if let Some(res) = &self.resolver {
                if let Some(host) = res.lookup(&info.qname_lower) {
                    if let Some(out) = self.ptr_response(msg, info, client, &host, udp_limit) {
                        self.dlog(
                            "local-ptr",
                            info,
                            client,
                            None,
                            "NOERROR",
                            None,
                            Some(&host),
                        );
                        return Some(out);
                    }
                }
            }
            if self.boguspriv && is_private_ptr(&info.qname.to_string()) {
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
                return Some(self.build(
                    msg,
                    Rcode::NXDOMAIN,
                    &Parts::empty(),
                    info.client_edns,
                    udp_limit,
                    None,
                    Some(info.qtype),
                ));
            }
        }
        None
    }

    /// Build a NOERROR response with A/AAAA records (TTL 300) for a hosts hit,
    /// filtering by qtype. Returns None if no record matches the qtype.
    fn hosts_response(
        &self,
        msg: &Message<Vec<u8>>,
        info: &QueryInfo,
        client: IpAddr,
        ips: &[std::net::IpAddr],
        udp_limit: Option<u16>,
    ) -> Option<Vec<u8>> {
        let mut answers = Vec::new();
        for ip in ips {
            match (info.qtype, ip) {
                (Rtype::A, std::net::IpAddr::V4(v4)) => {
                    let o = v4.octets();
                    answers.push(OwnedRecord::new(
                        info.qname.clone(),
                        Class::IN,
                        Ttl::from_secs(300),
                        AllRecordData::A(A::from_octets(o[0], o[1], o[2], o[3])),
                    ));
                }
                (Rtype::AAAA, std::net::IpAddr::V6(v6)) => {
                    answers.push(OwnedRecord::new(
                        info.qname.clone(),
                        Class::IN,
                        Ttl::from_secs(300),
                        AllRecordData::Aaaa(Aaaa::new(*v6)),
                    ));
                }
                _ => {}
            }
        }
        if answers.is_empty() {
            return None;
        }
        let parts = Parts {
            rcode: Rcode::NOERROR,
            answers,
            authority: Vec::new(),
            additional: Vec::new(),
        };
        let out = self.build(
            msg,
            Rcode::NOERROR,
            &parts,
            info.client_edns,
            udp_limit,
            None,
            Some(info.qtype),
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
        Some(out)
    }

    /// Build a NOERROR PTR response (TTL 300) for a local reverse hit.
    fn ptr_response(
        &self,
        msg: &Message<Vec<u8>>,
        info: &QueryInfo,
        client: IpAddr,
        hostname: &str,
        udp_limit: Option<u16>,
    ) -> Option<Vec<u8>> {
        let target = hostname_to_name(hostname)?;
        let rec = OwnedRecord::new(
            info.qname.clone(),
            Class::IN,
            Ttl::from_secs(300),
            AllRecordData::Ptr(Ptr::new(target)),
        );
        let parts = Parts {
            rcode: Rcode::NOERROR,
            answers: vec![rec],
            authority: Vec::new(),
            additional: Vec::new(),
        };
        let out = self.build(
            msg,
            Rcode::NOERROR,
            &parts,
            info.client_edns,
            udp_limit,
            None,
            Some(info.qtype),
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
        Some(out)
    }

    /// force_fall matcher + hook-down forcing + the `paopao.dns` always-main
    /// special case. `fall_label` is the route label used when the query is
    /// answered from the fallback ("fall" / "force_fall" / "hook_fall").
    fn resolve_route(&self, info: &QueryInfo, client: IpAddr) -> RouteDecision {
        let ff = self.force_fall.matches(client);
        let hook_down = self
            .hook_failed
            .as_ref()
            .map(|h| h.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false);
        let mut force = ff || hook_down;
        // paopao.dns always uses the primary DNS, overriding force_fall/hook.
        if force && info.qname_lower.eq_ignore_ascii_case(PAOPAO_DNS_WIRE) {
            force = false;
            return RouteDecision {
                force,
                fall_label: "fall",
            };
        }
        let fall_label = if !force {
            "fall"
        } else if hook_down {
            "hook_fall"
        } else {
            "force_fall"
        };
        RouteDecision { force, fall_label }
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
        info: &QueryInfo,
        client: IpAddr,
    ) {
        let Some(rep) = &self.pplog else {
            return;
        };
        let lvl = rep.level();
        let name = info.qname.to_string();
        let entry = crate::pplog::QueryEntry {
            client,
            qtype: info.qtype.to_int(),
            rcode,
            route,
            duration_ms: dur_ms,
            query_name: &name,
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
        info: &QueryInfo,
        client: IpAddr,
        upstream: Option<&str>,
        rcode: &str,
        dur: Option<Duration>,
        extra: Option<&str>,
    ) {
        if !log::debug_enabled() {
            return;
        }
        let domain = info.qname.to_string();
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

    async fn exec_local(
        &self,
        msg: &Message<Vec<u8>>,
        info: &QueryInfo,
        key: &CacheKey,
        query: &[u8],
        client: IpAddr,
        udp_limit: Option<u16>,
    ) -> LocalResult {
        let fr = self.main.exec(query).await;
        let up = fr.upstream.clone();
        let dur = Some(fr.duration);
        let dms = dur_to_ms(fr.duration);
        let Some(resp) = fr.response else {
            self.dlog("local", info, client, Some(&up), "timeout/error", dur, None);
            self.preport(ROUTE_LOCAL, RCODE_TIMEOUT, dms, &up, &[], &[], info, client);
            return LocalResult::none();
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
            let label = if parts.answers.is_empty() {
                format!("{}(trusted)", rcode_label(parts.rcode, false))
            } else {
                rcode_label(parts.rcode, false)
            };
            log_local(&label);
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
            self.store(key, parts, None);
            return LocalResult {
                handled: Some(out),
                carry: None,
                carry_is_nodata: false,
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
            self.store(key, parts, None);
            return LocalResult {
                handled: Some(out),
                carry: None,
                carry_is_nodata: false,
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
                self.store(key, parts, None);
                return LocalResult {
                    handled: Some(out),
                    carry: None,
                    carry_is_nodata: false,
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
        LocalResult {
            handled: None,
            carry: Some(parts),
            carry_is_nodata: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn exec_fallback(
        &self,
        msg: &Message<Vec<u8>>,
        info: &QueryInfo,
        key: &CacheKey,
        query: &[u8],
        route: &RouteDecision,
        client: IpAddr,
        local: LocalResult,
        udp_limit: Option<u16>,
    ) -> Vec<u8> {
        let fr = self.fallback.exec(query).await;
        let up = fr.upstream.clone();
        let dur = Some(fr.duration);
        let fall = fr.response.as_ref().map(Parts::from_msg);
        let fall_is_nodata = fall.as_ref().map(Parts::is_nodata).unwrap_or(false);
        let cache_writes = !route.force;
        let flabel = route.fall_label;

        // pplog reports the fallback query outcome (route byte from the label),
        // regardless of which response is ultimately served to the client.
        let flabel_byte = match flabel {
            "hook_fall" => ROUTE_HOOK_FALL,
            "force_fall" => ROUTE_FORCE_FALL,
            _ => ROUTE_FALL,
        };
        let dms = dur_to_ms(fr.duration);
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

        // NODATA preference: main NODATA beats a NODATA/absent fallback.
        if local.carry_is_nodata && (fall_is_nodata || fall.is_none()) {
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
            if cache_writes {
                self.store(key, np, None);
            }
            return out;
        }

        if let Some(mut fp) = fall {
            if self.lite {
                self.apply_lite(&mut fp, info);
            }
            let label = rcode_label(fp.rcode, fp.answers.is_empty());
            // Failover answers (main failed / hook-down) are short-lived (TTL=1)
            // so recovery switches back fast. force_fall is policy routing, not
            // failover: those clients always use the fallback, so their answers
            // keep the upstream TTLs — forcing TTL=1 would only make them
            // re-resolve every second, uncached.
            let ttl_override = if flabel == "force_fall" {
                None
            } else {
                Some(1)
            };
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
            if cache_writes {
                self.store(key, fp, ttl_override);
            }
            return out;
        }

        // Fallback failed entirely: surface the main-DNS response if we have one.
        if fr.had_error {
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
                if cache_writes {
                    self.store(key, lp, None);
                }
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
    fn apply_lite(&self, parts: &mut Parts, info: &QueryInfo) {
        let qtype = info.qtype;
        if qtype == Rtype::CNAME {
            parts.answers.retain(|r| r.rtype() == Rtype::CNAME);
            parts.authority.retain(|r| r.rtype() == Rtype::SOA);
            parts.additional.clear();
            return;
        }

        let final_name = resolve_cname_chain(&parts.answers, &info.qname_lower);
        let has_chain = final_name != info.qname_lower;
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
                    info.qname.clone(),
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

    fn store(&self, key: &CacheKey, parts: Parts, ttl_override: Option<u32>) {
        let ttl = ttl_override.unwrap_or_else(|| parts.min_ttl());
        let cached = Arc::new(CachedMsg {
            rcode: parts.rcode,
            answers: parts.answers,
            authority: parts.authority,
            additional: parts.additional,
        });
        self.cache.store(key.clone(), cached, ttl);
    }

    fn build_cached(
        &self,
        msg: &Message<Vec<u8>>,
        info: &QueryInfo,
        cached: &CachedMsg,
        ttl_left: u32,
        udp_limit: Option<u16>,
    ) -> Vec<u8> {
        let data = ResponseData {
            rcode: cached.rcode,
            answers: &cached.answers,
            authority: &cached.authority,
            additional: &cached.additional,
            ttl_override: Some(ttl_left),
            edns: info.client_edns,
            shuffle_qtype: Some(info.qtype),
        };
        dns::build_response(msg, &data, udp_limit)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        &self,
        msg: &Message<Vec<u8>>,
        rcode: Rcode,
        parts: &Parts,
        edns: Option<ClientEdns>,
        udp_limit: Option<u16>,
        ttl_override: Option<u32>,
        shuffle_qtype: Option<Rtype>,
    ) -> Vec<u8> {
        let data = ResponseData {
            rcode,
            answers: &parts.answers,
            authority: &parts.authority,
            additional: &parts.additional,
            ttl_override,
            edns,
            shuffle_qtype,
        };
        dns::build_response(msg, &data, udp_limit)
    }
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
    use crate::local_resolver::PtrResolver;
    use crate::upstream::{Forwarder, Upstream};
    use domain::base::name::ToName;
    use domain::base::{MessageBuilder, Name};
    use domain::rdata::Cname;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;

    // ---- builders / helpers ----

    fn mk(main: Vec<String>, fall: Vec<String>) -> Handler {
        let fwd = |addrs: Vec<String>, to: u64| {
            Forwarder::new(
                addrs
                    .iter()
                    .map(|u| Arc::new(Upstream::parse(u).unwrap()))
                    .collect(),
                Duration::from_millis(to),
            )
        };
        Handler {
            main: fwd(main, 300),
            fallback: fwd(fall, 800),
            cache: Arc::new(Cache::new(1024)),
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
        let resolver = PtrResolver::new(vec![], vec![], false, &statics).map(Arc::new);
        let mut h = mk(dead(), dead());
        h.resolver = resolver;
        let out = ask(&h, "host.lan.", Rtype::A, "127.0.0.1").await;
        assert_eq!(parse_resp(&out).header().rcode(), Rcode::NOERROR);
        assert_eq!(answer_count(&out), 1);
        assert_eq!(first_ttl(&out), Some(300));
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
    async fn force_fall_uses_fallback_and_skips_cache() {
        let main = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([1, 1, 1, 1], 60)])).await;
        let fall = spawn_mock(|q| answer(q, Rcode::NOERROR, &[([2, 2, 2, 2], 60)])).await;
        let mut h = mk(vec![main], vec![fall]);
        h.force_fall
            .include
            .push(parse_prefix("127.0.0.1/32").unwrap());
        let out = ask(&h, "example.com.", Rtype::A, "127.0.0.1").await;
        // Policy-routed clients keep the upstream TTL (only failover gets 1).
        assert_eq!(first_ttl(&out), Some(60));
        // force_fall clients never touch the shared cache.
        assert!(h.cache.is_empty());
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

    fn info_for(name: &str, qtype: Rtype) -> QueryInfo {
        let req = Message::from_octets(client_query(name, qtype)).unwrap();
        dns::extract_query(&req).unwrap()
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
        h.apply_lite(&mut parts, &info_for("www.example.com.", Rtype::A));
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
        h.apply_lite(&mut parts, &info_for("www.example.com.", Rtype::A));
        assert_eq!(parts.answers.len(), 1);
        assert_eq!(parts.answers[0].rtype(), Rtype::CNAME);
    }

    #[test]
    fn hook_down_forces_fallback_route() {
        let flag = Arc::new(AtomicBool::new(true));
        let mut h = mk(dead(), dead());
        h.hook_failed = Some(flag);
        let route = h.resolve_route(
            &info_for("example.com.", Rtype::A),
            "127.0.0.1".parse().unwrap(),
        );
        assert!(route.force);
        assert_eq!(route.fall_label, "hook_fall");
    }
}
