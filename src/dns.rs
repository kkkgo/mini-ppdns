// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! DNS message toolkit built on the `domain` crate: parsing queries, building
//! responses, and an owned record representation for the cache.

use domain::base::iana::{Class, Rcode, Rtype};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::name::{FlattenInto, ToName};
use domain::base::rdata::ComposeRecordData;
use domain::base::{Message, MessageBuilder, Name, Ttl};
use domain::rdata::AllRecordData;

pub type Bytes = Vec<u8>;
pub type OwnedName = Name<Bytes>;
pub type OwnedData = AllRecordData<Bytes, OwnedName>;
pub type OwnedRecord = domain::base::Record<OwnedName, OwnedData>;

/// The client's EDNS0 state we care about echoing.
#[derive(Debug, Clone, Copy)]
pub struct ClientEdns {
    pub do_bit: bool,
    pub udp_size: u16,
}

/// Advertised EDNS0 UDP payload size we use on *outgoing upstream queries*
/// (DNS Flag Day 2020 recommendation).
pub const OUR_UDP_SIZE: u16 = 1200;

/// Anti-fragmentation cap on the UDP response size we will emit, even if the
/// client advertises a larger EDNS buffer. Bounds fragmentation-related packet
/// loss while still letting well-behaved EDNS clients receive large answers.
pub const MAX_UDP_RESPONSE: u16 = 4096;

/// Wire size of the OPT pseudo-record we append (root name(1) + type(2) +
/// class/size(2) + ttl/flags(4) + rdlen(2), empty rdata). Reserved while
/// fitting records so the OPT always has room after truncation.
const OPT_WIRE_LEN: usize = 11;

/// UDP byte budget for a response to a client with the given EDNS state: the
/// client's advertised size clamped to `[512, MAX_UDP_RESPONSE]`, or the bare
/// 512 floor (RFC 1035 §4.2.1) when the client sent no OPT.
pub fn udp_response_limit(edns: Option<ClientEdns>) -> u16 {
    match edns {
        Some(e) => e.udp_size.clamp(512, MAX_UDP_RESPONSE),
        None => 512,
    }
}

/// Extracted, owned view of an incoming query's question + EDNS state.
#[derive(Debug, Clone)]
pub struct QueryInfo {
    pub qname: OwnedName,
    /// Lower-cased uncompressed wire name, used as the cache key.
    pub qname_lower: Vec<u8>,
    pub qtype: Rtype,
    pub qclass: Class,
    pub client_edns: Option<ClientEdns>,
}

/// Parse a datagram/stream message body. Returns None on malformed input.
pub fn parse(bytes: Vec<u8>) -> Option<Message<Vec<u8>>> {
    Message::from_octets(bytes).ok()
}

/// Extract the sole question and EDNS state. Returns None if there is no
/// question (caller then answers FORMERR).
pub fn extract_query<Octs: domain::dep::octseq::Octets + ?Sized>(
    msg: &Message<Octs>,
) -> Option<QueryInfo> {
    let q = msg.sole_question().ok()?;
    let qname: OwnedName = q.qname().to_vec();
    let mut qname_lower = qname.as_slice().to_vec();
    qname_lower.make_ascii_lowercase();
    let client_edns = msg.opt().map(|opt| ClientEdns {
        do_bit: opt.dnssec_ok(),
        udp_size: opt.udp_payload_size(),
    });
    Some(QueryInfo {
        qname,
        qname_lower,
        qtype: q.qtype(),
        qclass: q.qclass(),
        client_edns,
    })
}

/// Collect the answer section as owned records (names decompressed).
pub fn answers_owned(msg: &Message<Vec<u8>>) -> Vec<OwnedRecord> {
    section_owned(msg.answer().ok())
}

/// Collect the authority section as owned records.
pub fn authority_owned(msg: &Message<Vec<u8>>) -> Vec<OwnedRecord> {
    section_owned(msg.authority().ok())
}

/// Collect the additional section as owned records, excluding the OPT
/// pseudo-record (which is rebuilt from the client's EDNS state on the way out).
pub fn additional_owned(msg: &Message<Vec<u8>>) -> Vec<OwnedRecord> {
    let mut recs = section_owned(msg.additional().ok());
    recs.retain(|r| r.rtype() != Rtype::OPT);
    recs
}

fn section_owned(
    section: Option<domain::base::message::RecordSection<'_, Vec<u8>>>,
) -> Vec<OwnedRecord> {
    let mut out = Vec::new();
    let Some(section) = section else { return out };
    for rec in section.limit_to::<AllRecordData<_, _>>() {
        let Ok(rec) = rec else { continue };
        // Flattening into a Vec-backed record is infallible (the Err variant is
        // uninhabited), so this binding is irrefutable.
        let Ok(owned) = rec.try_flatten_into();
        out.push(owned);
    }
    out
}

/// Minimum TTL (seconds) across the given records, ignoring OPT. Returns None
/// when there are no non-OPT records.
pub fn min_ttl(records: &[OwnedRecord]) -> Option<u32> {
    records
        .iter()
        .filter(|r| r.rtype() != Rtype::OPT)
        .map(|r| r.ttl().as_secs())
        .min()
}

/// A response ready to build: header flags, rcode, and sectioned records.
pub struct ResponseData<'a> {
    pub rcode: Rcode,
    pub answers: &'a [OwnedRecord],
    pub authority: &'a [OwnedRecord],
    pub additional: &'a [OwnedRecord],
    /// Per-record TTL override (seconds). When Some, every record is emitted
    /// with this TTL; when None, each record keeps its own TTL.
    pub ttl_override: Option<u32>,
    pub edns: Option<ClientEdns>,
    /// When Some and there is more than one answer, answers are emitted in a
    /// three-tier order (CNAMEs, then shuffled qtype matches, then the rest)
    /// for load balancing.
    pub shuffle_qtype: Option<Rtype>,
}

/// Build a wire response echoing `req`'s question. `udp_limit` (Some for UDP)
/// caps the datagram size; on overflow the response is refilled up to the limit
/// with as many records as fit and the TC bit is set (RFC 1035 §4.2.1).
pub fn build_response<Octs: domain::dep::octseq::Octets + ?Sized>(
    req: &Message<Octs>,
    data: &ResponseData<'_>,
    udp_limit: Option<u16>,
) -> Vec<u8> {
    let msg = assemble(req, data);
    match udp_limit {
        // Over budget → rebuild filling records up to the limit and set TC. This
        // slower, allocation-heavier path runs only on actual overflow; every
        // in-budget response (the overwhelming majority) pays nothing beyond the
        // single build above.
        Some(limit) if msg.len() > limit as usize => assemble_fitted(req, data, limit),
        _ => msg,
    }
}

/// Append the response OPT, echoing the client's advertised UDP size (clamped
/// to what we are actually willing to send) so "advertised" agrees with the
/// truncation budget, and carrying the DO bit back if the client set it.
fn push_opt(add: &mut AdditionalBuilder<Vec<u8>>, edns: ClientEdns) {
    let _ = add.opt(|opt| {
        opt.set_udp_payload_size(edns.udp_size.clamp(512, MAX_UDP_RESPONSE));
        if edns.do_bit {
            opt.set_dnssec_ok(true);
        }
        Ok(())
    });
}

/// Full build with no size limit (TCP, or a UDP response known to fit).
fn assemble<Octs: domain::dep::octseq::Octets + ?Sized>(
    req: &Message<Octs>,
    data: &ResponseData<'_>,
) -> Vec<u8> {
    let mut ans = MessageBuilder::new_vec().start_error(req, data.rcode);
    ans.header_mut().set_ra(true); // forwarder offers recursion
    match data.shuffle_qtype {
        Some(qtype) if data.answers.len() > 1 => {
            for i in answer_order(data.answers, qtype) {
                if push_record(&mut ans, &data.answers[i], data.ttl_override).is_err() {
                    break;
                }
            }
        }
        _ => {
            for r in data.answers {
                if push_record(&mut ans, r, data.ttl_override).is_err() {
                    break;
                }
            }
        }
    }
    let mut auth = ans.authority();
    for r in data.authority {
        if push_record(&mut auth, r, data.ttl_override).is_err() {
            break;
        }
    }
    let mut add = auth.additional();
    for r in data.additional {
        if push_record(&mut add, r, data.ttl_override).is_err() {
            break;
        }
    }
    if let Some(edns) = data.edns {
        push_opt(&mut add, edns);
    }
    add.finish()
}

/// Size-bounded build: emit as many records as fit within `limit` (in section
/// order, so the shuffle's CNAME→qtype priority keeps the most relevant answers)
/// and set TC. Only ever reached when the full build overflowed, so at least one
/// record is dropped and TC always applies.
fn assemble_fitted<Octs: domain::dep::octseq::Octets + ?Sized>(
    req: &Message<Octs>,
    data: &ResponseData<'_>,
    limit: u16,
) -> Vec<u8> {
    let limit = limit as usize;
    // The OPT is appended last; keep room for it so it never gets crowded out.
    let opt_reserve = if data.edns.is_some() { OPT_WIRE_LEN } else { 0 };

    let mut ans = MessageBuilder::new_vec().start_error(req, data.rcode);
    {
        let h = ans.header_mut();
        h.set_ra(true);
        h.set_tc(true);
    }

    let order: Vec<usize> = match data.shuffle_qtype {
        Some(qtype) if data.answers.len() > 1 => answer_order(data.answers, qtype),
        _ => (0..data.answers.len()).collect(),
    };
    for i in order {
        let r = &data.answers[i];
        if ans.as_slice().len() + rr_upper_bound(r) + opt_reserve > limit {
            break;
        }
        if push_record(&mut ans, r, data.ttl_override).is_err() {
            break;
        }
    }

    let mut auth = ans.authority();
    for r in data.authority {
        if auth.as_slice().len() + rr_upper_bound(r) + opt_reserve > limit {
            break;
        }
        if push_record(&mut auth, r, data.ttl_override).is_err() {
            break;
        }
    }

    let mut add = auth.additional();
    for r in data.additional {
        if add.as_slice().len() + rr_upper_bound(r) + opt_reserve > limit {
            break;
        }
        if push_record(&mut add, r, data.ttl_override).is_err() {
            break;
        }
    }

    if let Some(edns) = data.edns {
        push_opt(&mut add, edns);
    }
    add.finish()
}

/// Safe upper bound on a record's uncompressed wire size (owner name, the fixed
/// 10-byte header, and rdata). Name compression only shrinks the real encoding,
/// so budgeting with this bound can truncate a hair early but never overflows
/// the datagram.
fn rr_upper_bound(r: &OwnedRecord) -> usize {
    let owner_len = r.owner().as_slice().len();
    let mut scratch = Vec::new();
    let rdata_len = if r.data().compose_rdata(&mut scratch).is_ok() {
        scratch.len()
    } else {
        0
    };
    // owner + type(2) + class(2) + ttl(4) + rdlen(2) + rdata
    owner_len + 10 + rdata_len
}

/// Three-tier answer push order per RFC 1034: CNAMEs
/// first (in original order), then qtype matches (shuffled for load balancing),
/// then everything else (original order).
fn answer_order(answers: &[OwnedRecord], qtype: Rtype) -> Vec<usize> {
    let mut cnames = Vec::new();
    let mut matches = Vec::new();
    let mut rest = Vec::new();
    for (i, r) in answers.iter().enumerate() {
        let t = r.rtype();
        if t == Rtype::CNAME {
            cnames.push(i);
        } else if t == qtype {
            matches.push(i);
        } else {
            rest.push(i);
        }
    }
    crate::rng::shuffle(&mut matches);
    cnames.into_iter().chain(matches).chain(rest).collect()
}

fn push_record<T: domain::base::message_builder::RecordSectionBuilder<Vec<u8>>>(
    builder: &mut T,
    r: &OwnedRecord,
    ttl_override: Option<u32>,
) -> Result<(), domain::base::message_builder::PushError> {
    let ttl = match ttl_override {
        Some(secs) => Ttl::from_secs(secs),
        None => r.ttl(),
    };
    builder.push((r.owner(), r.class(), ttl, r.data()))
}

/// Build a normalized upstream query: fresh random ID, RD set, EDNS0 OPT with
/// our advertised UDP size (+ DO bit if the client asked for it).
pub fn build_upstream_query(q: &QueryInfo) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec();
    {
        let h = builder.header_mut();
        h.set_rd(true);
        h.set_random_id();
    }
    let mut question = builder.question();
    let _ = question.push((&q.qname, q.qtype, q.qclass));
    let mut add = question.additional();
    let do_bit = q.client_edns.map(|e| e.do_bit).unwrap_or(false);
    let _ = add.opt(|opt| {
        opt.set_udp_payload_size(OUR_UDP_SIZE);
        if do_bit {
            opt.set_dnssec_ok(true);
        }
        Ok(())
    });
    add.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::base::net::Ipv4Addr;
    use domain::rdata::A;
    use std::str::FromStr;

    fn make_query(name: &str, qtype: Rtype) -> Vec<u8> {
        let mut b = MessageBuilder::new_vec();
        b.header_mut().set_rd(true);
        let mut q = b.question();
        q.push((Name::<Vec<u8>>::from_str(name).unwrap(), qtype))
            .unwrap();
        q.finish()
    }

    fn fake_a_response(name: &str, ttl: u32) -> Vec<u8> {
        let req = make_query(name, Rtype::A);
        let req = Message::from_octets(req).unwrap();
        let mut ans = MessageBuilder::new_vec()
            .start_answer(&req, Rcode::NOERROR)
            .unwrap();
        let n = Name::<Vec<u8>>::from_str(name).unwrap();
        ans.push((
            n,
            Class::IN,
            Ttl::from_secs(ttl),
            A::new(Ipv4Addr::new(1, 2, 3, 4)),
        ))
        .unwrap();
        ans.finish()
    }

    #[test]
    fn parse_extract_build_roundtrip() {
        let req_bytes = make_query("Example.COM.", Rtype::A);
        let req = Message::from_octets(req_bytes.clone()).unwrap();
        let info = extract_query(&req).expect("has question");
        assert_eq!(info.qtype, Rtype::A);
        assert_eq!(info.qclass, Class::IN);
        // Cache key is lower-cased.
        assert_eq!(info.qname_lower, b"\x07example\x03com\x00");

        // Parse a fake upstream response, own its records, rebuild with TTL=1.
        let resp = parse(fake_a_response("example.com.", 3600)).unwrap();
        let answers = answers_owned(&resp);
        assert_eq!(answers.len(), 1);
        assert_eq!(min_ttl(&answers), Some(3600));

        let data = ResponseData {
            rcode: Rcode::NOERROR,
            answers: &answers,
            authority: &[],
            additional: &[],
            ttl_override: Some(1),
            edns: None,
            shuffle_qtype: None,
        };
        let out = build_response(&req, &data, Some(1232));
        let out_msg = parse(out).unwrap();
        assert_eq!(out_msg.header().rcode(), Rcode::NOERROR);
        assert!(out_msg.header().qr());
        let ans: Vec<_> = out_msg
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .collect();
        assert_eq!(ans.len(), 1);
        assert_eq!(ans[0].as_ref().unwrap().ttl().as_secs(), 1); // override applied
    }

    #[test]
    fn upstream_query_has_opt_and_rd() {
        let req = Message::from_octets(make_query("example.com.", Rtype::AAAA)).unwrap();
        let info = extract_query(&req).unwrap();
        let q = parse(build_upstream_query(&info)).unwrap();
        assert!(q.header().rd());
        assert!(q.opt().is_some());
        assert_eq!(q.sole_question().unwrap().qtype(), Rtype::AAAA);
    }

    fn a_record(name: &str, last: u8) -> OwnedRecord {
        OwnedRecord::new(
            Name::<Vec<u8>>::from_str(name).unwrap(),
            Class::IN,
            Ttl::from_secs(300),
            AllRecordData::A(A::from_octets(10, 0, 0, last)),
        )
    }

    #[test]
    fn answer_order_partitions_cname_qtype_rest() {
        use domain::rdata::{Aaaa, Cname};
        let recs = vec![
            OwnedRecord::new(
                Name::<Vec<u8>>::from_str("a.").unwrap(),
                Class::IN,
                Ttl::from_secs(60),
                AllRecordData::Cname(Cname::new(Name::<Vec<u8>>::from_str("b.").unwrap())),
            ),
            a_record("a.", 1), // A (qtype match)
            OwnedRecord::new(
                Name::<Vec<u8>>::from_str("a.").unwrap(),
                Class::IN,
                Ttl::from_secs(60),
                AllRecordData::Aaaa(Aaaa::new("::1".parse().unwrap())),
            ), // rest
            a_record("a.", 2), // A (qtype match)
        ];
        let order = answer_order(&recs, Rtype::A);
        assert_eq!(order.len(), 4);
        assert_eq!(order[0], 0, "CNAME goes first");
        assert_eq!(order[3], 2, "non-matching rest goes last");
        assert!(
            [order[1], order[2]].contains(&1) && [order[1], order[2]].contains(&3),
            "qtype matches occupy the middle"
        );
    }

    #[test]
    fn udp_truncation_fills_to_limit_and_sets_tc() {
        // A non-EDNS query: the 512-byte floor applies.
        let req = Message::from_octets(make_query("example.com.", Rtype::A)).unwrap();
        let answers: Vec<OwnedRecord> = (0..100u8).map(|i| a_record("example.com.", i)).collect();
        let data = ResponseData {
            rcode: Rcode::NOERROR,
            answers: &answers,
            authority: &[],
            additional: &[],
            ttl_override: None,
            edns: None,
            shuffle_qtype: Some(Rtype::A),
        };
        let limit = 512u16;
        let out = build_response(&req, &data, Some(limit));
        assert!(out.len() <= limit as usize, "len {} > {limit}", out.len());
        let msg = parse(out).unwrap();
        assert!(msg.header().tc(), "TC must be set when records are dropped");
        let n = msg
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .count();
        // Fill-to-limit: some answers fit, but not all 100.
        assert!(n > 0 && n < 100, "should keep a partial set, got {n}");
    }

    #[test]
    fn small_response_not_truncated() {
        let req = Message::from_octets(make_query("example.com.", Rtype::A)).unwrap();
        let answers = vec![a_record("example.com.", 1)];
        let data = ResponseData {
            rcode: Rcode::NOERROR,
            answers: &answers,
            authority: &[],
            additional: &[],
            ttl_override: None,
            edns: None,
            shuffle_qtype: Some(Rtype::A),
        };
        let out = build_response(&req, &data, Some(512));
        let msg = parse(out).unwrap();
        assert!(!msg.header().tc());
        assert_eq!(
            msg.answer()
                .unwrap()
                .limit_to::<AllRecordData<_, _>>()
                .count(),
            1
        );
    }

    fn query_with_edns(udp_size: u16) -> Vec<u8> {
        let mut b = MessageBuilder::new_vec();
        b.header_mut().set_rd(true);
        let mut q = b.question();
        q.push((Name::<Vec<u8>>::from_str("example.com.").unwrap(), Rtype::A))
            .unwrap();
        let mut add = q.additional();
        add.opt(|opt| {
            opt.set_udp_payload_size(udp_size);
            Ok(())
        })
        .unwrap();
        add.finish()
    }

    #[test]
    fn response_opt_echoes_clamped_client_size() {
        for (advertised, want) in [(1400u16, 1400u16), (8192, MAX_UDP_RESPONSE), (200, 512)] {
            let req = Message::from_octets(query_with_edns(advertised)).unwrap();
            let info = extract_query(&req).unwrap();
            let data = ResponseData {
                rcode: Rcode::NOERROR,
                answers: &[],
                authority: &[],
                additional: &[],
                ttl_override: None,
                edns: info.client_edns,
                shuffle_qtype: Some(Rtype::A),
            };
            let out = build_response(&req, &data, Some(udp_response_limit(info.client_edns)));
            let msg = parse(out).unwrap();
            assert_eq!(
                msg.opt().unwrap().udp_payload_size(),
                want,
                "advertised={advertised}"
            );
        }
    }

    // Regression guard for the `panic = "unwind"` isolation story: the untrusted
    // parse surface (what `process` runs before any of our logic) must never
    // panic on malformed wire data. Cheap enough to keep in the normal suite.
    #[test]
    fn fuzz_parse_surface_never_panics() {
        let mut state: u64 = 0x1234_5678_9abc_def1;
        let mut rnd = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Pure-random datagrams.
        for _ in 0..60_000 {
            let len = (rnd() % 96) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (rnd() & 0xff) as u8).collect();
            if let Some(msg) = parse(bytes) {
                if let Some(info) = extract_query(&msg) {
                    let _ = info.qname.to_string();
                }
                let _ = answers_owned(&msg);
                let _ = authority_owned(&msg);
                let _ = additional_owned(&msg);
            }
        }
        // Valid header + corrupted section counts + random tail (exercises the
        // record iterators against claimed-but-absent RRs).
        for _ in 0..60_000 {
            let mut bytes = make_query("a.example.com.", Rtype::A);
            for _ in 0..(rnd() % 48) {
                bytes.push((rnd() & 0xff) as u8);
            }
            for idx in [6usize, 7, 8, 9, 10, 11] {
                bytes[idx] = (rnd() & 0xff) as u8;
            }
            if let Some(msg) = parse(bytes) {
                let _ = extract_query(&msg);
                let _ = answers_owned(&msg);
                let _ = authority_owned(&msg);
                let _ = additional_owned(&msg);
            }
        }
    }
}
