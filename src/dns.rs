// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! DNS message toolkit built on the `domain` crate: parsing queries, building
//! responses, and an owned record representation for the cache.

use domain::base::iana::{Class, Rcode, Rtype};
use domain::base::message_builder::{AdditionalBuilder, AnswerBuilder, StaticCompressor};
use domain::base::name::{FlattenInto, ToName};
use domain::base::rdata::ComposeRecordData;
use domain::base::wire::Composer;
use domain::base::{Message, MessageBuilder, Name, Ttl};
use domain::rdata::AllRecordData;

pub type Bytes = Vec<u8>;
pub type OwnedName = Name<Bytes>;
pub type OwnedData = AllRecordData<Bytes, OwnedName>;
pub type OwnedRecord = domain::base::Record<OwnedName, OwnedData>;

/// The client's EDNS0 state we care about echoing (just the advertised UDP
/// size). The DO bit is deliberately not tracked: DNSSEC is out of scope for
/// this forwarder (lite mode strips RRSIGs and the cache is not DO-aware), so
/// we never request DNSSEC records upstream and never claim support
/// downstream.
#[derive(Debug, Clone, Copy)]
pub struct ClientEdns {
    pub udp_size: u16,
}

/// Advertised EDNS0 UDP payload size we use on *outgoing upstream queries*
/// (DNS Flag Day 2020 recommendation).
pub const OUR_UDP_SIZE: u16 = 1200;

/// Anti-fragmentation cap on the UDP response size we will emit, even if the
/// client advertises a larger EDNS buffer. Bounds fragmentation-related packet
/// loss while still letting well-behaved EDNS clients receive large answers.
pub const MAX_UDP_RESPONSE: u16 = 4096;

/// Build target for outgoing responses: a plain `Vec<u8>` wrapped in the
/// crate's name compressor.
///
/// Uncompressed, every record repeats its owner name in full, which for a
/// multi-record answer is the bulk of the datagram. That matters most at the
/// RFC 1035 512-byte floor — what a client which sends no OPT gets, glibc's
/// stub resolver among them — where it is the difference between a whole answer
/// and a truncated one the client has to re-ask for over TCP.
///
/// `StaticCompressor` is a fixed `[u16; 24]` table: no allocation, a bounded
/// scan per name, and once full it writes full names again, so a large answer
/// degrades gracefully. Per-record-type policy (RFC 3597: only RFC 1035
/// well-known types may compress names inside rdata) is handled by the `domain`
/// crate itself.
type BuildTarget = StaticCompressor<Vec<u8>>;

/// A fresh compressing response builder.
fn new_packed() -> MessageBuilder<BuildTarget> {
    // `Vec`'s append error is uninhabited, so this cannot fail.
    let Ok(builder) = MessageBuilder::from_target(StaticCompressor::new(Vec::new()));
    builder
}

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

/// Byte offset just past the (single) question of a well-formed message:
/// header 12 + QNAME + QTYPE(2) + QCLASS(2). `None` if the QNAME is malformed,
/// runs off the end, or uses a compression pointer — question names are never
/// compressed, so a pointer here means the message is not one we will echo
/// verbatim.
pub fn question_end(msg: &[u8]) -> Option<usize> {
    let mut i = 12usize;
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            let end = i + 1 + 4; // zero label + QTYPE + QCLASS
            return (end <= msg.len()).then_some(end);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        i += 1 + len;
    }
}

/// Extracted, owned view of an incoming query's question + EDNS state.
#[derive(Debug, Clone)]
pub struct QueryInfo {
    pub qname: OwnedName,
    /// `util::hash` of the lower-cased wire name, computed once per query and reused by
    /// the resolver's negative filter and the cache key (shard selection
    /// continues from it), so the name is FNV-hashed exactly once.
    pub name_hash: u64,
    pub qtype: Rtype,
    pub qclass: Class,
    pub client_edns: Option<ClientEdns>,
}

/// Parse a datagram/stream message body. Returns None on malformed input.
pub fn parse(bytes: Vec<u8>) -> Option<Message<Vec<u8>>> {
    Message::from_octets(bytes).ok()
}

/// Extract the sole question and EDNS state, plus the lower-cased uncompressed
/// wire name. Returns None if there is no question (caller then answers
/// FORMERR).
///
/// The lower-cased name comes back beside the `QueryInfo` so the caller can
/// move it into the `CacheKey`, which has to own it.
pub fn extract_query<Octs: domain::dep::octseq::Octets + ?Sized>(
    msg: &Message<Octs>,
) -> Option<(QueryInfo, Vec<u8>)> {
    let q = msg.sole_question().ok()?;
    let qname: OwnedName = q.qname().to_vec();
    let mut qname_lower = qname.as_slice().to_vec();
    qname_lower.make_ascii_lowercase();
    let name_hash = crate::util::hash(&qname_lower);
    let client_edns = edns_of(msg);
    Some((
        QueryInfo {
            qname,
            name_hash,
            qtype: q.qtype(),
            qclass: q.qclass(),
            client_edns,
        },
        qname_lower,
    ))
}

/// Read the OPT a query carries right after its question, for the message
/// shapes where that position is guaranteed.
///
/// `Some(x)` is a definitive answer; `None` means the shape is not one this can
/// read directly and the caller must fall back to walking the sections.
fn opt_after_question(src: &[u8]) -> Option<Option<ClientEdns>> {
    if src.len() < 12 {
        return None;
    }
    // No additional section at all: there is definitively no OPT.
    if u16::from_be_bytes([src[10], src[11]]) == 0 {
        return Some(None);
    }
    // Otherwise the OPT is only at a known offset when nothing precedes it.
    if u16::from_be_bytes([src[4], src[5]]) != 1
        || u16::from_be_bytes([src[6], src[7]]) != 0
        || u16::from_be_bytes([src[8], src[9]]) != 0
    {
        return None;
    }
    let i = question_end(src)?;
    // An OPT's owner is always the root name.
    if *src.get(i)? != 0 {
        return None;
    }
    // owner(1) + type(2) + class(2) + ttl(4) + rdlen(2)
    let rr = src.get(i..i + 11)?;
    if u16::from_be_bytes([rr[1], rr[2]]) != Rtype::OPT.to_int() {
        // Something else comes first; the OPT may still be further along.
        return None;
    }
    // The record has to be complete, rdata included, or the message is
    // malformed and the general path will reject it too — decline and let it.
    let rdlen = u16::from_be_bytes([rr[9], rr[10]]) as usize;
    if i + 11 + rdlen > src.len() {
        return None;
    }
    // The class field of an OPT carries the advertised UDP payload size.
    Some(Some(ClientEdns {
        udp_size: u16::from_be_bytes([rr[3], rr[4]]),
    }))
}

/// The EDNS state of a message's OPT record, if any. Works even when the
/// question section is unusable — the FORMERR/NOTIMP paths still echo EDNS
/// per RFC 6891 §7.
pub fn edns_of<Octs: domain::dep::octseq::Octets + ?Sized>(
    msg: &Message<Octs>,
) -> Option<ClientEdns> {
    if let Some(fast) = opt_after_question(msg.as_slice()) {
        return fast;
    }
    edns_of_slow(msg)
}

/// The general path: walk the sections and look for an OPT anywhere.
fn edns_of_slow<Octs: domain::dep::octseq::Octets + ?Sized>(
    msg: &Message<Octs>,
) -> Option<ClientEdns> {
    msg.opt().map(|opt| ClientEdns {
        udp_size: opt.udp_payload_size(),
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
    // TCP carries no datagram budget, but a DNS message is still capped by the
    // 2-byte length prefix the transport frames it with, so that is the budget
    // there — an over-long message gets truncated with TC like any other.
    let limit = udp_limit.unwrap_or(u16::MAX) as usize;

    // Uncompressed build first: compression costs noticeably more CPU, and the
    // overwhelming majority of responses fit without it.
    let msg = assemble(req, data);
    if msg.len() <= limit {
        return msg;
    }

    // Over budget. Name compression alone usually brings a multi-record answer
    // back under the limit, saving the client a TCP round trip; the extra build
    // only ever happens here.
    let packed = assemble_packed(req, data);
    if packed.len() <= limit {
        return packed;
    }

    // Genuinely too big: drop records and set TC. Compressed, so the budget
    // holds as many of them as possible.
    assemble_fitted(req, data, limit)
}

/// Append the response OPT, echoing the client's advertised UDP size (clamped
/// to what we are actually willing to send) so "advertised" agrees with the
/// truncation budget. The DO bit is never echoed (see [`ClientEdns`]).
fn push_opt<T: Composer>(add: &mut AdditionalBuilder<T>, edns: ClientEdns) {
    let _ = add.opt(|opt| {
        opt.set_udp_payload_size(edns.udp_size.clamp(512, MAX_UDP_RESPONSE));
        Ok(())
    });
}

/// Fill every section with no size limit, shared by the plain and compressed
/// builds — they differ only in the octets target they compose into.
fn fill<T: Composer>(mut ans: AnswerBuilder<T>, data: &ResponseData<'_>) -> T {
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

/// Start a response: header copied from `req`, RA set (we offer recursion).
fn start<Octs: domain::dep::octseq::Octets + ?Sized, T: Composer>(
    builder: MessageBuilder<T>,
    req: &Message<Octs>,
    rcode: Rcode,
) -> AnswerBuilder<T> {
    let mut ans = builder.start_error(req, rcode);
    ans.header_mut().set_ra(true);
    ans
}

/// Append one record in wire form.
///
/// A `Name<Vec<u8>>` already holds its uncompressed wire encoding, so the owner
/// is a straight copy.
fn write_record(out: &mut Vec<u8>, r: &OwnedRecord, ttl_override: Option<u32>) -> bool {
    let start = out.len();
    out.extend_from_slice(r.owner().as_slice());
    out.extend_from_slice(&r.rtype().to_int().to_be_bytes());
    out.extend_from_slice(&r.class().to_int().to_be_bytes());
    let ttl = ttl_override.unwrap_or_else(|| r.ttl().as_secs());
    out.extend_from_slice(&ttl.to_be_bytes());
    let len_at = out.len();
    out.extend_from_slice(&[0, 0]);
    // Composing into a `Vec` cannot fail: its append error is uninhabited.
    let _ = r.data().compose_rdata(out);
    match u16::try_from(out.len() - len_at - 2) {
        Ok(rdlen) => {
            out[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
            true
        }
        // rdata past 65535 cannot be encoded; drop the record whole, matching
        // what the builder path does.
        Err(_) => {
            out.truncate(start);
            false
        }
    }
}

/// Append the OPT pseudo-record: root owner, type OPT, the advertised UDP size
/// in the class field, and an all-zero TTL field (extended rcode 0, version 0,
/// no flags — DO is never echoed, see [`ClientEdns`]). Exactly [`OPT_WIRE_LEN`]
/// bytes.
fn write_opt(out: &mut Vec<u8>, edns: ClientEdns) {
    out.push(0);
    out.extend_from_slice(&Rtype::OPT.to_int().to_be_bytes());
    out.extend_from_slice(&edns.udp_size.clamp(512, MAX_UDP_RESPONSE).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
}

/// Full build, no name compression — the fast, common path.
///
/// Writes the wire format directly. The response's header and question section
/// are the request's own bytes — the question has to be echoed verbatim anyway —
/// and a `Name<Vec<u8>>` is already stored in wire form, so records are copies
/// too.
///
/// Must stay byte-identical to the `MessageBuilder` path below, which
/// `assemble_matches_the_builder` checks. Shapes this cannot echo verbatim
/// (more than one question, or a question it cannot walk) go to that path.
fn assemble<Octs: domain::dep::octseq::Octets + ?Sized>(
    req: &Message<Octs>,
    data: &ResponseData<'_>,
) -> Vec<u8> {
    let src = req.as_slice();
    // `Message` guarantees at least a full header.
    let qend = match u16::from_be_bytes([src[4], src[5]]) {
        0 => Some(12),
        1 => question_end(src),
        _ => None,
    };
    let Some(qend) = qend else {
        return fill(start(MessageBuilder::new_vec(), req, data.rcode), data);
    };

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&src[..qend]); // header + question, verbatim
                                         // QR=1, opcode and RD copied from the request, AA/TC cleared.
    out[2] = 0x80 | (src[2] & 0x79);
    // RA=1 (we offer recursion), Z/AD/CD cleared, rcode in the low nibble.
    out[3] = 0x80 | u8::from(data.rcode);
    out[6..12].fill(0); // QDCOUNT is the request's; the rest we count as we go

    let mut counts = [0u16; 3]; // AN, NS, AR
    match data.shuffle_qtype {
        Some(qtype) if data.answers.len() > 1 => {
            for i in answer_order(data.answers, qtype) {
                counts[0] += u16::from(write_record(&mut out, &data.answers[i], data.ttl_override));
            }
        }
        _ => {
            for r in data.answers {
                counts[0] += u16::from(write_record(&mut out, r, data.ttl_override));
            }
        }
    }
    for r in data.authority {
        counts[1] += u16::from(write_record(&mut out, r, data.ttl_override));
    }
    for r in data.additional {
        counts[2] += u16::from(write_record(&mut out, r, data.ttl_override));
    }
    if let Some(edns) = data.edns {
        write_opt(&mut out, edns);
        counts[2] += 1;
    }
    for (i, c) in counts.iter().enumerate() {
        out[6 + i * 2..8 + i * 2].copy_from_slice(&c.to_be_bytes());
    }
    out
}

/// Full build with name compression, for a response that overflowed its budget.
fn assemble_packed<Octs: domain::dep::octseq::Octets + ?Sized>(
    req: &Message<Octs>,
    data: &ResponseData<'_>,
) -> Vec<u8> {
    fill(start(new_packed(), req, data.rcode), data).into_target()
}

/// Size-bounded build: emit as many records as fit within `limit` (in section
/// order, so the shuffle's CNAME→qtype priority keeps the most relevant answers)
/// and set TC. Only ever reached when even the compressed build overflowed, so
/// at least one record is dropped and TC always applies.
fn assemble_fitted<Octs: domain::dep::octseq::Octets + ?Sized>(
    req: &Message<Octs>,
    data: &ResponseData<'_>,
    limit: usize,
) -> Vec<u8> {
    // The OPT is appended last; keep room for it so it never gets crowded out.
    let opt_reserve = if data.edns.is_some() { OPT_WIRE_LEN } else { 0 };

    let mut ans = start(new_packed(), req, data.rcode);
    ans.header_mut().set_tc(true);

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
    add.finish().into_target()
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
/// then everything else (original order). Built as a single index Vec — one
/// allocation, with the match range shuffled in place — instead of a Vec per
/// tier plus a collect.
fn answer_order(answers: &[OwnedRecord], qtype: Rtype) -> Vec<usize> {
    let tier = |r: &OwnedRecord| {
        let t = r.rtype();
        if t == Rtype::CNAME {
            0u8
        } else if t == qtype {
            1
        } else {
            2
        }
    };
    let mut order = Vec::with_capacity(answers.len());
    let mut bounds = [0usize; 2]; // end of the CNAME tier, end of the match tier
    for want in 0..3u8 {
        for (i, r) in answers.iter().enumerate() {
            if tier(r) == want {
                order.push(i);
            }
        }
        if want < 2 {
            bounds[want as usize] = order.len();
        }
    }
    crate::rng::shuffle(&mut order[bounds[0]..bounds[1]]);
    order
}

fn push_record<T: Composer, B: domain::base::message_builder::RecordSectionBuilder<T>>(
    builder: &mut B,
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
/// our advertised UDP size. DO is never set, so upstreams don't bulk the
/// response up with DNSSEC records we would strip anyway (see [`ClientEdns`]).
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
    let _ = add.opt(|opt| {
        opt.set_udp_payload_size(OUR_UDP_SIZE);
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
        let (info, qname_lower) = extract_query(&req).expect("has question");
        assert_eq!(info.qtype, Rtype::A);
        assert_eq!(info.qclass, Class::IN);
        // Cache key is lower-cased.
        assert_eq!(qname_lower, b"\x07example\x03com\x00");

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
        let (info, _) = extract_query(&req).unwrap();
        let q = parse(build_upstream_query(&info)).unwrap();
        assert!(q.header().rd());
        assert!(q.opt().is_some());
        assert_eq!(q.sole_question().unwrap().qtype(), Rtype::AAAA);
    }

    #[test]
    fn do_bit_never_forwarded_or_echoed() {
        // Client asks with DO=1: neither the upstream query nor the response
        // may carry it (DNSSEC out of scope; see ClientEdns).
        let mut b = MessageBuilder::new_vec();
        b.header_mut().set_rd(true);
        let mut q = b.question();
        q.push((Name::<Vec<u8>>::from_str("example.com.").unwrap(), Rtype::A))
            .unwrap();
        let mut add = q.additional();
        add.opt(|opt| {
            opt.set_udp_payload_size(1232);
            opt.set_dnssec_ok(true);
            Ok(())
        })
        .unwrap();
        let req = Message::from_octets(add.finish()).unwrap();
        let (info, _) = extract_query(&req).unwrap();

        let upq = parse(build_upstream_query(&info)).unwrap();
        assert!(!upq.opt().unwrap().dnssec_ok(), "DO must not go upstream");

        let data = ResponseData {
            rcode: Rcode::NOERROR,
            answers: &[],
            authority: &[],
            additional: &[],
            ttl_override: None,
            edns: info.client_edns,
            shuffle_qtype: None,
        };
        let out = parse(build_response(&req, &data, None)).unwrap();
        assert!(!out.opt().unwrap().dnssec_ok(), "DO must not be echoed");
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
            let (info, _) = extract_query(&req).unwrap();
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

    // Regression guard for the untrusted parse surface (what `process` runs
    // before any of our logic): it must never panic on malformed wire data.
    // The release profile is `panic = "abort"`, so a panic here would take the
    // whole daemon down rather than just the one query — which is the right
    // trade for this binary (the fast path runs inline in the UDP receive loop,
    // so unwinding would silently kill one shard's intake and leave a
    // half-working process), but it makes this guard load-bearing.
    // Cheap enough to keep in the normal suite.
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
                if let Some((info, _)) = extract_query(&msg) {
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

    const LONG_NAME: &str = "very-long-cdn-hostname.example.com.";

    fn build_a_answers(n: usize, limit: Option<u16>) -> Vec<u8> {
        let req = Message::from_octets(make_query(LONG_NAME, Rtype::A)).unwrap();
        let answers: Vec<OwnedRecord> = (0..n)
            .map(|i| a_record(LONG_NAME, (i % 256) as u8))
            .collect();
        let data = ResponseData {
            rcode: Rcode::NOERROR,
            answers: &answers,
            authority: &[],
            additional: &[],
            ttl_override: None,
            edns: None,
            shuffle_qtype: Some(Rtype::A),
        };
        build_response(&req, &data, limit)
    }

    fn answer_records(bytes: Vec<u8>) -> (bool, usize, bool) {
        let msg = parse(bytes).unwrap();
        let recs: Vec<_> = msg
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .collect();
        (
            msg.header().tc(),
            recs.len(),
            recs.iter().all(|r| r.is_ok()),
        )
    }

    #[test]
    fn oversized_response_is_compressed_before_records_are_dropped() {
        // Ten A records for a long owner name overflow the RFC 1035 512-byte
        // floor (what a client that sends no OPT gets — glibc's stub resolver
        // is one) when every record repeats the name…
        let plain = build_a_answers(10, None);
        assert!(
            plain.len() > 512,
            "uncompressed build must overflow, got {}",
            plain.len()
        );
        // …but name compression brings them back under it, so the client gets
        // the whole answer instead of a truncated one plus a TCP retry.
        let out = build_a_answers(10, Some(512));
        assert!(out.len() <= 512, "len {}", out.len());
        assert!(
            out.len() < plain.len(),
            "the over-budget rebuild must actually compress"
        );
        let (tc, n, all_ok) = answer_records(out);
        assert!(!tc, "must not truncate what compression can fit");
        assert_eq!(n, 10, "every record survived");
        assert!(all_ok);
    }

    #[test]
    fn compression_fits_more_records_when_truncation_is_unavoidable() {
        // Forty records overflow 512 even compressed, so TC is set — but the
        // budget still holds 26 of them.
        let out = build_a_answers(40, Some(512));
        assert!(out.len() <= 512, "len {}", out.len());
        let (tc, n, all_ok) = answer_records(out);
        assert!(tc, "40 records still overflow 512");
        assert!(n >= 20, "compressed budget should hold 20+, got {n}");
        // The truncation path rebuilds the message; a stale compression pointer
        // into the discarded tail would surface here as an unparsable record.
        assert!(
            all_ok,
            "every record in a truncated response must still parse"
        );
    }

    #[test]
    fn in_budget_responses_are_left_uncompressed() {
        // Compression costs real CPU, so it is only paid for when it buys
        // something. A response that already fits is built once, plainly: each
        // record carries its own copy of the owner name, not a 2-byte pointer.
        //
        // Asserted as a size property, not by diffing two builds — `answer_order`
        // shuffles, so two builds of the same answer set differ in record order.
        let owner_wire = Name::<Vec<u8>>::from_str(LONG_NAME)
            .unwrap()
            .as_slice()
            .len();
        let one = build_a_answers(1, Some(512)).len();
        let two = build_a_answers(2, Some(512)).len();
        assert_eq!(
            two - one,
            owner_wire + 10 + 4,
            "an in-budget response must not pay for compression (a pointer would cost {})",
            2 + 10 + 4
        );
    }

    #[test]
    fn a_response_too_large_for_the_length_prefix_is_truncated_not_dropped() {
        // TCP carries no datagram budget, but the transport frames messages
        // with a 2-byte length prefix, so a response that re-encodes past
        // 65535 must come back honestly truncated rather than be undeliverable.
        let out = build_a_answers(5000, None);
        assert!(
            out.len() <= u16::MAX as usize,
            "must fit the length prefix, got {}",
            out.len()
        );
        let (tc, n, all_ok) = answer_records(out);
        assert!(tc, "TC marks the dropped records");
        assert!(n > 1000, "most records still fit, got {n}");
        assert!(all_ok);
    }

    #[test]
    fn compressed_rdata_names_round_trip() {
        // CNAME is an RFC 1035 "well-known" type, so the crate compresses the
        // name inside its rdata too (RFC 3597 forbids that for newer types —
        // the policy lives in `domain`; this pins the round trip).
        use domain::rdata::Cname;
        let req = Message::from_octets(make_query(LONG_NAME, Rtype::A)).unwrap();
        let target = Name::<Vec<u8>>::from_str("edge.example.com.").unwrap();
        let answers = vec![
            OwnedRecord::new(
                Name::<Vec<u8>>::from_str(LONG_NAME).unwrap(),
                Class::IN,
                Ttl::from_secs(60),
                AllRecordData::Cname(Cname::new(target.clone())),
            ),
            OwnedRecord::new(
                target.clone(),
                Class::IN,
                Ttl::from_secs(60),
                AllRecordData::A(A::from_octets(5, 6, 7, 8)),
            ),
        ];
        let data = ResponseData {
            rcode: Rcode::NOERROR,
            answers: &answers,
            authority: &[],
            additional: &[],
            ttl_override: None,
            edns: None,
            shuffle_qtype: Some(Rtype::A),
        };
        // Squeeze the budget to just under the plain size so the compressed
        // build is the one that gets sent.
        let plain = build_response(&req, &data, None);
        let out = build_response(&req, &data, Some((plain.len() - 1) as u16));
        assert!(
            out.len() < plain.len(),
            "compression must have been applied"
        );
        let msg = parse(out).unwrap();
        assert!(!msg.header().tc(), "both records still fit once compressed");
        let recs: Vec<_> = msg
            .answer()
            .unwrap()
            .limit_to::<AllRecordData<_, _>>()
            .map(|r| r.expect("parses"))
            .collect();
        assert_eq!(recs.len(), 2);
        let cname = recs
            .iter()
            .find(|r| r.rtype() == Rtype::CNAME)
            .expect("the CNAME survived");
        match cname.data() {
            AllRecordData::Cname(c) => assert_eq!(
                c.cname().to_string().to_ascii_lowercase(),
                "edge.example.com"
            ),
            _ => panic!("expected a CNAME"),
        }
    }

    /// `assemble` and the `MessageBuilder` path must be indistinguishable —
    /// same header bits, same verbatim question, same records, byte for byte.
    /// That equivalence is the whole safety argument for writing the wire
    /// format by hand, so this sweeps the shapes that reach it in production
    /// plus the ones that must fall back.
    #[test]
    fn assemble_matches_the_builder() {
        use domain::rdata::{Aaaa, Cname, Ns, Soa, Txt};

        fn rec(owner: &str, data: OwnedData, ttl: u32) -> OwnedRecord {
            OwnedRecord::new(
                Name::<Vec<u8>>::from_str(owner).unwrap(),
                Class::IN,
                Ttl::from_secs(ttl),
                data,
            )
        }
        let n = |s: &str| Name::<Vec<u8>>::from_str(s).unwrap();
        let soa = OwnedData::Soa(Soa::new(
            n("ns.example.com."),
            n("hostmaster.example.com."),
            domain::base::Serial(42),
            Ttl::from_secs(7200),
            Ttl::from_secs(3600),
            Ttl::from_secs(1209600),
            Ttl::from_secs(300),
        ));
        let answers = [
            rec(
                "www.example.com.",
                OwnedData::Cname(Cname::new(n("edge.example.org."))),
                60,
            ),
            rec(
                "edge.example.org.",
                OwnedData::A(A::from_octets(1, 2, 3, 4)),
                300,
            ),
            rec(
                "edge.example.org.",
                OwnedData::Aaaa(Aaaa::new("2001:db8::1".parse().unwrap())),
                300,
            ),
            rec(
                "edge.example.org.",
                OwnedData::Txt(Txt::build_from_slice(b"hello world").unwrap()),
                120,
            ),
        ];
        let authority = [
            rec("example.com.", soa, 3600),
            rec(
                "example.com.",
                OwnedData::Ns(Ns::new(n("ns.example.com."))),
                3600,
            ),
        ];
        let additional = [rec(
            "ns.example.com.",
            OwnedData::A(A::from_octets(9, 9, 9, 9)),
            3600,
        )];

        // Request shapes, including ones the fast path must hand back.
        let two_questions = {
            let mut b = MessageBuilder::new_vec();
            b.header_mut().set_rd(true);
            let mut q = b.question();
            q.push((n("a.example."), Rtype::A)).unwrap();
            q.push((n("b.example."), Rtype::A)).unwrap();
            q.finish()
        };
        let mut no_question = make_query("x.example.", Rtype::A);
        no_question[4] = 0;
        no_question[5] = 0;
        no_question.truncate(12);
        let mut opcode_update = make_query("u.example.", Rtype::A);
        opcode_update[2] |= 0x28; // opcode 5, RD kept
        let mut no_rd = make_query("nord.example.", Rtype::A);
        no_rd[2] &= !0x01;
        // Nonsense in a query, but a client can set them and the response must
        // not echo them: AA/TC in byte 2, Z/AD/CD in byte 3.
        let mut junk_flags = make_query("flags.example.", Rtype::A);
        junk_flags[2] |= 0x06;
        junk_flags[3] |= 0x70;
        let requests: [Vec<u8>; 8] = [
            make_query("www.example.com.", Rtype::A),
            make_query(".", Rtype::NS),
            query_with_edns(1232),
            no_rd,
            junk_flags,
            opcode_update,
            no_question,
            two_questions,
        ];

        let mut checked = 0;
        for raw in &requests {
            let req = Message::from_octets(raw.clone()).unwrap();
            for rcode in [
                Rcode::NOERROR,
                Rcode::NXDOMAIN,
                Rcode::SERVFAIL,
                Rcode::REFUSED,
            ] {
                for edns in [
                    None,
                    Some(ClientEdns { udp_size: 1232 }),
                    Some(ClientEdns { udp_size: 200 }),
                    Some(ClientEdns { udp_size: 9000 }),
                ] {
                    for ttl_override in [None, Some(1), Some(86400)] {
                        for (ans, auth, add) in [
                            (&answers[..], &authority[..], &additional[..]),
                            (&answers[..1], &[][..], &[][..]),
                            (&[][..], &authority[..1], &[][..]),
                            (&[][..], &[][..], &[][..]),
                        ] {
                            let data = ResponseData {
                                rcode,
                                answers: ans,
                                authority: auth,
                                additional: add,
                                ttl_override,
                                edns,
                                // None: the shuffle would make the two builds
                                // disagree on record order by design.
                                shuffle_qtype: None,
                            };
                            let fast = assemble(&req, &data);
                            let slow =
                                fill(start(MessageBuilder::new_vec(), &req, data.rcode), &data);
                            assert_eq!(
                                fast,
                                slow,
                                "mismatch: rcode={rcode:?} edns={edns:?} ttl={ttl_override:?} \
                                 an={} ns={} ar={} req={raw:?}",
                                ans.len(),
                                auth.len(),
                                add.len()
                            );
                            // And it must be a message the parser accepts back.
                            assert!(parse(fast).is_some());
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert!(checked >= 300, "only {checked} combinations checked");
    }

    /// With the shuffle on, the two builds legitimately differ in record order,
    /// so compare content instead: same header, same record multiset.
    #[test]
    fn assemble_matches_the_builder_under_shuffle() {
        let req = Message::from_octets(make_query("example.com.", Rtype::A)).unwrap();
        let answers: Vec<OwnedRecord> = (0..6u8).map(|i| a_record("example.com.", i)).collect();
        let data = ResponseData {
            rcode: Rcode::NOERROR,
            answers: &answers,
            authority: &[],
            additional: &[],
            ttl_override: None,
            edns: Some(ClientEdns { udp_size: 1232 }),
            shuffle_qtype: Some(Rtype::A),
        };
        let sorted = |bytes: Vec<u8>| -> (Vec<u8>, Vec<String>) {
            let msg = parse(bytes).unwrap();
            let mut rrs: Vec<String> = msg
                .answer()
                .unwrap()
                .limit_to::<AllRecordData<_, _>>()
                .map(|r| format!("{:?}", r.unwrap().data()))
                .collect();
            rrs.sort();
            (msg.as_slice()[..12].to_vec(), rrs)
        };
        let fast = sorted(assemble(&req, &data));
        let slow = sorted(fill(
            start(MessageBuilder::new_vec(), &req, data.rcode),
            &data,
        ));
        assert_eq!(fast, slow, "header and record set must match under shuffle");
    }

    /// The direct OPT read must agree with the general `Message::opt` path on
    /// every message it claims to understand — including malformed ones, since
    /// it runs on unvalidated client input.
    #[test]
    fn fast_edns_agrees_with_the_general_path() {
        let mut state: u64 = 0xfeed_face_cafe_beef;
        let mut rnd = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut agreed = 0usize;
        let mut fast_used = 0usize;

        let mut check = |bytes: Vec<u8>| {
            if let Some(msg) = parse(bytes.clone()) {
                if opt_after_question(&bytes).is_some() {
                    fast_used += 1;
                }
                let fast = edns_of(&msg).map(|e| e.udp_size);
                let slow = edns_of_slow(&msg).map(|e| e.udp_size);
                assert_eq!(fast, slow, "disagreement on {bytes:?}");
                agreed += 1;
            }
        };

        // Well-formed queries, with and without OPT, across payload sizes.
        for size in [0u16, 512, 1232, 4096, 65535] {
            check(query_with_edns(size));
        }
        check(make_query("example.com.", Rtype::A));
        check(make_query(".", Rtype::NS));

        // An OPT-shaped record parked in the *answer* section, with the real
        // OPT (a different advertised size) after it. Reading at the fixed
        // offset without first checking that nothing precedes the additional
        // section would pick up the decoy.
        {
            let base = query_with_edns(1232);
            let qend = question_end(&base).unwrap();
            let mut m = base[..qend].to_vec();
            // root owner, type OPT, class 4096, ttl 0, rdlen 0
            m.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
            m.extend_from_slice(&base[qend..]);
            m[6] = 0;
            m[7] = 1; // ANCOUNT = 1
            check(m);
        }

        // A query whose additional section holds something *other* than an OPT
        // first — the direct read must decline and let the general path look.
        let mut two_additional = query_with_edns(1232);
        two_additional[10] = 0;
        two_additional[11] = 2;
        check(two_additional);

        // Truncated tails: the direct read must never index past the end.
        let full = query_with_edns(1232);
        for cut in 12..full.len() {
            check(full[..cut].to_vec());
        }

        // Random garbage: almost all of it is rejected outright, which is
        // itself worth pinning.
        for _ in 0..30_000 {
            let len = (rnd() % 80) as usize;
            check((0..len).map(|_| (rnd() & 0xff) as u8).collect());
        }
        // Counts kept plausible, body corrupted — this is the corpus that
        // actually drives the direct read.
        let mut fast_seen = 0usize;
        for _ in 0..40_000 {
            let mut bytes = query_with_edns(1232);
            let n = bytes.len();
            for _ in 0..1 + rnd() % 3 {
                bytes[12 + (rnd() as usize % (n - 12))] = (rnd() & 0xff) as u8;
            }
            if opt_after_question(&bytes).is_some() {
                fast_seen += 1;
            }
            check(bytes);
        }
        // Counts corrupted too — drives the fallback.
        for _ in 0..30_000 {
            let mut bytes = query_with_edns(1232);
            for idx in [4usize, 5, 6, 7, 8, 9, 10, 11] {
                bytes[idx] = (rnd() & 0xff) as u8;
            }
            let n = bytes.len();
            bytes[12 + (rnd() as usize % (n - 12))] = (rnd() & 0xff) as u8;
            check(bytes);
        }
        assert!(agreed > 20_000, "only {agreed} messages compared");
        assert!(
            fast_seen > 10_000,
            "direct read only applied to {fast_seen} of the structured corpus"
        );
        assert!(
            fast_used > 10_000,
            "direct read used {fast_used} times overall"
        );
    }
}
