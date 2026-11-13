// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! DNS upstreams and the concurrent failover forwarder — the data-plane heart.
//!
//! Each `Forwarder` fans a query out to up to 3 randomly-chosen upstreams and
//! takes the first NOERROR answer, cancelling the rest. UDP upstreams fall back
//! to TCP when the answer is truncated (RFC 1035).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use domain::base::iana::{OptRcode, Rcode};
use domain::base::Message;
use domain::rdata::AllRecordData;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::dns;
use crate::rng;

const MAX_CONCURRENT_QUERIES: usize = 3;
/// Upstreams beyond this are ignored so the per-query shuffle scratch stays on
/// the stack (allocation-free). A failover forwarder with >16 upstreams is a
/// misconfiguration.
pub const MAX_UPSTREAMS: usize = 16;
const UDP_RECV_BUF: usize = 4096;
const TCP_MAX_MSG: usize = 65535;
/// Cap on idle connections retained per upstream (bounds fd usage under bursts).
const MAX_IDLE_CONNS: usize = 128;
/// How long a pooled connection may sit idle before it is dropped instead of
/// reused. Comfortably under the shortest NAT/conntrack idle timeouts a home
/// router runs with, so a reused connection is one the path still carries.
const MAX_IDLE_AGE: Duration = Duration::from_secs(10);
/// Consecutive hard failures (timeout / socket error / unparseable reply) that
/// trip the main upstream's breaker. Large enough that ordinary packet loss
/// cannot trip it — five independent losses in a row — small enough to react
/// within a handful of queries.
const BREAKER_FAILS: u32 = 5;
/// How long a tripped upstream is skipped before one probe is let through.
/// One second, so recovery is noticed almost immediately — switching *back* to
/// the main DNS has to stay fast. Counted in deciseconds: whole seconds would
/// round the deadline down to the current second, cutting the cooldown to
/// whatever is left of it. `u32` deciseconds still spans 13 years, and the
/// 32-bit MIPS targets have no 64-bit atomics.
const BREAKER_COOLDOWN_DS: u32 = 10;
/// Upstream label reported when the breaker answered instead of the network.
const CIRCUIT_OPEN: &str = "circuit-open";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Udp,
    Tcp,
}

/// A single DNS upstream endpoint. Connected sockets are pooled and reused
/// across queries (far fewer syscalls than dialing per query) while each query
/// still owns its socket for the recv, preserving fast failover on a dead peer.
pub struct Upstream {
    addr: SocketAddr,
    kind: Kind,
    /// Human-readable label used in logs (the normalized `scheme://host:port`).
    /// `Arc<str>` rather than `String`: every forwarded query hands this label
    /// to the logger/telemetry, and a refcount bump beats a heap copy.
    pub label: Arc<str>,
    /// Idle connected sockets, each carrying its own receive buffer so the hot
    /// path does not allocate (and zero) a fresh `UDP_RECV_BUF` per query.
    idle_udp: Mutex<Vec<(UdpSocket, Vec<u8>)>>,
    /// Idle connections with the moment each was returned: one a NAT or
    /// firewall has blackholed answers nothing and has no FIN to notice, so a
    /// query on it burns the whole deadline. Anything idle past
    /// [`MAX_IDLE_AGE`] is dropped rather than reused.
    idle_tcp: Mutex<Vec<(TcpStream, Instant)>>,
}

impl Upstream {
    /// Parse a normalized `scheme://ip:port` URL (see `util::format_upstream_addr`).
    pub fn parse(url: &str) -> Result<Upstream, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| format!("missing scheme in upstream {url:?}"))?;
        let kind = match scheme {
            "" | "udp" => Kind::Udp,
            // Pipelining is a throughput optimization; behaviorally it is TCP.
            "tcp" | "tcp+pipeline" => Kind::Tcp,
            other => return Err(format!("unsupported upstream scheme {other:?}")),
        };
        let addr: SocketAddr = rest
            .parse()
            .map_err(|_| format!("upstream address must be ip:port, got {rest:?}"))?;
        Ok(Upstream {
            addr,
            kind,
            label: Arc::from(url),
            idle_udp: Mutex::new(Vec::new()),
            idle_tcp: Mutex::new(Vec::new()),
        })
    }

    /// Send `query` and return the raw response bytes, honoring `deadline`
    /// across the whole exchange: a truncation-triggered TCP retry only gets
    /// whatever time the UDP leg left over.
    async fn query(&self, query: &[u8], deadline: Duration) -> Result<Vec<u8>, String> {
        match self.kind {
            Kind::Udp => {
                let start = Instant::now();
                let resp = timeout(deadline, self.query_udp(query))
                    .await
                    .map_err(|_| "timeout".to_string())??;
                // Truncated → retry over TCP (RFC 1035 fallback). A datagram
                // that exactly fills the receive buffer counts as truncated
                // too: the kernel drops the tail without reporting an error,
                // so the alternative is serving (and caching) a partial RRset.
                if resp.len() >= 3 && ((resp[2] & 0x02) != 0 || resp.len() == UDP_RECV_BUF) {
                    let remaining = deadline.saturating_sub(start.elapsed());
                    if remaining.is_zero() {
                        return Err("timeout".to_string());
                    }
                    return timeout(remaining, self.query_tcp(query))
                        .await
                        .map_err(|_| "timeout".to_string())?;
                }
                Ok(resp)
            }
            Kind::Tcp => timeout(deadline, self.query_tcp(query))
                .await
                .map_err(|_| "timeout".to_string())?,
        }
    }

    async fn query_udp(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        // Reuse a pooled connected socket, or dial a fresh one. The pop is its
        // own statement so the mutex guard never spans the dial `.await`.
        let pooled = self.idle_udp.lock().unwrap().pop();
        let (sock, mut buf) = match pooled {
            Some(pair) => pair,
            None => {
                let bind = if self.addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let s = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
                s.connect(self.addr).await.map_err(|e| e.to_string())?;
                (s, vec![0u8; UDP_RECV_BUF])
            }
        };
        sock.send(query).await.map_err(|e| e.to_string())?;
        // Byte offset just past our query's question section; a matching reply
        // must echo those bytes verbatim (see `reply_matches`).
        let qend = question_end(query);
        loop {
            // A recv error (e.g. ECONNREFUSED from a dead peer) propagates so the
            // forwarder fails over fast rather than waiting out the timeout.
            let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
            // Accept only a reply that matches the transaction ID *and* echoes
            // the question (RFC 5452 defence-in-depth: rejects off-path spoofs
            // and stale duplicates from a prior query on this reused socket).
            // Anything else is skipped and we keep waiting, bounded by the
            // caller's deadline — no fixed round cap, which could otherwise drop
            // a valid late answer that trailed a few stale datagrams.
            if reply_matches(&buf[..n], query, qend)
                && ((buf[2] & 0x02) != 0 || n == UDP_RECV_BUF || response_is_complete(&buf[..n]))
            {
                // TC and buffer-filling replies may end halfway through an
                // RR. Validate only their header/question here: `query` will
                // retry them over TCP before anything reaches the forwarder.
                // Copy out the exact response bytes and return the (still
                // full-size) scratch buffer to the pool with its socket. Only
                // `buf[..n]` is ever read, so bytes left over from an earlier,
                // longer reply are never observable.
                let resp = buf[..n].to_vec();
                let mut idle = self.idle_udp.lock().unwrap();
                if idle.len() < MAX_IDLE_CONNS {
                    idle.push((sock, buf));
                }
                return Ok(resp);
            }
        }
    }

    async fn query_tcp(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        // Try a pooled connection; on failure (peer may have closed an idle
        // conn) retry once with a fresh dial.
        let pooled = {
            let mut idle = self.idle_tcp.lock().unwrap();
            match idle.pop() {
                Some((stream, since)) if since.elapsed() <= MAX_IDLE_AGE => Some(stream),
                // Returned connections are pushed, so the rest of the pool is
                // older still: it is all past its idle limit too.
                Some(_) => {
                    idle.clear();
                    None
                }
                None => None,
            }
        };
        if let Some(stream) = pooled {
            if let Ok(resp) = self.tcp_exchange(stream, query).await {
                return Ok(resp);
            }
        }
        let stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        self.tcp_exchange(stream, query).await
    }

    async fn tcp_exchange(&self, mut stream: TcpStream, query: &[u8]) -> Result<Vec<u8>, String> {
        let len = u16::try_from(query.len()).map_err(|_| "query too large".to_string())?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(query).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| e.to_string())?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > TCP_MAX_MSG {
            return Err(format!("bad TCP response length {resp_len}"));
        }
        let mut resp = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp)
            .await
            .map_err(|e| e.to_string())?;
        // A protocol-violating peer can send a stale or malformed response on
        // a connected stream too. Validate it before returning the connection
        // to the pool (the caller can redial after a failed pooled exchange).
        if !reply_matches(&resp, query, question_end(query)) {
            return Err("tcp reply header/question mismatch".to_string());
        }
        if !response_is_complete(&resp) {
            return Err("malformed tcp reply".to_string());
        }
        let mut idle = self.idle_tcp.lock().unwrap();
        if idle.len() < MAX_IDLE_CONNS {
            idle.push((stream, Instant::now()));
        }
        Ok(resp)
    }
}

/// Give this attempt its own DNS transaction ID, in place. Every hop draws
/// independently: the three fan-out copies of one query, and the fallback stage
/// after the main stage, must not share an ID (RFC 5452 §9 — ID entropy is
/// per-query, not per-client-request). Uses `getrandom` rather than
/// `rng::next_u64`, which is explicitly documented as non-cryptographic; on
/// failure the ID built by `dns::build_upstream_query` (already CSPRNG) stands.
fn randomize_id(query: &mut [u8]) {
    if query.len() >= 2 {
        let mut id = [0u8; 2];
        if getrandom::fill(&mut id).is_ok() {
            query[0..2].copy_from_slice(&id);
        }
    }
}

/// Byte offset just past the question section of a well-formed query
/// (header 12 + QNAME + QTYPE(2) + QCLASS(2)). `None` if the QNAME is malformed
/// or runs off the end — only possible for a caller-broken query, never for one
/// built by `dns::build_upstream_query`.
fn question_end(query: &[u8]) -> Option<usize> {
    let mut i = 12usize;
    loop {
        let len = *query.get(i)? as usize;
        if len == 0 {
            let end = i + 1 + 4; // zero label + QTYPE + QCLASS
            return (end <= query.len()).then_some(end);
        }
        // Question QNAMEs are never compressed; reject a pointer/reserved label.
        if len & 0xC0 != 0 {
            return None;
        }
        i += 1 + len;
    }
}

/// Whether `reply` has the matching response header and question. The question
/// sits at the same offset (12) in query and reply, uncompressed, so a byte
/// compare is sufficient and stricter than a parse (it also pins QTYPE/QCLASS). A reply
/// carrying no question (QDCOUNT==0, as some servers' error replies do) is
/// accepted only for an error rcode, preserving those servers' error replies.
fn reply_matches(reply: &[u8], query: &[u8], qend: Option<usize>) -> bool {
    if reply.len() < 12
        || query.len() < 12
        || reply[0..2] != query[0..2]
        || reply[2] & 0x80 == 0
        || reply[2] & 0x78 != query[2] & 0x78
    {
        return false;
    }
    let qdcount = u16::from_be_bytes([reply[4], reply[5]]);
    if qdcount == 0 {
        if reply[3] & 0x0f != 0 {
            return true;
        }
        // EDNS errors such as BADVERS have zero in the header's rcode bits.
        // Only this questionless case needs the extra OPT lookup. Parsing the
        // OPT also rejects a cut-off record or malformed option lengths;
        // complete replies still undergo the full record validation below.
        return Message::from_octets(reply).ok().is_some_and(|msg| {
            msg.opt()
                .is_some_and(|opt| opt.rcode(msg.header()) != OptRcode::NOERROR)
        });
    }
    if qdcount != 1 || query[4..6] != [0, 1] {
        return false;
    }
    match qend {
        Some(end) => reply.len() >= end && reply[12..end] == query[12..end],
        None => false,
    }
}

/// `Message::from_octets` only checks the header length. Walk every question
/// and every record, including its typed RDATA, before accepting a complete
/// response. Otherwise a valid first RR can hide a malformed later RR and be
/// forwarded/cached as a successful partial answer. AllRecordData also keeps
/// unknown record types as opaque data, as DNS requires.
fn response_is_complete(reply: &[u8]) -> bool {
    let Ok(msg) = Message::from_octets(reply) else {
        return false;
    };
    let mut questions = msg.question();
    if questions.by_ref().any(|question| question.is_err()) {
        return false;
    }
    let Ok(mut section) = questions.next_section() else {
        return false;
    };
    loop {
        let mut records = section.into_records::<AllRecordData<_, _>>();
        if records.by_ref().any(|record| record.is_err()) {
            return false;
        }
        match records.next_section() {
            Ok(Some(next)) => section = next,
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

/// One concurrent query's result: the upstream label, its latency, and the
/// parsed response (or an error string).
type QueryOutcome = (Arc<str>, Duration, Result<Message<Vec<u8>>, String>);

/// Fail-fast breaker for the *main* forwarder.
///
/// A main DNS that refuses packets fails immediately, but one that has gone
/// silent (link down, firewall DROP, hung process) costs every query the full
/// `qtime` before the fallback is tried at all. After `BREAKER_FAILS`
/// consecutive hard failures this reports the upstream as down without touching
/// the network, so queries reach the fallback with no added latency.
///
/// Switching *back* must stay fast, so the cooldown is one second and exactly
/// one query per cooldown is let through to probe (a `probing` latch keeps a
/// burst from piling onto the dead upstream). One successful probe closes it.
///
/// A parsed response counts as success even when it is SERVFAIL or NXDOMAIN:
/// the upstream is alive and the rcode-based failover handles the rest. Only
/// transport-level failures count against it.
struct Breaker {
    base: Instant,
    /// Consecutive hard failures.
    fails: AtomicU32,
    /// Cooldown deadline, deciseconds since `base`; 0 means "closed" (not
    /// tripped). `AtomicU32`, never `AtomicU64`: 32-bit MIPS release targets
    /// have no 64-bit atomics. Deciseconds give 13 years of headroom.
    open_until: AtomicU32,
    /// Held by the one query currently probing a tripped upstream.
    probing: AtomicBool,
    label: Arc<str>,
}

/// What the breaker says about this attempt.
enum Admit<'a> {
    /// Not tripped — go to the network.
    Closed,
    /// Tripped and still cooling down — fail immediately.
    Open,
    /// Cooldown elapsed and this call won the latch: it is the probe.
    Probe(ProbeGuard<'a>),
}

/// Releases the probe latch however the attempt ends — including when the task
/// is cancelled mid-flight, which would otherwise wedge the breaker half-open.
struct ProbeGuard<'a>(&'a AtomicBool);

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Breaker {
    fn new() -> Self {
        Breaker {
            base: Instant::now(),
            fails: AtomicU32::new(0),
            open_until: AtomicU32::new(0),
            probing: AtomicBool::new(false),
            label: Arc::from(CIRCUIT_OPEN),
        }
    }

    fn now_ds(&self) -> u32 {
        (self.base.elapsed().as_millis() / 100) as u32
    }

    fn admit(&self) -> Admit<'_> {
        let until = self.open_until.load(Ordering::Relaxed);
        if until == 0 {
            return Admit::Closed;
        }
        if self.now_ds() < until {
            return Admit::Open;
        }
        // Cooldown elapsed: exactly one caller becomes the probe, the rest keep
        // failing fast until it reports back.
        match self
            .probing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        {
            Ok(_) => Admit::Probe(ProbeGuard(&self.probing)),
            Err(_) => Admit::Open,
        }
    }

    fn record(&self, ok: bool) {
        if ok {
            // One success is enough: close immediately so the main DNS is used
            // again on the very next query.
            self.fails.store(0, Ordering::Relaxed);
            self.open_until.store(0, Ordering::Relaxed);
            return;
        }
        let fails = self.fails.fetch_add(1, Ordering::Relaxed) + 1;
        if fails >= BREAKER_FAILS {
            // Also re-arms after a failed probe, which lands here with the
            // streak already past the threshold.
            self.open_until
                .store(self.now_ds() + BREAKER_COOLDOWN_DS, Ordering::Relaxed);
        }
    }
}

/// A pool of upstreams queried concurrently with failover.
pub struct Forwarder {
    upstreams: Vec<Arc<Upstream>>,
    timeout: Duration,
    /// Only the main forwarder gets one: skipping the *fallback* would leave
    /// the query with nowhere to go.
    breaker: Option<Breaker>,
}

/// Outcome of a forward attempt.
pub struct ForwardResult {
    /// The chosen response (first NOERROR, else first non-error), if any.
    pub response: Option<Message<Vec<u8>>>,
    /// Label of the upstream that answered, or "timeout/err".
    pub upstream: Arc<str>,
    pub duration: Duration,
    pub had_error: bool,
}

impl Forwarder {
    /// Whether the breaker is currently refusing queries (tests only).
    #[cfg(test)]
    pub fn breaker_is_open(&self) -> bool {
        self.breaker
            .as_ref()
            .is_some_and(|b| b.open_until.load(Ordering::Relaxed) != 0)
    }

    /// Descriptors one in-flight query can hold here: the fan-out asks this
    /// many upstreams at once, each on its own socket.
    pub fn sockets_per_query(&self) -> usize {
        MAX_CONCURRENT_QUERIES.min(self.upstreams.len()).max(1)
    }
    pub fn new(upstreams: Vec<Arc<Upstream>>, timeout: Duration) -> Self {
        Forwarder {
            upstreams,
            timeout,
            breaker: None,
        }
    }

    /// The main forwarder: adds the fail-fast breaker (see [`Breaker`]).
    pub fn with_breaker(upstreams: Vec<Arc<Upstream>>, timeout: Duration) -> Self {
        Forwarder {
            upstreams,
            timeout,
            breaker: Some(Breaker::new()),
        }
    }

    /// Fan `query` out to up to 3 shuffled upstreams; return the first NOERROR
    /// response (cancelling the rest), else the first non-success response,
    /// else an error result.
    /// `query` is mutated in place: each attempt stamps its own transaction ID
    /// (see `randomize_id`).
    pub async fn exec(&self, query: &mut [u8]) -> ForwardResult {
        let probe = match self.breaker.as_ref().map(Breaker::admit) {
            Some(Admit::Open) => {
                // Tripped: report the failure without touching the network so
                // the caller moves straight on to the fallback.
                let label = self
                    .breaker
                    .as_ref()
                    .map(|b| b.label.clone())
                    .unwrap_or_else(|| Arc::from(CIRCUIT_OPEN));
                return ForwardResult {
                    response: None,
                    upstream: label,
                    duration: Duration::ZERO,
                    had_error: true,
                };
            }
            Some(Admit::Probe(guard)) => Some(guard),
            _ => None,
        };
        let out = self.exec_inner(query).await;
        if let Some(b) = &self.breaker {
            b.record(!out.had_error);
        }
        drop(probe);
        out
    }

    async fn exec_inner(&self, query: &mut [u8]) -> ForwardResult {
        let start = Instant::now();
        let n = self.upstreams.len();
        if n == 0 {
            return ForwardResult {
                response: None,
                upstream: Arc::from("timeout/err"),
                duration: Duration::ZERO,
                had_error: true,
            };
        }
        // Single upstream (the common config): query it inline. The JoinSet +
        // per-attempt task spawn below costs forward-path CPU and buys nothing
        // when there is no fan-out.
        if n == 1 {
            randomize_id(query);
            let up = &self.upstreams[0];
            let parsed = match up.query(query, self.timeout).await {
                Ok(bytes) => dns::parse(bytes).ok_or_else(|| "unpack failed".to_string()),
                Err(e) => Err(e),
            };
            let duration = start.elapsed();
            return match parsed {
                Ok(msg) => ForwardResult {
                    response: Some(msg),
                    upstream: up.label.clone(),
                    duration,
                    had_error: false,
                },
                Err(_) => ForwardResult {
                    response: None,
                    upstream: up.label.clone(),
                    duration,
                    had_error: true,
                },
            };
        }
        // Cap the working set so the index scratch lives on the stack.
        let n = n.min(MAX_UPSTREAMS);
        let concurrent = MAX_CONCURRENT_QUERIES.min(n);
        let mut idx = [0usize; MAX_UPSTREAMS];
        for (i, slot) in idx.iter_mut().enumerate().take(n) {
            *slot = i;
        }
        rng::partial_shuffle(&mut idx[..n], concurrent);

        let mut set: JoinSet<QueryOutcome> = JoinSet::new();
        for &i in idx[..concurrent].iter() {
            let up = self.upstreams[i].clone();
            // Each fan-out copy carries its own transaction ID.
            let mut q = query.to_vec();
            randomize_id(&mut q);
            let to = self.timeout;
            set.spawn(async move {
                let started = Instant::now();
                let parsed = match up.query(&q, to).await {
                    Ok(bytes) => dns::parse(bytes).ok_or_else(|| "unpack failed".to_string()),
                    Err(e) => Err(e),
                };
                (up.label.clone(), started.elapsed(), parsed)
            });
        }

        let mut fallback: Option<(Arc<str>, Duration, Message<Vec<u8>>)> = None;
        let mut first_err: Option<(Arc<str>, Duration)> = None;
        while let Some(joined) = set.join_next().await {
            let Ok((label, dur, parsed)) = joined else {
                continue;
            };
            match parsed {
                Ok(msg) => {
                    if msg.header().rcode() == Rcode::NOERROR {
                        // Winner: dropping `set` aborts the pending queries.
                        return ForwardResult {
                            response: Some(msg),
                            upstream: label,
                            duration: dur,
                            had_error: false,
                        };
                    }
                    if fallback.is_none() {
                        fallback = Some((label, dur, msg));
                    }
                }
                Err(_) => {
                    if first_err.is_none() {
                        first_err = Some((label, dur));
                    }
                }
            }
        }

        if let Some((label, dur, msg)) = fallback {
            return ForwardResult {
                response: Some(msg),
                upstream: label,
                duration: dur,
                had_error: false,
            };
        }
        if let Some((label, dur)) = first_err {
            return ForwardResult {
                response: None,
                upstream: label,
                duration: dur,
                had_error: true,
            };
        }
        ForwardResult {
            response: None,
            upstream: Arc::from("timeout/err"),
            duration: start.elapsed(),
            had_error: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::base::iana::Rtype;
    use domain::base::{MessageBuilder, Name};
    use std::str::FromStr;

    #[test]
    fn a_query_claims_one_socket_per_upstream_it_fans_out_to() {
        let fwd = |n: usize| {
            Forwarder::new(
                (0..n)
                    .map(|i| {
                        Arc::new(
                            Upstream::parse(&format!("udp://127.0.0.1:{}", 60000 + i)).unwrap(),
                        )
                    })
                    .collect(),
                Duration::from_millis(100),
            )
        };
        // The descriptor budget is derived from this, so it has to track the
        // fan-out the forwarder actually performs.
        assert_eq!(
            fwd(0).sockets_per_query(),
            1,
            "an empty forwarder holds one"
        );
        assert_eq!(fwd(1).sockets_per_query(), 1);
        assert_eq!(fwd(2).sockets_per_query(), 2);
        assert_eq!(fwd(3).sockets_per_query(), MAX_CONCURRENT_QUERIES);
        assert_eq!(fwd(9).sockets_per_query(), MAX_CONCURRENT_QUERIES);
    }

    #[test]
    fn parse_schemes() {
        assert_eq!(Upstream::parse("udp://1.2.3.4:53").unwrap().kind, Kind::Udp);
        assert_eq!(Upstream::parse("tcp://1.2.3.4:53").unwrap().kind, Kind::Tcp);
        assert_eq!(
            Upstream::parse("tcp+pipeline://1.2.3.4:53").unwrap().kind,
            Kind::Tcp
        );
        assert!(Upstream::parse("udp://[::1]:53").unwrap().addr.is_ipv6());
        assert!(Upstream::parse("1.2.3.4:53").is_err()); // no scheme
        assert!(Upstream::parse("https://1.2.3.4:443").is_err()); // unsupported
    }

    fn query() -> Vec<u8> {
        let mut b = MessageBuilder::new_vec();
        b.header_mut().set_rd(true);
        b.header_mut().set_random_id();
        let mut q = b.question();
        q.push((Name::<Vec<u8>>::from_str("example.com.").unwrap(), Rtype::A))
            .unwrap();
        q.finish()
    }

    /// UDP mock that replies to every query with the given rcode (echoing id).
    async fn mock(rcode: Rcode) -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if let Some(msg) = dns::parse(buf[..n].to_vec()) {
                    let resp = MessageBuilder::new_vec()
                        .start_answer(&msg, rcode)
                        .unwrap()
                        .finish();
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });
        format!("udp://{addr}")
    }

    fn fwd(addrs: &[String], to_ms: u64) -> Forwarder {
        Forwarder::new(
            addrs
                .iter()
                .map(|a| Arc::new(Upstream::parse(a).unwrap()))
                .collect(),
            Duration::from_millis(to_ms),
        )
    }

    #[tokio::test]
    async fn first_noerror_wins() {
        let bad = mock(Rcode::SERVFAIL).await;
        let good = mock(Rcode::NOERROR).await;
        let f = fwd(&[bad, good], 500);
        let r = f.exec(&mut query()).await;
        assert!(!r.had_error);
        assert_eq!(r.response.unwrap().header().rcode(), Rcode::NOERROR);
    }

    #[tokio::test]
    async fn non_success_is_surfaced_not_dropped() {
        let bad = mock(Rcode::SERVFAIL).await;
        let f = fwd(&[bad], 500);
        let r = f.exec(&mut query()).await;
        assert!(!r.had_error); // a parsed non-NOERROR is still a response
        assert_eq!(r.response.unwrap().header().rcode(), Rcode::SERVFAIL);
    }

    #[tokio::test]
    async fn all_dead_reports_error() {
        let f = fwd(&["udp://127.0.0.1:1".to_string()], 200);
        let r = f.exec(&mut query()).await;
        assert!(r.had_error);
        assert!(r.response.is_none());
    }

    #[test]
    fn question_end_and_reply_matching() {
        let q = query(); // A? example.com. (no OPT)
        let qend = question_end(&q);
        assert_eq!(qend, Some(29)); // 12 header + 13 qname + 4 (qtype+qclass)

        // Verbatim echo with matching id and QR set matches.
        let mut good = q.clone();
        good[2] |= 0x80; // QR
        assert!(reply_matches(&good, &q, qend));

        // A different question is rejected.
        let mut bad = good.clone();
        bad[13] ^= 0xFF; // corrupt a QNAME byte
        assert!(!reply_matches(&bad, &q, qend));

        // A valid error reply may omit its question.
        let mut noq = good.clone();
        noq[3] = 2; // SERVFAIL
        noq[4] = 0;
        noq[5] = 0;
        noq.truncate(12);
        assert!(reply_matches(&noq, &q, qend));

        // Too-short datagram is rejected.
        assert!(!reply_matches(&q[..4], &q, qend));
    }

    fn response(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] |= 0x80;
        response
    }

    #[test]
    fn response_validation_requires_qr() {
        let q = query();
        assert!(!reply_matches(&q, &q, question_end(&q)));
    }

    #[test]
    fn response_validation_requires_matching_opcode() {
        let q = query();
        let mut reply = response(&q);
        reply[2] |= 0x08;
        assert!(!reply_matches(&reply, &q, question_end(&q)));
    }

    #[test]
    fn response_validation_requires_matching_id() {
        let q = query();
        let mut reply = response(&q);
        reply[0] ^= 0xff;
        assert!(!reply_matches(&reply, &q, question_end(&q)));
    }

    #[test]
    fn response_validation_requires_exact_question_count() {
        let q = query();
        let mut reply = response(&q);
        reply[5] = 2;
        reply.extend_from_slice(&q[12..]);
        assert!(!reply_matches(&reply, &q, question_end(&q)));
    }

    #[test]
    fn response_validation_rejects_success_without_question() {
        let q = query();
        let mut reply = response(&q);
        reply[5] = 0;
        reply.truncate(12);
        assert!(!reply_matches(&reply, &q, question_end(&q)));
    }

    #[test]
    fn response_validation_accepts_error_without_question() {
        let q = query();
        let mut reply = response(&q);
        reply[3] = 2; // SERVFAIL
        reply[5] = 0;
        reply.truncate(12);
        assert!(reply_matches(&reply, &q, question_end(&q)));
    }

    fn questionless_edns_reply(query: &[u8], extended_rcode: u8) -> Vec<u8> {
        let mut reply = response(query);
        reply[3] &= 0xf0;
        reply[5] = 0;
        reply[11] = 1;
        reply.truncate(12);
        // Root OPT, UDP payload 1232, version 0, no flags or options.
        reply.extend_from_slice(&[0, 0, 41, 4, 208, extended_rcode, 0, 0, 0, 0, 0]);
        reply
    }

    #[test]
    fn response_validation_accepts_questionless_edns_error() {
        let q = query();
        // BADVERS = 16 has a zero header rcode and a nonzero OPT rcode.
        let mut reply = questionless_edns_reply(&q, 1);
        assert!(reply_matches(&reply, &q, question_end(&q)));
        // Unknown but well-formed EDNS options must remain acceptable.
        reply[22] = 5;
        reply.extend_from_slice(&[0xfd, 0xe8, 0, 1, 42]);
        assert!(reply_matches(&reply, &q, question_end(&q)));
    }

    #[tokio::test]
    async fn response_validation_rejects_questionless_success_and_malformed_edns() {
        let q = query();
        let badvers = questionless_edns_reply(&q, 1);
        let mut replies = vec![questionless_edns_reply(&q, 0)];
        // No complete OPT exists at any truncation point.
        replies.extend((12..badvers.len()).map(|end| badvers[..end].to_vec()));
        let mut missing_opt = badvers.clone();
        missing_opt[11] = 0;
        replies.push(missing_opt);
        let mut short_option = badvers;
        short_option[22] = 5;
        short_option.extend_from_slice(&[0xfd, 0xe8, 0, 2, 42]);
        replies.push(short_option);
        for reply in replies {
            assert!(!reply_matches(&reply, &q, question_end(&q)));
            assert_eq!(tcp_response_result(reply.clone(), &q).await, (false, 0));
            udp_ignores_invalid_reply(reply, &q).await;
        }
    }

    /// A valid first A RR followed by one of three malformed records: a
    /// complete but wrongly sized A RDATA, a cut-off RDATA, or a CNAME whose
    /// target pointer leaves the message. A record-header-only scan would
    /// miss the first and third cases.
    fn malformed_records(query: &[u8], count_offset: usize) -> [Vec<u8>; 3] {
        [
            (1u16, 3u16, &[192, 0, 2][..]),
            (1, 3, &[192, 0][..]),
            (5, 2, &[0xc0, 0xff][..]),
        ]
        .map(|(rtype, rdlength, data)| {
            let mut reply = response(query);
            reply[count_offset + 1] = 2;
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
            reply.extend_from_slice(&[0xc0, 0x0c]);
            reply.extend_from_slice(&rtype.to_be_bytes());
            reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            reply.extend_from_slice(&rdlength.to_be_bytes());
            reply.extend_from_slice(data);
            reply
        })
    }

    async fn tcp_response_result(reply: Vec<u8>, query: &[u8]) -> (bool, usize) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = Upstream::parse(&format!("tcp://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let len = stream.read_u16().await.unwrap() as usize;
            let mut request = vec![0; len];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_u16(reply.len() as u16).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        let result = up.query(query, Duration::from_secs(1)).await;
        server.await.unwrap();
        let pooled = up.idle_tcp.lock().unwrap().len();
        (result.is_ok(), pooled)
    }

    #[tokio::test]
    async fn response_validation_tcp_rejects_wrong_question_without_pooling() {
        let q = query();
        let mut reply = response(&q);
        reply[13] = b'X';
        assert_eq!(tcp_response_result(reply, &q).await, (false, 0));
    }

    #[tokio::test]
    async fn response_validation_tcp_rejects_invalid_headers_without_pooling() {
        let q = query();
        for (offset, value) in [(2, q[2]), (2, 0x88), (5, 0), (5, 2)] {
            let mut reply = response(&q);
            reply[offset] = value;
            assert_eq!(
                tcp_response_result(reply, &q).await,
                (false, 0),
                "invalid header at byte {offset}: {value}"
            );
        }
    }

    /// The valid SERVFAIL arrives after the invalid NOERROR. Checking the
    /// returned rcode proves the first datagram was ignored, without relying
    /// on an absence-of-response timeout.
    async fn udp_ignores_invalid_reply(reply: Vec<u8>, query: &[u8]) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up = Upstream::parse(&format!("udp://{}", socket.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&reply, peer).await.unwrap();
            let mut good = response(&buf[..n]);
            good[3] = 2;
            socket.send_to(&good, peer).await.unwrap();
        });
        let reply = up.query(query, Duration::from_secs(1)).await.unwrap();
        server.await.unwrap();
        assert_eq!(reply[3] & 0x0f, 2, "must skip the invalid NOERROR");
    }

    #[tokio::test]
    async fn response_validation_udp_ignores_invalid_headers() {
        let q = query();
        for (offset, value) in [(2, q[2]), (2, 0x88), (5, 0), (5, 2)] {
            let mut reply = response(&q);
            reply[offset] = value;
            udp_ignores_invalid_reply(reply, &q).await;
        }
    }

    #[tokio::test]
    async fn response_validation_udp_ignores_malformed_record_in_every_section() {
        let q = query();
        for offset in [6, 8, 10] {
            for reply in malformed_records(&q, offset) {
                udp_ignores_invalid_reply(reply, &q).await;
            }
        }
    }

    #[tokio::test]
    async fn response_validation_tcp_rejects_malformed_record_in_every_section() {
        let q = query();
        for offset in [6, 8, 10] {
            for reply in malformed_records(&q, offset) {
                assert_eq!(
                    tcp_response_result(reply, &q).await,
                    (false, 0),
                    "malformed record in section with count at {offset}"
                );
            }
        }
    }

    #[tokio::test]
    async fn response_validation_accepts_unknown_records_and_questionless_errors() {
        let q = query();
        let mut unknown = response(&q);
        unknown[7] = 1;
        // Private-use TYPE65280 with opaque RDATA, including pointer-like bytes.
        unknown.extend_from_slice(&[0xc0, 0x0c, 0xff, 0, 0, 1, 0, 0, 0, 60, 0, 3, 0xc0, 0xff, 0]);
        let mut error = response(&q);
        error[3] = 2;
        error[5] = 0;
        error.truncate(12);
        for expected in [unknown, error, questionless_edns_reply(&q, 1)] {
            assert_eq!(tcp_response_result(expected.clone(), &q).await, (true, 1));
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let up = Upstream::parse(&format!("udp://{}", socket.local_addr().unwrap())).unwrap();
            let reply = expected.clone();
            let server = tokio::spawn(async move {
                let mut buf = [0; 512];
                let (_, peer) = socket.recv_from(&mut buf).await.unwrap();
                socket.send_to(&reply, peer).await.unwrap();
            });
            assert_eq!(
                up.query(&q, Duration::from_secs(1)).await.unwrap(),
                expected
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn response_validation_truncated_partial_record_retries_over_tcp() {
        let q = query();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let up = Upstream::parse(&format!("udp://{addr}")).unwrap();
        let udp = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let mut reply = response(&buf[..n]);
            reply[2] |= 0x02;
            reply[7] = 1;
            reply.push(0xc0); // RR cut in the middle of its owner pointer.
            socket.send_to(&reply, peer).await.unwrap();
        });
        let tcp = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let n = stream.read_u16().await.unwrap() as usize;
            let mut query = vec![0; n];
            stream.read_exact(&mut query).await.unwrap();
            let reply = response(&query);
            stream.write_u16(reply.len() as u16).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        assert_eq!(
            up.query(&q, Duration::from_secs(1)).await.unwrap(),
            response(&q)
        );
        udp.await.unwrap();
        tcp.await.unwrap();
    }

    /// UDP mock that always replies with a well-formed answer for the WRONG
    /// question name, echoing the query's transaction id.
    async fn mock_wrong_question() -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if n < 2 {
                    continue;
                }
                let mut b = MessageBuilder::new_vec();
                b.header_mut().set_qr(true);
                let mut q = b.question();
                q.push((
                    Name::<Vec<u8>>::from_str("evil.example.").unwrap(),
                    Rtype::A,
                ))
                .unwrap();
                let mut resp = q.finish();
                resp[0] = buf[0]; // echo the transaction id
                resp[1] = buf[1];
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        format!("udp://{addr}")
    }

    /// TCP mock that echoes the query back with QR set but a corrupted id.
    async fn mock_tcp_wrong_id() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let n = u16::from_be_bytes(len) as usize;
                    let mut q = vec![0u8; n];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    q[0] ^= 0xFF; // wrong transaction id
                    q[2] |= 0x80; // QR
                    let _ = s.write_all(&(q.len() as u16).to_be_bytes()).await;
                    let _ = s.write_all(&q).await;
                });
            }
        });
        format!("tcp://{addr}")
    }

    #[tokio::test]
    async fn tcp_reply_with_wrong_id_is_rejected() {
        let up = mock_tcp_wrong_id().await;
        let f = fwd(&[up], 300);
        let r = f.exec(&mut query()).await;
        assert!(r.had_error, "id-mismatched TCP reply must not be accepted");
        assert!(r.response.is_none());
    }

    #[tokio::test]
    async fn reply_with_wrong_question_is_rejected() {
        let up = mock_wrong_question().await;
        let f = fwd(&[up], 250);
        let r = f.exec(&mut query()).await;
        // Id matches but the echoed question doesn't → skipped → deadline hit.
        assert!(r.had_error);
        assert!(r.response.is_none());
    }

    /// UDP mock whose first reply is long and every later reply is short, so a
    /// reused receive buffer would visibly carry a tail from the first one.
    async fn mock_shrinking() -> String {
        use domain::base::iana::Class;
        use domain::base::name::ToName;
        use domain::base::Ttl;
        use domain::rdata::A;
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut first = true;
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let Some(msg) = dns::parse(buf[..n].to_vec()) else {
                    continue;
                };
                let count: u8 = if first { 20 } else { 1 };
                first = false;
                let mut b = MessageBuilder::new_vec()
                    .start_answer(&msg, Rcode::NOERROR)
                    .unwrap();
                let name = msg.sole_question().unwrap().qname().to_vec();
                for i in 0..count {
                    b.push((
                        &name,
                        Class::IN,
                        Ttl::from_secs(60),
                        A::from_octets(10, 0, 0, i),
                    ))
                    .unwrap();
                }
                let _ = sock.send_to(&b.finish(), peer).await;
            }
        });
        format!("udp://{addr}")
    }

    /// The connected socket and its receive buffer are pooled together across
    /// queries. The second exchange must yield exactly the bytes the server
    /// sent for it — never the longer previous reply's tail left in the buffer.
    #[tokio::test]
    async fn pooled_receive_buffer_yields_exact_reply_bytes() {
        use domain::rdata::AllRecordData;
        let f = fwd(&[mock_shrinking().await], 500);

        let long = f.exec(&mut query()).await.response.expect("first reply");
        let long_len = long.as_slice().len();

        let short = f.exec(&mut query()).await.response.expect("second reply");
        let short_len = short.as_slice().len();

        // header(12) + question("example.com." 13 + qtype/qclass 4)
        //            + one uncompressed A RR (13 + 10 + 4)
        assert_eq!(short_len, 12 + 13 + 4 + 13 + 10 + 4);
        assert!(
            long_len > short_len,
            "the first reply must be the longer one ({long_len} vs {short_len})"
        );
        assert_eq!(
            short
                .answer()
                .unwrap()
                .limit_to::<AllRecordData<_, _>>()
                .count(),
            1
        );
    }

    /// UDP mock that can be switched between answering and going silent, so a
    /// single upstream can be driven from "dead" to "recovered".
    async fn mock_toggleable() -> (String, Arc<AtomicBool>) {
        let alive = Arc::new(AtomicBool::new(false));
        let a = alive.clone();
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if !a.load(Ordering::Relaxed) {
                    continue; // silent: the caller waits out its deadline
                }
                if let Some(msg) = dns::parse(buf[..n].to_vec()) {
                    let resp = MessageBuilder::new_vec()
                        .start_answer(&msg, Rcode::NOERROR)
                        .unwrap()
                        .finish();
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });
        (format!("udp://{addr}"), alive)
    }

    #[test]
    fn the_breaker_cooldown_does_not_end_early_in_the_second_it_trips() {
        let b = Breaker::new();
        // Trip as late in a whole second as possible: a deadline rounded down
        // to whole seconds would then expire within milliseconds.
        while b.now_ds() % 10 != 9 {
            std::thread::sleep(Duration::from_millis(10));
        }
        for _ in 0..BREAKER_FAILS {
            b.record(false);
        }
        assert!(matches!(b.admit(), Admit::Open), "must be tripped");
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            matches!(b.admit(), Admit::Open),
            "a probe was let through inside the cooldown"
        );
        std::thread::sleep(Duration::from_millis(900));
        assert!(
            matches!(b.admit(), Admit::Probe(_)),
            "the cooldown must end about a second after it trips"
        );
    }

    /// A TCP mock that counts how many connections it accepts.
    async fn mock_tcp_counting() -> (String, Arc<AtomicU32>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(AtomicU32::new(0));
        let seen = conns.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                seen.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    loop {
                        let mut len = [0u8; 2];
                        if s.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let n = u16::from_be_bytes(len) as usize;
                        let mut q = vec![0u8; n];
                        if s.read_exact(&mut q).await.is_err() {
                            return;
                        }
                        q[2] |= 0x80; // QR, echoing the question back
                        let _ = s.write_all(&(q.len() as u16).to_be_bytes()).await;
                        let _ = s.write_all(&q).await;
                    }
                });
            }
        });
        (format!("tcp://{addr}"), conns)
    }

    #[tokio::test]
    async fn a_pooled_connection_past_its_idle_limit_is_not_reused() {
        let (url, conns) = mock_tcp_counting().await;
        let up = Arc::new(Upstream::parse(&url).unwrap());
        let f = Forwarder::new(vec![up.clone()], Duration::from_millis(500));

        assert!(!f.exec(&mut query()).await.had_error);
        assert_eq!(conns.load(Ordering::Relaxed), 1);
        // Straight away the pooled connection is reused.
        assert!(!f.exec(&mut query()).await.had_error);
        assert_eq!(conns.load(Ordering::Relaxed), 1, "pool must be reused");

        // Age it past the limit: such a connection may have been blackholed by
        // a NAT that will never answer, so it has to be dropped, not reused.
        {
            let mut idle = up.idle_tcp.lock().unwrap();
            assert_eq!(idle.len(), 1, "one connection pooled");
            idle[0].1 = Instant::now() - MAX_IDLE_AGE - Duration::from_secs(1);
        }
        assert!(!f.exec(&mut query()).await.had_error);
        assert_eq!(
            conns.load(Ordering::Relaxed),
            2,
            "an over-idle connection must be replaced, not reused"
        );
    }

    /// A UDP mock that answers with a datagram larger than the receive buffer,
    /// plus a TCP side on the same port that answers properly.
    async fn mock_oversized_udp() -> (String, Arc<AtomicU32>) {
        use domain::base::iana::Class;
        use domain::base::name::ToName;
        use domain::base::Ttl;
        use domain::rdata::A;

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let tcp_hits = Arc::new(AtomicU32::new(0));

        fn answer(q: &[u8], records: usize) -> Option<Vec<u8>> {
            let msg = dns::parse(q.to_vec())?;
            let mut b = MessageBuilder::new_vec()
                .start_answer(&msg, Rcode::NOERROR)
                .ok()?;
            let owner = Name::<Vec<u8>>::from_str("example.com.").unwrap();
            for i in 0..records {
                b.push((
                    owner.to_name::<Vec<u8>>(),
                    Class::IN,
                    Ttl::from_secs(300),
                    A::from_octets(10, 0, (i / 256) as u8, i as u8),
                ))
                .ok()?;
            }
            Some(b.finish())
        }

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                // ~300 A records: over the 4096-byte receive buffer, which the
                // kernel silently cuts short.
                if let Some(resp) = answer(&buf[..n], 300) {
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });
        let hits = tcp_hits.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                hits.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let n = u16::from_be_bytes(len) as usize;
                    let mut q = vec![0u8; n];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    if let Some(resp) = answer(&q, 3) {
                        let _ = s.write_all(&(resp.len() as u16).to_be_bytes()).await;
                        let _ = s.write_all(&resp).await;
                    }
                });
            }
        });
        (format!("udp://{addr}"), tcp_hits)
    }

    #[tokio::test]
    async fn a_datagram_that_fills_the_buffer_is_re_asked_over_tcp() {
        let (url, tcp_hits) = mock_oversized_udp().await;
        let f = fwd(&[url], 800);
        let r = f.exec(&mut query()).await;
        let resp = r.response.expect("an answer");
        assert!(!r.had_error);
        assert_eq!(
            tcp_hits.load(Ordering::Relaxed),
            1,
            "a buffer-filling datagram must be re-asked over TCP"
        );
        // The TCP answer is the complete one, and complete means parseable to
        // its last record.
        let count = resp.answer().unwrap().count();
        assert_eq!(count, 3, "the TCP answer is what gets returned");
    }

    #[tokio::test]
    async fn breaker_trips_on_a_silent_upstream_then_closes_on_recovery() {
        let (up, alive) = mock_toggleable().await;
        let f = Forwarder::with_breaker(
            vec![Arc::new(Upstream::parse(&up).unwrap())],
            Duration::from_millis(60),
        );

        // A silent upstream costs a full timeout per query — the cost the
        // breaker exists to remove. It must not trip early.
        for i in 0..BREAKER_FAILS {
            let r = f.exec(&mut query()).await;
            assert!(r.had_error, "attempt {i}");
            assert_ne!(
                &*r.upstream, CIRCUIT_OPEN,
                "attempt {i} must still reach the network"
            );
        }

        // Tripped: fails immediately, without touching the network.
        let t = Instant::now();
        let r = f.exec(&mut query()).await;
        assert!(r.had_error);
        assert_eq!(&*r.upstream, CIRCUIT_OPEN);
        assert!(
            t.elapsed() < Duration::from_millis(30),
            "a tripped breaker must not wait out the timeout (took {:?})",
            t.elapsed()
        );

        // Recovery: after the cooldown one probe is let through, and a single
        // success closes the breaker again — switching back must not get slower.
        alive.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let probe = f.exec(&mut query()).await;
        assert!(!probe.had_error, "the probe reaches the recovered upstream");
        let after = f.exec(&mut query()).await;
        assert!(!after.had_error);
        assert_ne!(
            &*after.upstream, CIRCUIT_OPEN,
            "one success must close the breaker"
        );
    }

    /// The fallback forwarder never gets a breaker: short-circuiting the last
    /// resort would leave the query with nowhere to go.
    #[tokio::test]
    async fn fallback_forwarder_keeps_trying() {
        let f = fwd(&["udp://127.0.0.1:1".to_string()], 60);
        for i in 0..(BREAKER_FAILS + 3) {
            let r = f.exec(&mut query()).await;
            assert!(r.had_error, "attempt {i}");
            assert_ne!(
                &*r.upstream, CIRCUIT_OPEN,
                "attempt {i} must not short-circuit"
            );
        }
    }
}
