// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! DNS upstreams and the concurrent failover forwarder — the data-plane heart.
//!
//! Each `Forwarder` fans a query out to up to 3 randomly-chosen upstreams and
//! takes the first NOERROR answer, cancelling the rest. UDP upstreams fall back
//! to TCP when the answer is truncated (RFC 1035).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use domain::base::iana::Rcode;
use domain::base::Message;
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
    pub label: String,
    idle_udp: Mutex<Vec<UdpSocket>>,
    idle_tcp: Mutex<Vec<TcpStream>>,
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
            label: url.to_string(),
            idle_udp: Mutex::new(Vec::new()),
            idle_tcp: Mutex::new(Vec::new()),
        })
    }

    /// Send `query` and return the raw response bytes, honoring `deadline`.
    async fn query(&self, query: &[u8], deadline: Duration) -> Result<Vec<u8>, String> {
        match self.kind {
            Kind::Udp => {
                let resp = timeout(deadline, self.query_udp(query))
                    .await
                    .map_err(|_| "timeout".to_string())??;
                // Truncated → retry over TCP (RFC 1035 fallback).
                if resp.len() >= 3 && (resp[2] & 0x02) != 0 {
                    return timeout(deadline, self.query_tcp(query))
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
        let sock = match pooled {
            Some(s) => s,
            None => {
                let bind = if self.addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let s = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
                s.connect(self.addr).await.map_err(|e| e.to_string())?;
                s
            }
        };
        sock.send(query).await.map_err(|e| e.to_string())?;
        // Byte offset just past our query's question section; a matching reply
        // must echo those bytes verbatim (see `reply_matches`).
        let qend = question_end(query);
        let mut buf = vec![0u8; UDP_RECV_BUF];
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
            if n >= 2 && buf[0..2] == query[0..2] && reply_matches(&buf[..n], query, qend) {
                buf.truncate(n);
                let mut idle = self.idle_udp.lock().unwrap();
                if idle.len() < MAX_IDLE_CONNS {
                    idle.push(sock);
                }
                return Ok(buf);
            }
        }
    }

    async fn query_tcp(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        // Try a pooled connection; on failure (peer may have closed an idle
        // conn) retry once with a fresh dial.
        let pooled = self.idle_tcp.lock().unwrap().pop();
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
        let mut idle = self.idle_tcp.lock().unwrap();
        if idle.len() < MAX_IDLE_CONNS {
            idle.push(stream);
        }
        Ok(resp)
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

/// Whether `reply` echoes `query`'s question verbatim. The question sits at the
/// same offset (12) in query and reply, uncompressed, so a byte compare is both
/// sufficient and stricter than a parse (it also pins QTYPE/QCLASS). A reply
/// carrying no question (QDCOUNT==0, as some servers' error replies do) is
/// accepted on the transaction-ID match alone, preserving forwarding behavior.
fn reply_matches(reply: &[u8], query: &[u8], qend: Option<usize>) -> bool {
    if reply.len() < 6 {
        return false;
    }
    let qdcount = u16::from_be_bytes([reply[4], reply[5]]);
    if qdcount == 0 {
        return true;
    }
    match qend {
        Some(end) => reply.len() >= end && reply[12..end] == query[12..end],
        // Query question length unknown (never happens for our queries): don't
        // reject on that basis.
        None => true,
    }
}

/// One concurrent query's result: the upstream label, its latency, and the
/// parsed response (or an error string).
type QueryOutcome = (String, Duration, Result<Message<Vec<u8>>, String>);

/// A pool of upstreams queried concurrently with failover.
pub struct Forwarder {
    upstreams: Vec<Arc<Upstream>>,
    timeout: Duration,
}

/// Outcome of a forward attempt.
pub struct ForwardResult {
    /// The chosen response (first NOERROR, else first non-error), if any.
    pub response: Option<Message<Vec<u8>>>,
    /// Label of the upstream that answered, or "timeout/err".
    pub upstream: String,
    pub duration: Duration,
    pub had_error: bool,
}

impl Forwarder {
    pub fn new(upstreams: Vec<Arc<Upstream>>, timeout: Duration) -> Self {
        Forwarder { upstreams, timeout }
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }

    /// Fan `query` out to up to 3 shuffled upstreams; return the first NOERROR
    /// response (cancelling the rest), else the first non-success response,
    /// else an error result.
    pub async fn exec(&self, query: &[u8]) -> ForwardResult {
        let start = Instant::now();
        let n = self.upstreams.len();
        if n == 0 {
            return ForwardResult {
                response: None,
                upstream: "timeout/err".to_string(),
                duration: Duration::ZERO,
                had_error: true,
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

        let q: Arc<[u8]> = Arc::from(query);
        let mut set: JoinSet<QueryOutcome> = JoinSet::new();
        for &i in idx[..concurrent].iter() {
            let up = self.upstreams[i].clone();
            let q = q.clone();
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

        let mut fallback: Option<(String, Duration, Message<Vec<u8>>)> = None;
        let mut first_err: Option<(String, Duration)> = None;
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
            upstream: "timeout/err".to_string(),
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
        let r = f.exec(&query()).await;
        assert!(!r.had_error);
        assert_eq!(r.response.unwrap().header().rcode(), Rcode::NOERROR);
    }

    #[tokio::test]
    async fn non_success_is_surfaced_not_dropped() {
        let bad = mock(Rcode::SERVFAIL).await;
        let f = fwd(&[bad], 500);
        let r = f.exec(&query()).await;
        assert!(!r.had_error); // a parsed non-NOERROR is still a response
        assert_eq!(r.response.unwrap().header().rcode(), Rcode::SERVFAIL);
    }

    #[tokio::test]
    async fn all_dead_reports_error() {
        let f = fwd(&["udp://127.0.0.1:1".to_string()], 200);
        let r = f.exec(&query()).await;
        assert!(r.had_error);
        assert!(r.response.is_none());
    }

    #[test]
    fn question_end_and_reply_matching() {
        let q = query(); // A? example.com. (no OPT)
        let qend = question_end(&q);
        assert_eq!(qend, Some(29)); // 12 header + 13 qname + 4 (qtype+qclass)

        // Verbatim echo (id changed, QR set) matches.
        let mut good = q.clone();
        good[0] ^= 0xAB; // different id
        good[2] |= 0x80; // QR
        assert!(reply_matches(&good, &q, qend));

        // A different question is rejected.
        let mut bad = q.clone();
        bad[13] ^= 0xFF; // corrupt a QNAME byte
        assert!(!reply_matches(&bad, &q, qend));

        // A reply that carries no question (QDCOUNT==0) is accepted on id alone.
        let mut noq = q.clone();
        noq[4] = 0;
        noq[5] = 0;
        assert!(reply_matches(&noq, &q, qend));

        // Too-short datagram is rejected.
        assert!(!reply_matches(&q[..4], &q, qend));
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

    #[tokio::test]
    async fn reply_with_wrong_question_is_rejected() {
        let up = mock_wrong_question().await;
        let f = fwd(&[up], 250);
        let r = f.exec(&query()).await;
        // Id matches but the echoed question doesn't → skipped → deadline hit.
        assert!(r.had_error);
        assert!(r.response.is_none());
    }
}
