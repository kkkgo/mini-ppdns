// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Tokio UDP/TCP front-ends.
//!
//! Each listen address runs a UDP receive loop and a TCP accept loop. Handling
//! is bounded by a per-protocol semaphore (UDP and TCP have separate pools so
//! neither can starve the other) and stops cleanly when the shutdown watch
//! flips. UDP sheds load by *dropping* excess datagrams (never stalling
//! intake); TCP back-pressures only the offending connection.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Semaphore};

use crate::handler::{FastOutcome, Handler};
use crate::util::unmap_ip;

const UDP_RECV_BUF: usize = 4096;
/// The receive loop builds inline replies in one buffer it keeps across
/// datagrams. An answer built past this size (the uncompressed form of an
/// oversized answer is assembled before truncation) is not kept for the life
/// of the loop: the buffer is replaced once the reply is sent.
const UDP_REPLY_BUF_RETAIN: usize = 4 * UDP_RECV_BUF;
const TCP_IDLE: Duration = Duration::from_secs(3);
/// Cap on an accepted TCP query. Real queries are a few hundred bytes even
/// with EDNS + TSIG; honoring the full 64 KiB a length prefix can claim would
/// let a connection flood pin MAX_TCP_CONNS × 64 KiB (~128 MiB) of buffers.
const TCP_MAX_QUERY: usize = 4096;
/// Queries from one connection that may be in flight at once.
const TCP_PIPELINE: usize = 16;
/// How long the accept loop pauses after an accept failed for want of a
/// resource. Such a failure leaves the connection queued and the listener
/// readable, so retrying at once spins on the same error, burning the CPU the
/// in-flight queries need to finish and release their descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

type Shutdown = watch::Receiver<bool>;

/// Whether an accept error is the process running out of descriptors or
/// memory, rather than one connection going wrong (`ECONNABORTED` and friends,
/// where the next accept makes progress).
fn accept_exhausted(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

fn is_shutdown(rx: &Shutdown) -> bool {
    *rx.borrow()
}

/// UDP receive loop: no-IO queries (static rewrite / cache hit) are answered
/// inline — profiling showed per-datagram `tokio::spawn` dominating CPU on the
/// hot path — and only queries needing upstream IO spawn a handler task.
pub async fn serve_udp(
    sock: UdpSocket,
    handler: Arc<Handler>,
    sem: Arc<Semaphore>,
    mut shutdown: Shutdown,
) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; UDP_RECV_BUF];
    let mut reply = Vec::with_capacity(usize::from(crate::dns::MAX_UDP_RESPONSE));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if is_shutdown(&shutdown) { break; }
            }
            res = sock.recv_from(&mut buf) => {
                let (n, peer) = match res {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let client = unmap_ip(peer.ip());
                // Synchronous, bounded (~µs) fast path: parse + static rewrite +
                // cache lookup. Running it inline avoids the per-task spawn and
                // wakeup cost, and keeps cache hits served even while the permit
                // pool is drained by a stalled upstream.
                match handler.process_fast(&buf[..n], client, true, &mut reply) {
                    FastOutcome::Reply => {
                        // try_send_to never blocks intake; a full socket send
                        // buffer (rare for UDP) drops the reply — client retries.
                        let _ = sock.try_send_to(&reply, peer);
                        if reply.capacity() > UDP_REPLY_BUF_RETAIN {
                            reply = Vec::with_capacity(usize::from(crate::dns::MAX_UDP_RESPONSE));
                        }
                    }
                    FastOutcome::Drop => {}
                    FastOutcome::Pending(p) => {
                        // Non-blocking permit: when the UDP pool is saturated we
                        // drop this datagram and immediately go back to receiving.
                        // This keeps intake responsive under overload (no global
                        // 2.5s stall while a slow upstream holds permits) and
                        // leans on client retry.
                        let Ok(permit) = sem.clone().try_acquire_owned() else { continue };
                        let handler = handler.clone();
                        let sock = sock.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Some(resp) = handler.process_slow(p, client).await {
                                let _ = sock.send_to(&resp, peer).await;
                            }
                        });
                    }
                }
            }
        }
    }
}

/// TCP accept loop: one connection → a task that serves length-prefixed
/// queries until idle or closed.
///
/// `conn_sem` caps the number of *concurrent connections* (distinct from the
/// per-query `sem`): on saturation the new connection is dropped rather than
/// spawning an unbounded task, so a connection flood — e.g. many sockets that
/// send a length prefix then stall — can't exhaust tasks/memory. This mirrors
/// the UDP shed.
pub async fn serve_tcp(
    listener: TcpListener,
    handler: Arc<Handler>,
    sem: Arc<Semaphore>,
    conn_sem: Arc<Semaphore>,
    mut shutdown: Shutdown,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if is_shutdown(&shutdown) { break; }
            }
            res = listener.accept() => {
                let (stream, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        if accept_exhausted(&e) {
                            tokio::time::sleep(ACCEPT_BACKOFF).await;
                        }
                        continue;
                    }
                };
                // Drop the connection when the pool is full (client may retry).
                let Ok(conn_permit) = conn_sem.clone().try_acquire_owned() else {
                    continue;
                };
                let handler = handler.clone();
                let sem = sem.clone();
                tokio::spawn(async move {
                    let _conn_permit = conn_permit;
                    handle_tcp_conn(stream, unmap_ip(peer.ip()), handler, sem).await;
                });
            }
        }
    }
}

async fn handle_tcp_conn(
    stream: TcpStream,
    client: std::net::IpAddr,
    handler: Arc<Handler>,
    sem: Arc<Semaphore>,
) {
    let (mut rd, mut wr) = stream.into_split();
    // One writer for the connection: pipelined queries finish out of order —
    // that is the point (RFC 7766 §6.2.1.1) — and two of them must never
    // interleave halves of a message on the wire.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TCP_PIPELINE);
    let writer = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            let Ok(len) = u16::try_from(resp.len()) else {
                break;
            };
            // Bound the write like the reads: a client that stops reading
            // would otherwise park this task — and its connection permit —
            // forever once the socket send buffer fills.
            let write = async {
                wr.write_all(&len.to_be_bytes()).await?;
                wr.write_all(&resp).await?;
                wr.flush().await
            };
            if !matches!(tokio::time::timeout(TCP_IDLE, write).await, Ok(Ok(()))) {
                break;
            }
        }
    });
    // Queries from this connection that may be in flight at once. Reading
    // pauses while this many are outstanding: pipelining must not let one
    // connection spawn tasks without limit.
    let inflight = Arc::new(Semaphore::new(TCP_PIPELINE));
    loop {
        let mut len_buf = [0u8; 2];
        // Idle timeout closes lingering connections.
        match tokio::time::timeout(TCP_IDLE, rd.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break, // idle, EOF, or error
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > TCP_MAX_QUERY {
            break;
        }
        let mut req = vec![0u8; len];
        // Bound the body read too (not only the length read above): a client
        // that sends the 2-byte length then stalls must not park this task
        // forever (slow-loris). Reuse the idle timeout.
        match tokio::time::timeout(TCP_IDLE, rd.read_exact(&mut req)).await {
            Ok(Ok(_)) => {}
            _ => break, // timed out, EOF, or error
        }
        // No-IO answers (cache hit, static rewrite) are microseconds: they
        // cannot head-of-line block anything, and a task per query would cost
        // more than the work.
        let mut out = Vec::new();
        match handler.process_fast(&req, client, false, &mut out) {
            FastOutcome::Reply => {
                if tx.send(out).await.is_err() {
                    break;
                }
            }
            FastOutcome::Drop => {}
            FastOutcome::Pending(p) => {
                // Both waits back-pressure only this connection: the per-query
                // pool is TCP's own (UDP intake is unaffected), and the wait is
                // bounded by the handler's own deadlines.
                let Ok(slot) = inflight.clone().acquire_owned().await else {
                    break;
                };
                let Ok(permit) = sem.clone().acquire_owned().await else {
                    break;
                };
                let handler = handler.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    let _permit = permit;
                    if let Some(resp) = handler.process_slow(p, client).await {
                        let _ = tx.send(resp).await;
                    }
                });
            }
        }
    }
    // Stop reading, but answer what was already accepted (RFC 7766 §6.2.4):
    // the writer ends once every sender — this loop and each in-flight query —
    // has dropped its handle.
    drop(tx);
    let _ = writer.await;
}
#[cfg(test)]
mod tests {
    use super::*;

    /// `www.example.com.` in wire form.
    const NAME: &[u8] = b"\x03www\x07example\x03com\x00";

    fn query_bytes(id: u16, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(NAME);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    /// An upstream that answers every query with one A record, `delay` late.
    async fn slow_upstream(delay: Duration) -> String {
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let listen = sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = listen.recv_from(&mut buf).await {
                let q = buf[..n].to_vec();
                let sock = listen.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let mut i = 12;
                    while q[i] != 0 {
                        i += 1 + usize::from(q[i]);
                    }
                    let qend = i + 5;
                    let mut r = Vec::new();
                    r.extend_from_slice(&q[..2]);
                    r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                    r.extend_from_slice(&q[12..qend]);
                    r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
                    r.extend_from_slice(&300u32.to_be_bytes());
                    r.extend_from_slice(&[0, 4, 10, 0, 0, 7]);
                    let _ = sock.send_to(&r, peer).await;
                });
            }
        });
        format!("udp://{addr}")
    }

    fn test_handler(main: Vec<String>) -> Arc<Handler> {
        let fwd = |addrs: Vec<String>, ms: u64| {
            crate::upstream::Forwarder::new(
                addrs
                    .iter()
                    .map(|u| Arc::new(crate::upstream::Upstream::parse(u).unwrap()))
                    .collect(),
                Duration::from_millis(ms),
            )
        };
        Arc::new(Handler {
            main: Arc::new(fwd(main, 2000)),
            // Past the upstream's own delay: these tests are about the TCP
            // front-end, not about hedging.
            hedge_after: Duration::from_millis(1500),
            fallback: fwd(vec!["udp://127.0.0.1:1".to_string()], 200),
            cache: Arc::new(crate::cache::Cache::new(64)),
            fall_cache: Arc::new(crate::cache::Cache::new(64)),
            force_fall: crate::forcefall::ForceFallMatcher::default(),
            aaaa_mode: crate::handler::AaaaMode::No,
            lite: true,
            boguspriv: true,
            block_svcb: true,
            trust_rcodes: std::collections::HashSet::new(),
            resolver: None,
            hook_failed: None,
            pplog: None,
        })
    }

    /// Start a TCP front-end on an ephemeral port; returns its address.
    async fn serve_on(handler: Arc<Handler>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        // Kept alive for the test's duration.
        std::mem::forget(tx);
        tokio::spawn(serve_tcp(
            listener,
            handler,
            Arc::new(Semaphore::new(16)),
            Arc::new(Semaphore::new(16)),
            rx,
        ));
        addr
    }

    async fn send_query(s: &mut TcpStream, q: &[u8]) {
        s.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        s.write_all(q).await.unwrap();
    }

    /// Read one length-prefixed message, or None if the peer closed first.
    async fn read_msg(s: &mut TcpStream) -> Option<Vec<u8>> {
        let mut len = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut len))
            .await
            .ok()?
            .ok()?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut body))
            .await
            .ok()?
            .ok()?;
        Some(body)
    }

    fn msg_id(m: &[u8]) -> u16 {
        u16::from_be_bytes([m[0], m[1]])
    }

    /// RFC 7766 §6.2.1.1: queries on one connection are handled concurrently,
    /// and an answer that is ready must not wait behind a slow one.
    #[tokio::test]
    async fn a_ready_answer_does_not_wait_behind_a_slow_one() {
        let up = slow_upstream(Duration::from_millis(400)).await;
        let addr = serve_on(test_handler(vec![up])).await;
        let mut s = TcpStream::connect(addr).await.unwrap();

        // The A query needs the upstream; the AAAA query is blocked locally and
        // is ready immediately.
        send_query(&mut s, &query_bytes(0x1111, 1)).await;
        send_query(&mut s, &query_bytes(0x2222, 28)).await;

        let first = read_msg(&mut s).await.expect("first answer");
        let second = read_msg(&mut s).await.expect("second answer");
        assert_eq!(
            msg_id(&first),
            0x2222,
            "the ready answer must come back first"
        );
        assert_eq!(msg_id(&second), 0x1111, "and the slow one after it");
    }

    /// RFC 7766 §6.2.4: a client that half-closes after asking still gets its
    /// answers — the connection drains rather than dropping them.
    #[tokio::test]
    async fn a_query_is_still_answered_after_the_client_half_closes() {
        let up = slow_upstream(Duration::from_millis(200)).await;
        let addr = serve_on(test_handler(vec![up])).await;
        let mut s = TcpStream::connect(addr).await.unwrap();

        send_query(&mut s, &query_bytes(0x3333, 1)).await;
        s.shutdown().await.unwrap(); // no more queries from this client
        let answer = read_msg(&mut s)
            .await
            .expect("the accepted query is answered");
        assert_eq!(msg_id(&answer), 0x3333);

        // And then it closes: draining has to end the connection, not hold it
        // — and its connection permit — open.
        let waited = std::time::Instant::now();
        assert!(read_msg(&mut s).await.is_none(), "nothing more to send");
        assert!(
            waited.elapsed() < Duration::from_secs(2),
            "the drained connection stayed open ({:?})",
            waited.elapsed()
        );
    }

    /// Framing survives concurrency: every pipelined query gets exactly one
    /// well-formed answer, whatever order they finish in.
    #[tokio::test]
    async fn every_pipelined_query_gets_exactly_one_answer() {
        let up = slow_upstream(Duration::from_millis(40)).await;
        let addr = serve_on(test_handler(vec![up])).await;
        let mut s = TcpStream::connect(addr).await.unwrap();

        const COUNT: u16 = 40;
        for id in 0..COUNT {
            // Alternate between the two paths so fast and slow answers race.
            let qtype = if id % 2 == 0 { 1 } else { 28 };
            send_query(&mut s, &query_bytes(0x8000 + id, qtype)).await;
        }
        let mut seen = std::collections::HashSet::new();
        for _ in 0..COUNT {
            let m = read_msg(&mut s).await.expect("an answer");
            assert!(m.len() >= 12, "a whole message");
            assert_eq!(m[2] & 0x80, 0x80, "QR set");
            assert!(seen.insert(msg_id(&m)), "an id came back twice");
        }
        assert_eq!(seen.len(), usize::from(COUNT));
        for id in 0..COUNT {
            assert!(seen.contains(&(0x8000 + id)), "id {id} never answered");
        }
    }

    #[test]
    fn only_resource_exhaustion_backs_the_accept_loop_off() {
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(
                accept_exhausted(&std::io::Error::from_raw_os_error(code)),
                "errno {code} leaves the listener readable with no descriptor to accept onto"
            );
        }
        // Per-connection failures: the next accept makes progress, so pausing
        // would only delay the connections behind the broken one.
        for code in [
            libc::ECONNABORTED,
            libc::EINTR,
            libc::EAGAIN,
            libc::EPROTO,
            libc::EINVAL,
        ] {
            assert!(
                !accept_exhausted(&std::io::Error::from_raw_os_error(code)),
                "errno {code} must not pause the accept loop"
            );
        }
    }
}
