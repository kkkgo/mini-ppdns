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

use crate::handler::Handler;
use crate::util::unmap_ip;

const UDP_RECV_BUF: usize = 4096;
const TCP_IDLE: Duration = Duration::from_secs(3);

type Shutdown = watch::Receiver<bool>;

fn is_shutdown(rx: &Shutdown) -> bool {
    *rx.borrow()
}

/// UDP receive loop: one datagram → one handler task → one reply.
pub async fn serve_udp(
    sock: UdpSocket,
    handler: Arc<Handler>,
    sem: Arc<Semaphore>,
    mut shutdown: Shutdown,
) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; UDP_RECV_BUF];
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
                // Non-blocking permit: when the UDP pool is saturated we drop
                // this datagram and immediately go back to receiving. This keeps
                // intake responsive under overload (no global 2.5s stall while a
                // slow upstream holds permits), avoids draining stale packets out
                // of the socket buffer, and leans on client retry. Acquire before
                // the copy so a dropped datagram costs nothing.
                // datagram costs nothing.
                let Ok(permit) = sem.clone().try_acquire_owned() else { continue };
                let req = buf[..n].to_vec();
                let handler = handler.clone();
                let sock = sock.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let client = unmap_ip(peer.ip());
                    if let Some(resp) = handler.process(req, client, true).await {
                        let _ = sock.send_to(&resp, peer).await;
                    }
                });
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
                    Err(_) => continue,
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
    mut stream: TcpStream,
    client: std::net::IpAddr,
    handler: Arc<Handler>,
    sem: Arc<Semaphore>,
) {
    loop {
        let mut len_buf = [0u8; 2];
        // Idle timeout closes lingering connections.
        match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break, // idle, EOF, or error
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            break;
        }
        let mut req = vec![0u8; len];
        // Bound the body read too (not only the length read above): a client
        // that sends the 2-byte length then stalls must not park this task
        // forever (slow-loris). Reuse the idle timeout.
        match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut req)).await {
            Ok(Ok(_)) => {}
            _ => break, // timed out, EOF, or error
        }
        // Blocking acquire is fine here: it back-pressures only this one
        // connection's task (other connections and all UDP intake are
        // unaffected, since TCP has its own permit pool), and the wait is
        // bounded by the handler's own qtime deadline.
        let Ok(permit) = sem.clone().acquire_owned().await else {
            break;
        };
        let resp = handler.process(req, client, false).await;
        drop(permit);
        if let Some(resp) = resp {
            let l = match u16::try_from(resp.len()) {
                Ok(l) => l,
                Err(_) => break,
            };
            if stream.write_all(&l.to_be_bytes()).await.is_err()
                || stream.write_all(&resp).await.is_err()
            {
                break;
            }
            let _ = stream.flush().await;
        }
    }
}
