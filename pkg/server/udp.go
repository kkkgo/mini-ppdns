package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

// getSrcAddrFromOOB decodes the destination IP from control-message
// (OOB) data attached to an incoming UDP datagram. Platform-specific
// implementations in udp_linux.go etc. plug into this signature.
type getSrcAddrFromOOB func(oob []byte) (net.IP, error)

// writeSrcAddrToOOB produces the control-message bytes needed to have
// the outgoing datagram appear to come from src.
type writeSrcAddrToOOB func(src net.IP) []byte

// UDPServerOpts tunes ServeUDP. Leave any field zero for a sensible
// default.
type UDPServerOpts struct {
	Logger *mlog.Logger

	// MaxConcurrent caps in-flight handler goroutines. Additional queries
	// arriving while the cap is saturated are dropped (logged at Debug).
	// Zero uses DefaultMaxConcurrent.
	//
	// DNS handlers are IO-bound on the upstream resolver, so parallelism
	// should track outstanding query count rather than CPU count. One
	// goroutine per in-flight query gives the Go scheduler full freedom
	// to overlap upstream waits; peak footprint is MaxConcurrent × a
	// few KiB of stack, idle footprint is near zero.
	MaxConcurrent int
}

// safeUnpack wraps q.Unpack() so a panic in the decoder surfaces as a
// recovered value instead of unwinding the UDP read loop. Return conventions:
// (nil, err) for a normal decode failure, (rec, nil) for a panic, (nil, nil)
// for success. error is last per Go convention (staticcheck ST1008).
func safeUnpack(q *dns.Msg) (panicVal any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			panicVal = rec
		}
	}()
	err = q.Unpack()
	return
}

// ServeUDP runs a DNS UDP server on c until c returns a non-recoverable
// read error (typically: c.Close from another goroutine). Clean shutdown
// via c.Close returns nil.
//
// h is required; opts.Logger is optional.
func ServeUDP(c *net.UDPConn, h Handler, opts UDPServerOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger
	}
	maxConc := opts.MaxConcurrent
	if maxConc <= 0 {
		maxConc = DefaultMaxConcurrent
	}

	listenerCtx, cancel := context.WithCancelCause(context.Background())
	var handlerWg sync.WaitGroup
	defer func() {
		cancel(errListenerCtxCanceled)
		handlerWg.Wait()
	}()

	oobReader, oobWriter, err := initOobHandler(c)
	if err != nil {
		return fmt.Errorf("failed to init oob handler, %w", err)
	}

	// sem is the concurrency gate. Capacity is the hard cap; a full sem
	// means the next datagram is dropped rather than queued — a stale
	// queued query is worthless once the client has timed out and
	// retried anyway.
	sem := make(chan struct{}, maxConc)

	// rxBufSize bounds incoming DNS queries. Real-world clients keep
	// queries well under 1 KiB; EDNS0's UDP payload negotiation (RFC
	// 9715) recommends 4 KiB as the upper bound. dns.MaxMsgSize (64
	// KiB) was 16× larger than necessary and pulled a 64 KiB bucket out
	// of the pool every time. dns.DefaultMsgSize trips one bucket-12
	// (4 KiB) — same throughput, far less memory churn under load, and
	// any over-sized datagram still surfaces as MSG_TRUNC → unpack
	// error → "invalid msg" warn, which is the only sensible response
	// to a >4 KiB DNS query anyway.
	rxBuf := pool.GetBuf(dns.DefaultMsgSize)
	defer pool.ReleaseBuf(rxBuf)

	var oobSlice []byte
	if oobReader != nil {
		oobBuf := pool.GetBuf(1024)
		defer pool.ReleaseBuf(oobBuf)
		oobSlice = *oobBuf
	}

	for {
		n, oobN, _, remote, err := c.ReadMsgUDPAddrPort(*rxBuf, oobSlice)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if n == 0 {
				// Zero bytes read plus an error almost always means the
				// socket was closed out from under us.
				return fmt.Errorf("unexpected read err: %w", err)
			}
			// Transient read error — log and keep accepting.
			logger.Warnw("read error", mlog.Err(err))
			continue
		}

		q := new(dns.Msg)
		q.Data = (*rxBuf)[:n]
		// miekg/dns Unpack has historically panicked on pathological wire
		// data (out-of-range offsets in compression pointers, malformed
		// EDNS0 option lengths, etc.). A single hostile datagram must not
		// tear down the listener, so funnel panics into the same log path
		// as a plain parse error.
		unpackPanic, unpackErr := safeUnpack(q)
		if unpackPanic != nil {
			logger.Errorw("unpack panic", mlog.String("recover", fmt.Sprint(unpackPanic)), mlog.Stringer("from", remote))
			continue
		}
		if unpackErr != nil {
			logger.Warnw("invalid msg", mlog.Err(unpackErr), mlog.Stringer("from", remote))
			continue
		}
		// rxBuf is reused on the next iteration; detach the pointer so
		// the handler's view of q cannot alias the next datagram.
		q.Data = nil

		var dstIP net.IP
		if oobReader != nil {
			if d, err := oobReader(oobSlice[:oobN]); err != nil {
				logger.Errorw("failed to get dst address from oob", mlog.Err(err))
			} else {
				dstIP = d
			}
		}

		// Reserve a concurrency slot before launching. Non-blocking: if
		// sem is full we drop and move on.
		select {
		case sem <- struct{}{}:
		default:
			logger.Debugw("udp query dropped, concurrency cap reached",
				mlog.Int("cap", maxConc),
				mlog.Stringer("client", remote))
			continue
		}

		handlerWg.Add(1)
		go func(msg *dns.Msg, from netip.AddrPort, dst net.IP) {
			defer handlerWg.Done()
			defer func() { <-sem }()
			// Recover so a panic deep in Handle (miekg/dns has historically
			// panicked on pathological wire data) drops just this query
			// instead of tearing down the whole resolver process. Mirrors
			// the TCP per-query handler in serveTCPConn. sem release and
			// handlerWg done both run via earlier defers so cleanup is
			// guaranteed on the panic path.
			defer func() {
				if rec := recover(); rec != nil {
					logger.Errorw("udp handler panic recovered",
						mlog.String("recover", fmt.Sprint(rec)),
						mlog.Stringer("from", from))
				}
			}()

			payload := h.Handle(listenerCtx, msg,
				QueryMeta{ClientAddr: from.Addr(), FromUDP: true},
				pool.PackBuffer)
			if payload == nil {
				return
			}
			// Defer the release so a panic in oobWriter or
			// WriteMsgUDPAddrPort can't leak the pooled (up to 64 KiB)
			// buffer — the recover above would otherwise swallow the panic
			// and skip a plain trailing ReleaseBuf. Mirrors the upstream
			// Exec goroutine's deferred-release pattern.
			defer pool.ReleaseBuf(payload)
			var oob []byte
			if oobWriter != nil && dst != nil {
				oob = oobWriter(dst)
			}
			if _, _, err := c.WriteMsgUDPAddrPort(*payload, oob, from); err != nil {
				logger.Warnw("failed to write response",
					mlog.Stringer("client", from),
					mlog.Err(err))
			}
		}(q, remote, dstIP)
	}
}
