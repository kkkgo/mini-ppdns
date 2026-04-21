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

	rxBuf := pool.GetBuf(dns.MaxMsgSize)
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
		if err := q.Unpack(); err != nil {
			logger.Warnw("invalid msg", mlog.Err(err), mlog.Stringer("from", remote))
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

			payload := h.Handle(listenerCtx, msg,
				QueryMeta{ClientAddr: from.Addr(), FromUDP: true},
				pool.PackBuffer)
			if payload == nil {
				return
			}
			var oob []byte
			if oobWriter != nil && dst != nil {
				oob = oobWriter(dst)
			}
			if _, _, err := c.WriteMsgUDPAddrPort(*payload, oob, from); err != nil {
				logger.Warnw("failed to write response",
					mlog.Stringer("client", from),
					mlog.Err(err))
			}
			pool.ReleaseBuf(payload)
		}(q, remote, dstIP)
	}
}
