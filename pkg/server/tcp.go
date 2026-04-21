package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/dnsutils"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

const (
	defaultTCPIdleTimeout = 10 * time.Second
	tcpFirstReadTimeout   = 1 * time.Second

	// defaultTCPMaxPerConnQuery bounds parallel queries on a single TCP
	// connection. 256 comfortably covers RFC 7766 pipelining patterns
	// (in practice clients issue single-digit parallel queries) while
	// leaving headroom for bursty DoT clients.
	defaultTCPMaxPerConnQuery = 256
)

// aLongTimeAgo is a fixed past instant used to unblock pending Reads
// during graceful shutdown. Borrowed from net/http for the same reason:
// resilient against NTP adjustments that could make time.Now() drift
// relative to an absolute deadline.
var aLongTimeAgo = time.Unix(1, 0)

type TCPServerOpts struct {
	// Logger for connection-level diagnostics. Nil becomes a no-op.
	Logger *mlog.Logger

	// IdleTimeout bounds how long a TCP conn may sit between reads.
	// Zero uses defaultTCPIdleTimeout.
	IdleTimeout time.Duration

	// MaxConnections caps concurrent accepted TCP connections. Extra
	// connections are dropped at Accept time. Zero uses
	// DefaultMaxConcurrent. This guards against FD exhaustion from
	// clients that dial without issuing queries.
	MaxConnections int

	// MaxConcurrent caps in-flight queries on a single connection.
	// Queries arriving while the per-connection slots are saturated
	// receive an immediate SERVFAIL rather than waiting. Zero uses
	// defaultTCPMaxPerConnQuery. Separate from MaxConnections so one
	// noisy client can't starve the listener.
	MaxConcurrent int
}

// ServeTCP runs a DNS TCP server on l until l.Accept returns ErrClosed
// (clean shutdown, returns nil) or any other error. On shutdown it
// waits for all per-connection goroutines to drain before returning,
// so callers using a WaitGroup around ServeTCP get a true "done"
// signal.
func ServeTCP(l net.Listener, h Handler, opts TCPServerOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	firstReadTimeout := tcpFirstReadTimeout
	if idleTimeout < firstReadTimeout {
		firstReadTimeout = idleTimeout
	}
	maxConn := opts.MaxConnections
	if maxConn <= 0 {
		maxConn = DefaultMaxConcurrent
	}
	perConnMax := opts.MaxConcurrent
	if perConnMax <= 0 {
		perConnMax = defaultTCPMaxPerConnQuery
	}
	connSem := make(chan struct{}, maxConn)

	listenerCtx, cancel := context.WithCancelCause(context.Background())
	var connWg sync.WaitGroup
	defer func() {
		cancel(errListenerCtxCanceled)
		connWg.Wait()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		// Enforce the global connection cap before spawning anything.
		// Otherwise a flood of idle connects could exhaust FDs without
		// ever showing up in the per-connection query limit.
		select {
		case connSem <- struct{}{}:
		default:
			logger.Debugw("tcp conn cap reached, dropping", mlog.Stringer("client", c.RemoteAddr()))
			c.Close()
			continue
		}

		connWg.Add(1)
		go func(c net.Conn) {
			defer connWg.Done()
			defer func() { <-connSem }()
			serveTCPConn(listenerCtx, c, h, logger, firstReadTimeout, idleTimeout, perConnMax)
		}(c)
	}
}

// The writer goroutine is the SOLE writer to c. This replaces the
// per-connection writeMu that the older design used and removes the
// lock-contention corner case where a slow responder could starve
// sibling queries multiplexed on the same conn.
func serveTCPConn(
	parentCtx context.Context,
	c net.Conn,
	h Handler,
	logger *mlog.Logger,
	firstReadTimeout, idleTimeout time.Duration,
	perConnMax int,
) {
	connCtx, cancelConn := context.WithCancelCause(parentCtx)

	// Defer teardown in LIFO: cancel → drain handlers → close outbound
	// channel → wait for writer → close socket. Closing c last lets the
	// writer flush its last frame before the FIN.
	var (
		handlerWg sync.WaitGroup
		writerWg  sync.WaitGroup
	)
	outCh := make(chan *[]byte, perConnMax)

	defer c.Close()
	defer writerWg.Wait()
	defer close(outCh)
	defer handlerWg.Wait()
	defer cancelConn(errConnectionCtxCanceled)

	// Writer goroutine: serialized writes, owns the write deadline.
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for buf := range outCh {
			c.SetWriteDeadline(time.Now().Add(idleTimeout))
			_, err := c.Write(*buf)
			pool.ReleaseBuf(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logger.Debugw("failed to write response (conn closed)",
						mlog.Stringer("client", c.RemoteAddr()))
				} else {
					logger.Warnw("failed to write response",
						mlog.Stringer("client", c.RemoteAddr()),
						mlog.Err(err))
				}
				// Force the read side to unstick so the conn can tear
				// down promptly, and drain the rest of outCh to keep
				// handler goroutines from blocking on send.
				c.Close()
				for leftover := range outCh {
					pool.ReleaseBuf(leftover)
				}
				return
			}
		}
	}()

	// Shutdown watchdog: when the listener cancels, jolt any blocked
	// Read via SetReadDeadline to a past instant.
	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		select {
		case <-parentCtx.Done():
			c.SetReadDeadline(aLongTimeAgo)
		case <-doneCh:
		}
	}()

	// Per-connection query concurrency limit.
	querySlot := make(chan struct{}, perConnMax)

	firstRead := true
	for {
		if firstRead {
			c.SetReadDeadline(time.Now().Add(firstReadTimeout))
			firstRead = false
		} else {
			c.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		req, _, err := dnsutils.ReadMsgFromTCP(c)
		if err != nil {
			return
		}

		select {
		case querySlot <- struct{}{}:
		default:
			// Busy: return SERVFAIL now rather than let the client wait
			// for idleTimeout. Goes through the same writer so ordering
			// relative to in-flight responses is preserved.
			if buf, ok := packServFail(req); ok {
				select {
				case outCh <- buf:
				case <-connCtx.Done():
					pool.ReleaseBuf(buf)
					return
				}
			}
			continue
		}

		handlerWg.Add(1)
		go func(req *dns.Msg) {
			defer handlerWg.Done()
			defer func() { <-querySlot }()

			r := h.Handle(connCtx, req, QueryMeta{
				ClientAddr: tcpRemoteAddr(c),
				FromUDP:    false,
			}, pool.PackTCPBuffer)
			if r == nil {
				return
			}
			select {
			case outCh <- r:
			case <-connCtx.Done():
				pool.ReleaseBuf(r)
			}
		}(req)
	}
}

// packServFail synthesizes a SERVFAIL reply for req, framed for TCP.
// Returns (nil, false) if packing fails — in practice this never
// happens for a well-formed request.
func packServFail(req *dns.Msg) (*[]byte, bool) {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, req)
	resp.Rcode = dns.RcodeServerFailure
	buf, err := pool.PackTCPBuffer(resp)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// tcpRemoteAddr extracts the remote addr as a netip.Addr; returns a
// zero value if the conn's remote address is not a TCP address (which
// shouldn't happen for a net.Listener-derived conn).
func tcpRemoteAddr(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr()
	}
	return netip.Addr{}
}
