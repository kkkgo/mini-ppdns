package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/dnsutils"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

// reuseConnQueryTimeout caps how long a single exchange on a reused
// connection may wait for its reply before concluding the peer is dead.
// Most authoritative servers answer or SERVFAIL within 3-5 s; six
// buys a little headroom on slow links while still redialing quickly.
const reuseConnQueryTimeout = 6 * time.Second

// ReuseConnTransport drives the non-pipelined "one query at a time per
// connection" mode used for plain TCP (no DoT pipelining). It keeps a
// pool of idle connections around so back-to-back queries amortise the
// connect cost.
type ReuseConnTransport struct {
	dialFunc    func(ctx context.Context) (NetConn, error)
	dialTimeout time.Duration
	idleTimeout time.Duration
	logger      *mlog.Logger // non-nil

	ctx       context.Context
	ctxCancel context.CancelCauseFunc

	mu        sync.Mutex
	closed    bool
	conns     map[*reusableConn]struct{}
	idleConns map[*reusableConn]struct{}

	// testWaitRespTimeout, when positive, overrides reuseConnQueryTimeout
	// so tests can trigger the "peer went silent" path without the full
	// production-length wait.
	testWaitRespTimeout time.Duration
}

type ReuseConnOpts struct {
	// DialContext dials a fresh NetConn. Must not be nil.
	DialContext func(ctx context.Context) (NetConn, error)

	// DialTimeout bounds each dial. Zero uses dialTimeoutDefault.
	DialTimeout time.Duration

	// IdleTimeout bounds how long a conn may sit idle before being
	// reaped on the next read. Zero uses idleTimeoutDefault.
	IdleTimeout time.Duration

	Logger *mlog.Logger
}

func NewReuseConnTransport(opt ReuseConnOpts) *ReuseConnTransport {
	ctx, cancel := context.WithCancelCause(context.Background())
	t := &ReuseConnTransport{
		dialFunc:  opt.DialContext,
		ctx:       ctx,
		ctxCancel: cancel,
		conns:     make(map[*reusableConn]struct{}),
		idleConns: make(map[*reusableConn]struct{}),
	}
	setDefaultGZ(&t.dialTimeout, opt.DialTimeout, dialTimeoutDefault)
	setDefaultGZ(&t.idleTimeout, opt.IdleTimeout, idleTimeoutDefault)
	setNonNilLogger(&t.logger, opt.Logger)
	return t
}

// ExchangeContext sends m and waits for the reply. Reused conns get up
// to maxRetry chances on error — they may be silently dead — while a
// freshly-dialed conn gets only one try.
func (t *ReuseConnTransport) ExchangeContext(ctx context.Context, m []byte) (*[]byte, error) {
	const maxRetry = 2

	payload, err := copyMsgWithLenHdr(m)
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(payload)

	for retry := 0; ; retry++ {
		c, fresh, err := t.acquireConn(ctx)
		if err != nil {
			return nil, err
		}

		resp, err := c.exchange(ctx, payload)
		if err == nil {
			return resp, nil
		}
		if fresh || retry >= maxRetry || ctx.Err() != nil {
			return nil, err
		}
	}
}

// acquireConn returns an idle conn if one is available, otherwise dials
// a fresh one. The boolean distinguishes the two for retry accounting.
func (t *ReuseConnTransport) acquireConn(ctx context.Context) (*reusableConn, bool, error) {
	c, err := t.takeAnyIdle()
	if err != nil {
		return nil, false, err
	}
	if c != nil {
		return c, false, nil
	}
	c, err = t.dialNew(ctx)
	if err != nil {
		return nil, false, err
	}
	return c, true, nil
}

// dialResult carries a completed dial back to dialNew's select.
type dialResult struct {
	c   *reusableConn
	err error
}

// dialNew dials a fresh connection and registers it with the transport.
// The dial itself runs in a background goroutine so a per-call ctx
// cancellation doesn't abort it — the dialed conn, if any, is stashed
// as idle for a later caller to reuse.
func (t *ReuseConnTransport) dialNew(ctx context.Context) (*reusableConn, error) {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	out := make(chan dialResult, 1)

	go func() {
		dialCtx, stopDial := context.WithTimeout(t.ctx, t.dialTimeout)
		defer stopDial()

		raw, err := t.dialFunc(dialCtx)
		if err != nil {
			t.logger.Warnw("fail to dial reusable conn", mlog.Err(err))
			select {
			case out <- dialResult{err: err}:
			case <-callCtx.Done():
			}
			return
		}

		rc := t.registerConn(raw)
		if rc == nil {
			// Transport was closed mid-dial. Drop the raw socket.
			raw.Close()
			select {
			case out <- dialResult{err: ErrClosedTransport}:
			case <-callCtx.Done():
			}
			return
		}

		select {
		case out <- dialResult{c: rc}:
		case <-callCtx.Done():
			// Caller already left; keep the conn warm for the next one.
			t.setIdle(rc)
		}
	}()

	select {
	case <-callCtx.Done():
		return nil, context.Cause(ctx)
	case <-t.ctx.Done():
		return nil, context.Cause(t.ctx)
	case res := <-out:
		return res.c, res.err
	}
}

// takeAnyIdle pulls a single idle conn out of the pool, if one exists.
// Order is unspecified (Go map iteration).
func (t *ReuseConnTransport) takeAnyIdle() (*reusableConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, ErrClosedTransport
	}
	for c := range t.idleConns {
		delete(t.idleConns, c)
		return c, nil
	}
	return nil, nil
}

// setIdle puts c back into the idle pool, unless the transport has been
// closed in the meantime.
func (t *ReuseConnTransport) setIdle(c *reusableConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	if _, ok := t.conns[c]; ok {
		t.idleConns[c] = struct{}{}
	}
}

// Close closes the transport and every conn. Idempotent.
func (t *ReuseConnTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	for c := range t.conns {
		delete(t.conns, c)
		delete(t.idleConns, c)
		c.shutdown(ErrClosedTransport, true)
	}
	t.ctxCancel(ErrClosedTransport)
	return nil
}

// --- reusableConn ---

type reusableConn struct {
	c NetConn
	t *ReuseConnTransport

	// mu guards waitingResp / replyCh interaction. Taken briefly on the
	// write side of exchange() and once per frame by readLoop.
	mu          sync.Mutex
	waitingResp bool
	replyCh     chan *[]byte

	closeGuard sync.Once
	closedCh   chan struct{}
	closeErr   error
}

// registerConn wraps raw into a reusableConn and registers it on t.
// Returns nil if the transport is already closed — the caller is then
// responsible for closing raw.
func (t *ReuseConnTransport) registerConn(raw NetConn) *reusableConn {
	rc := &reusableConn{
		c:        raw,
		t:        t,
		replyCh:  make(chan *[]byte, 1),
		closedCh: make(chan struct{}),
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.conns[rc] = struct{}{}
	t.mu.Unlock()

	go rc.readLoop()
	return rc
}

// Sentinel errors surfaced when the connection state is corrupted.
var (
	errUnexpectedResp     = errors.New("reusableConn: unexpected response while idle")
	errConcurrentExchange = errors.New("reusableConn: concurrent exchange on same conn")
	errRespChanFull       = errors.New("reusableConn: reply channel unexpectedly full")
)

// readLoop pulls frames off the wire and hands them to the one
// outstanding waiter. The 1-buffered replyCh is load-bearing: the write
// side drains any stale entry under the mutex before flagging
// waitingResp, so under correct usage the channel has at most one frame
// pending at a time.
func (c *reusableConn) readLoop() {
	for {
		resp, err := dnsutils.ReadRawMsgFromTCP(c.c)
		if err != nil {
			c.shutdown(err, false)
			return
		}

		c.mu.Lock()
		wasWaiting := c.waitingResp
		c.waitingResp = false
		c.mu.Unlock()

		if !wasWaiting {
			// Server pushed a frame without a pending request. Protocol
			// violation — drop the conn so the caller redials.
			pool.ReleaseBuf(resp)
			c.shutdown(errUnexpectedResp, false)
			return
		}

		// Refresh idle deadline before advertising the conn for reuse,
		// and put it back in the pool *before* handing the frame to the
		// waiter. Otherwise a fast-turnaround second exchange could
		// observe the conn as busy and dial a new one unnecessarily.
		c.c.SetReadDeadline(time.Now().Add(c.t.idleTimeout))
		c.t.setIdle(c)

		select {
		case c.replyCh <- resp:
		default:
			// Unreachable under correct usage: replyCh is buffered(1)
			// and we cleared waitingResp a few lines above, meaning no
			// one else could have stuffed it. If we somehow land here,
			// the invariant is already broken — close down so the
			// upstream redials rather than leaking a frame.
			pool.ReleaseBuf(resp)
			c.t.logger.Warnw("reusableConn: reply channel unexpectedly full, closing conn")
			c.shutdown(errRespChanFull, false)
			return
		}
	}
}

// shutdown closes the connection exactly once, notifying any waiter
// with err. When byTransport is true, the caller (Close) has already
// removed this conn from t.conns/idleConns under t.mu, so we must skip
// the cleanup branch — reacquiring t.mu would deadlock.
func (c *reusableConn) shutdown(err error, byTransport bool) {
	if err == nil {
		err = net.ErrClosed
	}
	c.closeGuard.Do(func() {
		c.closeErr = err
		c.c.Close()
		close(c.closedCh)
	})
	if byTransport {
		return
	}
	c.t.mu.Lock()
	if !c.t.closed {
		delete(c.t.conns, c)
		delete(c.t.idleConns, c)
	}
	c.t.mu.Unlock()
}

// exchange sends q and awaits the reply. Caller must treat the conn as
// exclusively theirs until this returns — concurrent calls trip the
// concurrent-exchange guard and tear the conn down.
func (c *reusableConn) exchange(ctx context.Context, q *[]byte) (*[]byte, error) {
	c.mu.Lock()
	if c.waitingResp {
		c.mu.Unlock()
		// Transport-level serialisation should make this unreachable.
		// Tear down rather than panic so upper layers can rebuild the
		// conn cleanly.
		c.shutdown(errConcurrentExchange, false)
		return nil, errConcurrentExchange
	}

	// Flush any stale reply left over from a previous exchange that
	// abandoned the wait (ctx cancel after the server already replied).
	select {
	case stale := <-c.replyCh:
		pool.ReleaseBuf(stale)
	default:
	}

	c.waitingResp = true
	c.mu.Unlock()

	waitTimeout := reuseConnQueryTimeout
	if c.t.testWaitRespTimeout > 0 {
		waitTimeout = c.t.testWaitRespTimeout
	}
	c.c.SetDeadline(time.Now().Add(waitTimeout))

	if _, err := c.c.Write(*q); err != nil {
		c.shutdown(err, false)
		return nil, err
	}

	select {
	case resp := <-c.replyCh:
		return resp, nil
	case <-c.closedCh:
		return nil, c.closeErr
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}
