package transport

import (
	"context"
	"sync"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
)

// reserveProbeCap bounds how many conn slots a single exchange will
// probe before giving up and dialing a fresh connection. Without the
// bound, a sea of "full but alive" conns could stall every exchange
// behind a linear scan.
const reserveProbeCap = 16

// maxConnsDefault caps how many pipelined conns a single transport
// can hold open concurrently. Each pipelined conn already multiplexes
// many in-flight queries (64 for TCP, 4096 for UDP), so 32 conns is
// far beyond any realistic single-host load while still placing a
// ceiling on runaway fan-out during transient upstream misbehavior.
const maxConnsDefault = 32

type PipelineTransport struct {
	m      sync.Mutex
	closed bool
	conns  map[*lazyDnsConn]struct{}

	// sem is a buffered token channel sized to maxConns. Dialing a
	// fresh conn takes one token; a conn being removed (dead or on
	// Close) releases one. Callers wanting to dial past the cap block
	// on sem until a slot frees or ctx cancels.
	sem     chan struct{}
	closeCh chan struct{}

	dialFunc         func(ctx context.Context) (DnsConn, error)
	dialTimeout      time.Duration
	maxLazyConnQueue int
	logger           *mlog.Logger // non-nil
}

type PipelineOpts struct {
	// DialContext dials a fresh DnsConn. Must NOT be nil.
	DialContext func(ctx context.Context) (DnsConn, error)

	// DialTimeout bounds how long a dial may take. 0 uses the package
	// default.
	DialTimeout time.Duration

	// MaxConcurrentQueryWhileDialing caps how many queries may be
	// enqueued against a still-dialing connection. If the connection
	// turns out to have a smaller limit, excess queued queries fail.
	MaxConcurrentQueryWhileDialing int

	// MaxConns caps concurrent open conns. Zero means "use the
	// package default" (see maxConnsDefault). Negative disables the
	// cap entirely (not recommended in production).
	MaxConns int

	Logger *mlog.Logger
}

// NewPipelineTransport constructs a PipelineTransport. It never dials
// on its own; the first exchange triggers the first dial.
func NewPipelineTransport(opt PipelineOpts) *PipelineTransport {
	t := &PipelineTransport{
		conns:    make(map[*lazyDnsConn]struct{}),
		dialFunc: opt.DialContext,
		closeCh:  make(chan struct{}),
	}
	setDefaultGZ(&t.dialTimeout, opt.DialTimeout, dialTimeoutDefault)
	setDefaultGZ(&t.maxLazyConnQueue, opt.MaxConcurrentQueryWhileDialing, lazyConnQueueDefault)
	setNonNilLogger(&t.logger, opt.Logger)

	maxConns := opt.MaxConns
	if maxConns == 0 {
		maxConns = maxConnsDefault
	}
	if maxConns > 0 {
		t.sem = make(chan struct{}, maxConns)
	}
	return t
}

// ExchangeContext sends m and waits for the reply. Reused connections
// get up to maxRetry chances on error (they may be stale); a failure on
// a freshly-dialed connection bails out immediately.
func (t *PipelineTransport) ExchangeContext(ctx context.Context, m []byte) (*[]byte, error) {
	const maxRetry = 2
	retry := 0

	for {
		rx, isFresh, err := t.reserveExchanger(ctx)
		if err != nil {
			return nil, err
		}
		resp, err := rx.ExchangeReserved(ctx, m)
		if err == nil {
			return resp, nil
		}
		// Retry only if the error came from an already-reused conn that
		// may have gone stale between the last successful exchange and
		// now. A fresh conn failing means the server or network is
		// actually sick — don't mask it with retries.
		if isFresh || retry >= maxRetry || ctx.Err() != nil {
			return nil, err
		}
		retry++
	}
}

// Close closes every conn and marks the transport dead. Subsequent
// ExchangeContext calls return ErrClosedTransport.
func (t *PipelineTransport) Close() error {
	t.m.Lock()
	if t.closed {
		t.m.Unlock()
		return nil
	}
	t.closed = true
	// Signal anyone waiting for a semaphore slot before we start
	// closing conns, so they bail out instead of racing with
	// teardown.
	close(t.closeCh)
	for c := range t.conns {
		c.Close()
	}
	t.m.Unlock()
	return nil
}

// acquireSlot takes a semaphore token, blocking until one is free
// or ctx/close fires. Returns nil if the cap is disabled.
func (t *PipelineTransport) acquireSlot(ctx context.Context) error {
	if t.sem == nil {
		return nil
	}
	select {
	case t.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closeCh:
		return ErrClosedTransport
	}
}

// releaseSlot returns a token to the semaphore. Must be called with
// t.m held or in a context where the caller is certain no other
// goroutine will try to read from an already-empty channel.
func (t *PipelineTransport) releaseSlot() {
	if t.sem == nil {
		return
	}
	select {
	case <-t.sem:
	default:
	}
}

// reserveExchanger walks existing conns looking for one with a free
// exchange slot, dialing a new one (subject to maxConns) if no
// existing conn has capacity.
func (t *PipelineTransport) reserveExchanger(ctx context.Context) (rx ReservedExchanger, isFresh bool, err error) {
	t.m.Lock()
	if t.closed {
		t.m.Unlock()
		return nil, false, ErrClosedTransport
	}

	probes := 0
	for c := range t.conns {
		probes++
		exch, dead := c.ReserveNewQuery()
		if dead {
			delete(t.conns, c)
			t.releaseSlot()
			continue
		}
		if exch != nil {
			t.m.Unlock()
			return exch, false, nil
		}
		if probes >= reserveProbeCap {
			break
		}
	}
	t.m.Unlock()

	// No capacity on any existing conn — dial a fresh one. Respect
	// the conn cap: if we're at the limit, block until a slot opens.
	if err := t.acquireSlot(ctx); err != nil {
		return nil, false, err
	}

	t.m.Lock()
	if t.closed {
		t.m.Unlock()
		t.releaseSlot()
		return nil, false, ErrClosedTransport
	}
	// Re-probe under the held lock: another in-flight reserveExchanger
	// may have dialed a fresh conn while we were blocked on
	// acquireSlot, so a reuse slot may now exist. Cap the probe count
	// at reserveProbeCap (Go's randomized map iteration would otherwise
	// let one full conn shadow many idle ones — when only one randomly
	// picked conn was checked, dialing past the useful working set was
	// the common outcome under load).
	reprobes := 0
	for c := range t.conns {
		reprobes++
		exch, dead := c.ReserveNewQuery()
		if dead {
			delete(t.conns, c)
			t.releaseSlot()
			continue
		}
		if exch != nil {
			t.m.Unlock()
			t.releaseSlot() // didn't dial; hand the token back
			return exch, false, nil
		}
		if reprobes >= reserveProbeCap {
			break
		}
	}
	fresh := newLazyDnsConn(t.dialFunc, t.dialTimeout, t.maxLazyConnQueue, t.logger)
	t.conns[fresh] = struct{}{}
	exch, _ := fresh.ReserveNewQuery()
	t.m.Unlock()

	if exch == nil {
		// Dial-newborn failed to reserve even its first slot; drop
		// it from the map, free the semaphore token, and Close the
		// lazy conn so the in-flight dial goroutine cannot orphan a
		// freshly-opened socket once it completes.
		t.m.Lock()
		delete(t.conns, fresh)
		t.m.Unlock()
		fresh.Close()
		t.releaseSlot()
		return nil, false, ErrNewConnCannotReserveQueryExchanger
	}
	return exch, true, nil
}
