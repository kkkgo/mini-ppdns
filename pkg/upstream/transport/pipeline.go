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

type PipelineTransport struct {
	m      sync.Mutex
	closed bool
	conns  map[*lazyDnsConn]struct{}

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

	Logger *mlog.Logger
}

// NewPipelineTransport constructs a PipelineTransport. It never dials
// on its own; the first exchange triggers the first dial.
func NewPipelineTransport(opt PipelineOpts) *PipelineTransport {
	t := &PipelineTransport{
		conns:    make(map[*lazyDnsConn]struct{}),
		dialFunc: opt.DialContext,
	}
	setDefaultGZ(&t.dialTimeout, opt.DialTimeout, dialTimeoutDefault)
	setDefaultGZ(&t.maxLazyConnQueue, opt.MaxConcurrentQueryWhileDialing, lazyConnQueueDefault)
	setNonNilLogger(&t.logger, opt.Logger)
	return t
}

// ExchangeContext sends m and waits for the reply. Reused connections
// get up to maxRetry chances on error (they may be stale); a failure on
// a freshly-dialed connection bails out immediately.
func (t *PipelineTransport) ExchangeContext(ctx context.Context, m []byte) (*[]byte, error) {
	const maxRetry = 2
	retry := 0

	for {
		rx, isFresh, err := t.reserveExchanger()
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
	defer t.m.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	for c := range t.conns {
		c.Close()
	}
	return nil
}

// reserveExchanger walks existing conns looking for one with a free
// exchange slot, dialing a new one if no existing conn has capacity.
// The probe is bounded by reserveProbeCap so a pile of saturated-but-
// live connections can't starve us.
func (t *PipelineTransport) reserveExchanger() (rx ReservedExchanger, isFresh bool, err error) {
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

	// No capacity on any existing conn — dial a fresh one and hand the
	// caller its first exchange slot.
	fresh := newLazyDnsConn(t.dialFunc, t.dialTimeout, t.maxLazyConnQueue, t.logger)
	t.conns[fresh] = struct{}{}
	exch, _ := fresh.ReserveNewQuery()
	t.m.Unlock()

	if exch == nil {
		return nil, false, ErrNewConnCannotReserveQueryExchanger
	}
	return exch, true, nil
}
