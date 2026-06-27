package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
)

type lazyDnsConn struct {
	maxConcurrentQuery int
	cancelDial         context.CancelFunc

	mu                 sync.Mutex
	earlyReserveCallWg sync.WaitGroup
	closed             bool
	reservedQuery      int
	dialFinished       chan struct{}
	c                  DnsConn
	dialErr            error

	// 1: Dial completed and all early reserve call finished.
	// 2: Dial failed.
	fastPath atomic.Uint32
}

var _ DnsConn = (*lazyDnsConn)(nil)

var (
	errLazyConnDialCanceled = errors.New("lazy dial canceled")
)

func newLazyDnsConn(
	dial func(ctx context.Context) (DnsConn, error),
	dialTimeout time.Duration,
	maxConcurrentQueryWhileDialing int, // must be valid, no default value
	logger *mlog.Logger, // must non-nil
) *lazyDnsConn {
	if dialTimeout <= 0 {
		dialTimeout = dialTimeoutDefault
	}
	dialCtx, cancelDial := context.WithTimeout(context.Background(), dialTimeout)
	lc := &lazyDnsConn{
		maxConcurrentQuery: maxConcurrentQueryWhileDialing,
		cancelDial:         cancelDial,
		dialFinished:       make(chan struct{}),
	}

	go func() {
		// A panic inside dial() — typically a misbehaving custom
		// DialContext or a future stdlib edge case — must not crash the
		// resolver process. It also must not leave dialFinished unclosed:
		// every ReserveNewQuery + ExchangeReserved on this lazyDnsConn
		// blocks on <-dialFinished, so silently leaking it would deadlock
		// the entire transport. Recover, synthesize a dial error so callers
		// see something other than ErrLazyConnCannotReserveQueryExchanger,
		// and close dialFinished under lc.mu (matching the normal-path
		// lock ordering with Close()).
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			lc.mu.Lock()
			defer lc.mu.Unlock()
			if lc.closed {
				return
			}
			lc.dialErr = fmt.Errorf("dial panic: %v", rec)
			select {
			case <-lc.dialFinished:
				// Close() already closed it before we got here.
			default:
				close(lc.dialFinished)
			}
		}()
		dc, err := dial(dialCtx)
		cancelDial()
		if err != nil {
			logger.Warnw("failed to dial dns conn", mlog.Err(err))
			// A conforming dial returns (nil, err) on failure, but a
			// misbehaving one may hand back a live conn alongside the error.
			// Close it now and drop the reference: the slow path below would
			// otherwise store it in lc.c with dialErr set, and
			// reserveExchanger drops such a dead lazyDnsConn without calling
			// lc.Close(), leaking the underlying socket.
			if dc != nil {
				dc.Close()
				dc = nil
			}
		}
		lc.mu.Lock()
		if lc.closed { // lc was closed and dial was canceled
			lc.mu.Unlock()
			if dc != nil {
				dc.Close()
			}
			return
		}

		lc.c = dc
		lc.dialErr = err
		close(lc.dialFinished)
		lc.mu.Unlock()
	}()
	return lc
}

func (lc *lazyDnsConn) Close() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.closed {
		return nil
	}
	lc.closed = true

	if lc.c == nil && lc.dialErr == nil { // still dialing
		lc.cancelDial()
		lc.dialErr = errLazyConnDialCanceled
		close(lc.dialFinished)
	} else {
		// Close connection
		if lc.c != nil {
			lc.c.Close()
		}
	}
	return nil
}

func (lc *lazyDnsConn) ReserveNewQuery() (_ ReservedExchanger, closed bool) {
	switch lc.fastPath.Load() {
	case 1:
		return lc.c.ReserveNewQuery()
	case 2:
		return nil, true
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()

	select {
	case <-lc.dialFinished:
		// Note: race condition here and lazyDnsConnEarlyReservedExchanger.ExchangeReserved().
		// Not a big problem. May cause at most all early exchange failed.
		// earlyExchangeWg makes sure that early exchange calls ReserveNewQuery first.
		dc, err := lc.c, lc.dialErr
		if err != nil {
			lc.fastPath.Store(2)
			return nil, true
		}
		lc.earlyReserveCallWg.Wait()
		lc.fastPath.Store(1)
		return dc.ReserveNewQuery()
	default:
		if lc.reservedQuery >= lc.maxConcurrentQuery {
			return nil, false
		}
		lc.reservedQuery++
		lc.earlyReserveCallWg.Add(1)
		return (*lazyDnsConnEarlyReservedExchanger)(lc), false
	}
}

type lazyDnsConnEarlyReservedExchanger lazyDnsConn

var _ ReservedExchanger = (*lazyDnsConnEarlyReservedExchanger)(nil)

func (ote *lazyDnsConnEarlyReservedExchanger) ExchangeReserved(ctx context.Context, q []byte) (resp *[]byte, err error) {
	// earlyReserveCallWg.Done() must run on every return path — including the
	// dial-error early return below and any panic from dc.ReserveNewQuery
	// (miekg/dns has a history of panics on pathological wire data). If Done
	// were skipped, a later ReserveNewQuery on this lazyDnsConn would block
	// forever on earlyReserveCallWg.Wait, deadlocking every future query on
	// this transport.
	//
	// Done() MUST fire before this returning goroutine contends for ote.mu.
	// The fastPath-transition path in ReserveNewQuery holds ote.mu while
	// calling earlyReserveCallWg.Wait(); if Done were gated behind ote.mu
	// here, that waiter (holding ote.mu and, above it, the PipelineTransport
	// mutex) would block this goroutine on ote.mu before it could decrement
	// the WaitGroup — a deadlock that wedges every forward on the transport.
	// So register the mu/reservedQuery cleanup FIRST and the Done() LAST, so
	// LIFO runs Done() first (lock-free), then the mu section — matching
	// WithdrawReserved's Done-before-mu ordering.
	defer func() {
		ote.mu.Lock()
		ote.reservedQuery--
		ote.mu.Unlock()
	}()
	defer ote.earlyReserveCallWg.Done()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-ote.dialFinished:
		dc, err := ote.c, ote.dialErr
		if err != nil {
			return nil, err
		}
		rec, _ := dc.ReserveNewQuery()
		if rec == nil {
			return nil, ErrLazyConnCannotReserveQueryExchanger
		}
		return rec.ExchangeReserved(ctx, q)
	}
}

func (ote *lazyDnsConnEarlyReservedExchanger) WithdrawReserved() {
	ote.earlyReserveCallWg.Done()
	ote.mu.Lock()
	ote.reservedQuery--
	ote.mu.Unlock()
}
