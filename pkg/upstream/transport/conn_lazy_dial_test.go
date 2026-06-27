package transport

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// fakeReadyConn stands in for a freshly dialed upstream: its reservation
// handshake returns immediately so the test exercises lazyDnsConn's own
// locking without real I/O.
type fakeReadyConn struct{}

func (fakeReadyConn) ReserveNewQuery() (ReservedExchanger, bool) { return fakeReadyExchanger{}, false }
func (fakeReadyConn) Close() error                               { return nil }

type fakeReadyExchanger struct{}

func (fakeReadyExchanger) ExchangeReserved(context.Context, []byte) (*[]byte, error) {
	return nil, nil
}
func (fakeReadyExchanger) WithdrawReserved() {}

// TestLazyDnsConn_NoDeadlockFastPathTransition reproduces the production
// deadlock: lazyDnsConn.ReserveNewQuery's fastPath-transition branch holds
// lc.mu across earlyReserveCallWg.Wait(), while an in-flight early
// lazyDnsConnEarlyReservedExchanger.ExchangeReserved must take lc.mu (for its
// reservedQuery-- cleanup) *before* it can call earlyReserveCallWg.Done(). The
// waiter never releases lc.mu, the early exchanger never reaches Done(), and
// the PipelineTransport mutex above stays locked forever — every forward on
// the transport then wedges on PipelineTransport.reserveExchanger.
//
// The loop forces the dial to complete mid-burst so a late reservation takes
// the Wait branch while early reservations are still finishing. With the buggy
// defer order this deadlocks within a few iterations; the watchdog fails the
// test with a full stack dump instead of hanging the suite.
func TestLazyDnsConn_NoDeadlockFastPathTransition(t *testing.T) {
	run := func() {
		for iter := 0; iter < 400; iter++ {
			dialGate := make(chan struct{})
			dial := func(ctx context.Context) (DnsConn, error) {
				<-dialGate
				return fakeReadyConn{}, nil
			}
			lc := newLazyDnsConn(dial, 5*time.Second, 16, nopLogger)

			// Phase 1: reserve early, while the dial is still gated — these
			// land in the "default" branch and Add to earlyReserveCallWg.
			const earlyN = 8
			early := make([]ReservedExchanger, 0, earlyN)
			for i := 0; i < earlyN; i++ {
				ex, closed := lc.ReserveNewQuery()
				if closed || ex == nil {
					continue
				}
				early = append(early, ex)
			}

			var wg sync.WaitGroup
			// Phase 2: drive the early exchanges; they block on dialFinished.
			for _, ex := range early {
				wg.Add(1)
				go func(e ReservedExchanger) {
					defer wg.Done()
					e.ExchangeReserved(context.Background(), make([]byte, 16))
				}(ex)
			}
			// Phase 3: release the dial AND fire late reservations; the first
			// late caller performs the fastPath transition (the Wait), racing
			// the early exchangers' cleanup.
			close(dialGate)
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ex, closed := lc.ReserveNewQuery()
					if closed || ex == nil {
						return
					}
					ex.ExchangeReserved(context.Background(), make([]byte, 16))
				}()
			}
			wg.Wait()
			lc.Close()
		}
	}

	done := make(chan struct{})
	go func() { run(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("deadlock: lazyDnsConn reservation handshake did not complete in 20s\n%s", buf[:n])
	}
}
