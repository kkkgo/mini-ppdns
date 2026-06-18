package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
)

// panickyNetConn satisfies NetConn but panics on every Read. Used to drive
// the readLoop recover regression tests.
type panickyNetConn struct{}

func (panickyNetConn) Read(_ []byte) (int, error)         { panic("simulated read panic") }
func (panickyNetConn) Write(p []byte) (int, error)        { return len(p), nil }
func (panickyNetConn) Close() error                       { return nil }
func (panickyNetConn) SetDeadline(_ time.Time) error      { return nil }
func (panickyNetConn) SetReadDeadline(_ time.Time) error  { return nil }
func (panickyNetConn) SetWriteDeadline(_ time.Time) error { return nil }

// minimalQuery is the smallest valid DNS query wire format that
// addQueueC's extractQuestion will accept: 12-byte header + root QNAME
// (single 0 byte) + QTYPE A (0x0001) + QCLASS IN (0x0001).
var minimalQuery = []byte{
	0x00, 0x00, // ID
	0x01, 0x00, // flags: standard query, RD set
	0x00, 0x01, // QDCOUNT
	0x00, 0x00, // ANCOUNT
	0x00, 0x00, // NSCOUNT
	0x00, 0x00, // ARCOUNT
	0x00,       // QNAME = root
	0x00, 0x01, // QTYPE A
	0x00, 0x01, // QCLASS IN
}

func BenchmarkConn_QueueAllocations(b *testing.B) {
	// Initialize a mock TraditionalDnsConn with default parameters
	dc := &TraditionalDnsConn{}

	// We only benchmark the queue addition/removal overhead with locks
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			qid, _ := dc.addQueueC(minimalQuery)
			dc.pending.lookup(qid)
			dc.deleteQueueC(qid)
		}
	})
}

// TestTraditionalDnsConn_ReadLoopPanicRecover pins B1: a panic inside the
// readLoop must be converted into a normal connection close (with the
// recovered value surfaced via closeErr) instead of crashing the process.
func TestTraditionalDnsConn_ReadLoopPanicRecover(t *testing.T) {
	dc := NewDnsConn(TraditionalDnsConnOpts{
		WithLengthHeader: false,
		IdleTimeout:      time.Second,
	}, panickyNetConn{})

	select {
	case <-dc.closedCh:
	case <-time.After(time.Second):
		t.Fatal("readLoop panic did not trigger CloseWithErr within 1s")
	}
	if dc.closeErr == nil || !strings.Contains(dc.closeErr.Error(), "readLoop panic") {
		t.Fatalf("closeErr = %v, want one containing %q", dc.closeErr, "readLoop panic")
	}
	if !dc.IsClosed() {
		t.Error("IsClosed should be true after readLoop panic")
	}
}

// TestReusableConn_ReadLoopPanicRecover pins B1 for the reuse transport:
// readLoop panic must shutdown the conn cleanly so the next exchange
// redials instead of the process crashing.
func TestReusableConn_ReadLoopPanicRecover(t *testing.T) {
	tr := NewReuseConnTransport(ReuseConnOpts{
		DialContext: func(_ context.Context) (NetConn, error) { return panickyNetConn{}, nil },
		DialTimeout: time.Second,
		IdleTimeout: time.Second,
	})
	defer tr.Close()

	rc := tr.registerConn(panickyNetConn{})
	if rc == nil {
		t.Fatal("registerConn returned nil")
	}

	select {
	case <-rc.closedCh:
	case <-time.After(time.Second):
		t.Fatal("reusableConn.readLoop panic did not trigger shutdown within 1s")
	}
	if rc.closeErr == nil || !strings.Contains(rc.closeErr.Error(), "readLoop panic") {
		t.Fatalf("closeErr = %v, want one containing %q", rc.closeErr, "readLoop panic")
	}
}

// TestLazyDnsConn_DialPanicRecover pins B2: if the dial func panics,
// dialFinished must still be closed and dialErr must surface — otherwise
// every ReserveNewQuery / ExchangeReserved on this lazyDnsConn blocks
// forever and deadlocks the whole pipeline transport.
func TestLazyDnsConn_DialPanicRecover(t *testing.T) {
	dialPanic := func(_ context.Context) (DnsConn, error) {
		panic("simulated dial panic")
	}
	lc := newLazyDnsConn(dialPanic, time.Second, 4, mlog.Nop())
	defer lc.Close()

	select {
	case <-lc.dialFinished:
	case <-time.After(time.Second):
		t.Fatal("dial panic did not close dialFinished within 1s — pipeline would deadlock")
	}
	if lc.dialErr == nil || !strings.Contains(lc.dialErr.Error(), "dial panic") {
		t.Fatalf("dialErr = %v, want one containing %q", lc.dialErr, "dial panic")
	}
	// And ReserveNewQuery must surface this as a closed conn so callers
	// stop waiting on this lazyDnsConn rather than spinning forever.
	if rx, closed := lc.ReserveNewQuery(); rx != nil || !closed {
		t.Errorf("ReserveNewQuery after dial panic: rx=%v closed=%v, want nil/true", rx, closed)
	}
	// Sanity: the recovered error chain is the synthetic one, not nil.
	if errors.Is(lc.dialErr, errLazyConnDialCanceled) {
		t.Errorf("dialErr should not be errLazyConnDialCanceled, got %v", lc.dialErr)
	}
}
