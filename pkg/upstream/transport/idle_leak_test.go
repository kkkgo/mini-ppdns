package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestReusableConn_InitialReadDeadline pins the idle-conn leak fix: a conn
// that is registered (dialed) but never exchanged — e.g. the caller's ctx
// was cancelled mid-dial and dialNew parked it idle — must still get a read
// deadline armed up front. Without it, readLoop's first ReadRawMsgFromTCP
// blocks forever on a silent peer and the goroutine + fd leak, because the
// idleTimeout deadline is otherwise only armed after the first successful
// read.
//
// net.Pipe gives us a NetConn whose Read honors SetReadDeadline; we never
// write to the server end, so the conn is a permanently silent peer.
func TestReusableConn_InitialReadDeadline(t *testing.T) {
	tr := NewReuseConnTransport(ReuseConnOpts{
		DialContext: func(_ context.Context) (NetConn, error) {
			return nil, errors.New("dial not used in this test")
		},
		IdleTimeout: 100 * time.Millisecond,
	})
	defer tr.Close()

	client, server := net.Pipe()
	defer server.Close()

	rc := tr.registerConn(client)
	if rc == nil {
		t.Fatal("registerConn returned nil")
	}

	// The conn is never exchanged. With the initial deadline armed in
	// registerConn, readLoop's first Read must time out within ~idleTimeout
	// and shut the conn down. Without the fix this blocks forever.
	select {
	case <-rc.closedCh:
		// Reaped via the initial read deadline — correct.
	case <-time.After(2 * time.Second):
		t.Fatal("idle-never-exchanged conn was not reaped: initial read deadline missing (goroutine/fd leak)")
	}
}

// TestReuseConnTransport_IdlePoolCap pins the idle-pool bound: parking more
// than maxIdleConns conns must not grow the idle LIFO past the cap — the
// excess are closed instead of hoarded, so a cancel flood can't accumulate
// unbounded idle conns.
func TestReuseConnTransport_IdlePoolCap(t *testing.T) {
	tr := NewReuseConnTransport(ReuseConnOpts{
		DialContext: func(_ context.Context) (NetConn, error) {
			return nil, errors.New("dial not used in this test")
		},
		// Long idle timeout so conns don't self-reap mid-test; we want to
		// observe the cap, not the deadline.
		IdleTimeout: time.Hour,
	})
	defer tr.Close()

	const extra = 5
	conns := make([]*reusableConn, 0, maxIdleConns+extra)
	for i := 0; i < maxIdleConns+extra; i++ {
		client, server := net.Pipe()
		t.Cleanup(func() { server.Close() })
		rc := tr.registerConn(client)
		if rc == nil {
			t.Fatal("registerConn returned nil")
		}
		conns = append(conns, rc)
	}
	for _, rc := range conns {
		tr.setIdle(rc)
	}

	tr.mu.Lock()
	idleLen := tr.idleLen
	tr.mu.Unlock()
	if idleLen > maxIdleConns {
		t.Fatalf("idle pool not capped: idleLen = %d, want <= %d", idleLen, maxIdleConns)
	}
}

// TestLazyDnsConn_DialErrorClosesConn pins the dc-leak fix: if a dial
// returns a live conn alongside an error (a contract violation, but defended
// against), the conn must be closed rather than parked in lc.c where a
// dead-conn eviction would drop it without ever calling Close.
func TestLazyDnsConn_DialErrorClosesConn(t *testing.T) {
	closed := make(chan struct{})
	bad := &closeSignalConn{closed: closed}
	dial := func(_ context.Context) (DnsConn, error) {
		return bad, errors.New("handshake failed")
	}
	lc := newLazyDnsConn(dial, time.Second, 4, nopLogger)
	defer lc.Close()

	select {
	case <-lc.dialFinished:
	case <-time.After(time.Second):
		t.Fatal("dialFinished not closed within 1s")
	}
	select {
	case <-closed:
		// dc.Close() was called on the error path — correct.
	case <-time.After(time.Second):
		t.Fatal("dial returned (conn, err) but the conn was never closed (fd leak)")
	}
}

// closeSignalConn is a DnsConn that signals when Close is called.
type closeSignalConn struct {
	closed chan struct{}
}

func (c *closeSignalConn) ReserveNewQuery() (ReservedExchanger, bool) { return nil, true }
func (c *closeSignalConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
