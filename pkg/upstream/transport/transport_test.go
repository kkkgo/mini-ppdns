package transport

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/kkkgo/mini-ppdns/pkg/dnsutils"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

func runMockServer(t *testing.T, network, addr string) net.Listener {
	l, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	var mu sync.Mutex
	conns := make(map[net.Conn]struct{})
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for c := range conns {
			_ = c.SetReadDeadline(time.Now())
			_ = c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[c] = struct{}{}
			mu.Unlock()
			go func(conn net.Conn) {
				defer func() {
					_ = conn.Close()
					mu.Lock()
					delete(conns, conn)
					mu.Unlock()
				}()
				for {
					req, _, err := dnsutils.ReadMsgFromTCP(conn)
					if err != nil {
						return
					}
					resp := new(dns.Msg)
					dnsutil.SetReply(resp, req)
					if err := resp.Pack(); err != nil {
						return
					}
					b := resp.Data
					wb := pool.GetBuf(2 + len(b))
					binary.BigEndian.PutUint16((*wb)[0:2], uint16(len(b)))
					copy((*wb)[2:], b)
					_, _ = conn.Write(*wb)
					pool.ReleaseBuf(wb)
				}
			}(c)
		}
	}()
	return l
}

func TestReuseConnTransport_Exchange(t *testing.T) {
	l := runMockServer(t, "tcp", "127.0.0.1:0")
	defer l.Close()

	dialFunc := func(ctx context.Context) (NetConn, error) {
		c, err := new(net.Dialer).DialContext(ctx, "tcp", l.Addr().String())
		return c, err
	}

	opt := ReuseConnOpts{
		DialContext: dialFunc,
		DialTimeout: time.Second * 2,
		IdleTimeout: time.Second * 2,
	}

	tr := NewReuseConnTransport(opt)
	defer tr.Close()

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, dnsutil.Fqdn("example.com"), dns.TypeA)
	if err := m.Pack(); err != nil {
		t.Fatalf("Pack failed: %v", err)
	}
	b := m.Data

	// First exchange (creates new conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	respBytes, err := tr.ExchangeContext(ctx, b)
	if err != nil {
		t.Fatalf("ExchangeContext failed: %v", err)
	}
	defer pool.ReleaseBuf(respBytes)

	resp := new(dns.Msg)
	resp.Data = *respBytes
	resp.Unpack()
	if resp.ID != m.ID {
		t.Fatalf("expected id %d, got %d", m.ID, resp.ID)
	}

	// Wait a bit to ensure it enters idle state
	time.Sleep(50 * time.Millisecond)

	// Second exchange (should reuse conn)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	m.ID++
	if err := m.Pack(); err != nil {
		t.Fatalf("Pack 2 failed: %v", err)
	}
	b2 := m.Data
	respBytes2, err2 := tr.ExchangeContext(ctx2, b2)
	if err2 != nil {
		t.Fatalf("ExchangeContext 2 failed: %v", err2)
	}
	defer pool.ReleaseBuf(respBytes2)

	resp2 := new(dns.Msg)
	resp2.Data = *respBytes2
	resp2.Unpack()
	if resp2.ID != m.ID {
		t.Fatalf("expected id %d, got %d", m.ID, resp2.ID)
	}
}

func TestPipelineTransport_Exchange(t *testing.T) {
	l := runMockServer(t, "tcp", "127.0.0.1:0")
	defer l.Close()

	dialDnsConn := func(ctx context.Context) (DnsConn, error) {
		c, err := new(net.Dialer).DialContext(ctx, "tcp", l.Addr().String())
		if err != nil {
			return nil, err
		}
		to := TraditionalDnsConnOpts{
			WithLengthHeader:   true,
			IdleTimeout:        time.Second * 2,
			MaxConcurrentQuery: 64,
		}
		return NewDnsConn(to, c), nil
	}

	opt := PipelineOpts{
		DialContext:                    dialDnsConn,
		MaxConcurrentQueryWhileDialing: 64,
	}

	tr := NewPipelineTransport(opt)
	defer tr.Close()

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, dnsutil.Fqdn("example.com"), dns.TypeA)
	if err := m.Pack(); err != nil {
		t.Fatalf("Pack failed: %v", err)
	}
	b := m.Data

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	respBytes, err := tr.ExchangeContext(ctx, b)
	if err != nil {
		t.Fatalf("ExchangeContext failed: %v", err)
	}
	defer pool.ReleaseBuf(respBytes)

	resp := new(dns.Msg)
	resp.Data = *respBytes
	resp.Unpack()
	if resp.ID != m.ID {
		t.Fatalf("expected id %d, got %d", m.ID, resp.ID)
	}
}

// TestPipelineTransport_MaxConnsBackpressure verifies that reserveExchanger
// blocks (rather than dialing unboundedly) once maxConns is reached, and
// that a subsequent ctx cancellation releases the waiting caller.
func TestPipelineTransport_MaxConnsBackpressure(t *testing.T) {
	// Dial hangs forever so every reserveExchanger holds its semaphore
	// token indefinitely. With MaxConns=1, the second caller must block
	// in acquireSlot until ctx fires.
	dialCh := make(chan struct{})
	hangingDial := func(ctx context.Context) (DnsConn, error) {
		<-dialCh
		return nil, context.Canceled
	}
	tr := NewPipelineTransport(PipelineOpts{
		DialContext: hangingDial,
		MaxConns:    1,
	})
	defer func() {
		close(dialCh)
		tr.Close()
	}()

	// Fill the one-slot semaphore via a goroutine that will block on the
	// hanging dial.
	firstDone := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = tr.ExchangeContext(ctx, make([]byte, 12))
		close(firstDone)
	}()
	// Let the first goroutine reach acquireSlot + dial.
	time.Sleep(50 * time.Millisecond)

	// Second caller must block on acquireSlot. Fire a short context and
	// assert that it times out (proving back-pressure engaged) rather
	// than succeeding by dialing a second conn.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := tr.ExchangeContext(ctx, make([]byte, 12))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("second ExchangeContext unexpectedly succeeded under MaxConns=1")
	}
	if elapsed < 80*time.Millisecond {
		t.Fatalf("second call returned in %v, expected to block ~100ms", elapsed)
	}
}
