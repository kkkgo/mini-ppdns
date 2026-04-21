package transport

import (
	"context"
	"encoding/binary"
	"net"
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
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
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
					defer pool.ReleaseBuf(wb)
					binary.BigEndian.PutUint16((*wb)[0:2], uint16(len(b)))
					copy((*wb)[2:], b)
					conn.Write(*wb)
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
