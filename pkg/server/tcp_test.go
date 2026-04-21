package server

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/kkkgo/mini-ppdns/pkg/dnsutils"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

type mockHandler struct {
	called atomic.Bool
}

func (m *mockHandler) Handle(ctx context.Context, q *dns.Msg, meta QueryMeta, packMsgPayload func(m *dns.Msg) (*[]byte, error)) *[]byte {
	m.called.Store(true)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, q)
	b, _ := packMsgPayload(resp)
	return b
}

func TestServeTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	h := &mockHandler{}
	opts := TCPServerOpts{
		IdleTimeout:   time.Second * 2,
		MaxConcurrent: 10,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeTCP(l, h, opts)
	}()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Make a client request
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, dnsutil.Fqdn("example.com"), dns.TypeA)
	if err := m.Pack(); err != nil {
		t.Fatalf("failed to pack msg: %v", err)
	}
	b := m.Data

	wb := pool.GetBuf(2 + len(b))
	defer pool.ReleaseBuf(wb)
	binary.BigEndian.PutUint16((*wb)[0:2], uint16(len(b)))
	copy((*wb)[2:], b)

	if _, err := conn.Write(*wb); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(time.Second))
	respMsg, _, err := dnsutils.ReadMsgFromTCP(conn)
	if err != nil {
		t.Fatalf("failed to read resp: %v", err)
	}

	if respMsg.ID != m.ID {
		t.Errorf("expected id %d, got %d", m.ID, respMsg.ID)
	}
	if !h.called.Load() {
		t.Error("handler was not called")
	}

	// Test shutdown
	l.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ServeTCP returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("ServeTCP did not return after listener close")
	}
}
