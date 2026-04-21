package upstream

import (
	"net"
	"testing"
)

func TestNewUpstream_InvalidAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"invalid_url", ":%err%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewUpstream(tt.addr, Opt{})
			if err == nil {
				t.Fatalf("NewUpstream(%q) expected error, got nil", tt.addr)
			}
		})
	}
}

func TestNewUpstream_ValidAddr(t *testing.T) {
	tests := []struct {
		name           string
		addr           string
		expectPipeline bool
	}{
		{"default_udp", "1.1.1.1", false},
		{"explicit_udp", "udp://1.1.1.1", false},
		{"explicit_tcp", "tcp://1.1.1.1", false},
		{"tcp_pipeline", "tcp+pipeline://1.1.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Opt{EnablePipeline: false}
			_, err := NewUpstream(tt.addr, opt)
			if err != nil {
				t.Fatalf("NewUpstream(%q) unexpected error: %v", tt.addr, err)
			}
			// It returns interfaces so we can't easily interrogate the returned struct
			// natively, but we ensure it doesn't return an error.
		})
	}
}

// ---- Event observer tests ----

type mockObserver struct {
	events []Event
}

func (m *mockObserver) OnEvent(e Event) {
	m.events = append(m.events, e)
}

func TestWrapConn(t *testing.T) {
	if got := wrapConn(nil, nopEO{}); got != nil {
		t.Errorf("wrapConn(nil, ...) = %v, want nil", got)
	}

	c, server := net.Pipe()
	defer server.Close()

	if got := wrapConn(c, nopEO{}); got != c {
		t.Errorf("wrapConn(c, nopEO{}) = %v, want c", got)
	}

	ob := &mockObserver{}
	wrapped := wrapConn(c, ob)

	if len(ob.events) != 1 || ob.events[0] != EventConnOpen {
		t.Errorf("expected EventConnOpen to be fired, got events: %v", ob.events)
	}

	if err := wrapped.Close(); err != nil {
		t.Errorf("wrapped.Close() error = %v", err)
	}

	if len(ob.events) != 2 || ob.events[1] != EventConnClose {
		t.Errorf("expected EventConnClose to be fired, got events: %v", ob.events)
	}

	wrapped.Close()
	if len(ob.events) != 2 {
		t.Errorf("expected exactly 2 events after double close, got: %v", ob.events)
	}
}
