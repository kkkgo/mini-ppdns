package server

import (
	"context"
	"errors"
	"net/netip"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/mlog"
)

const (
	// DefaultMaxConcurrent is the default limit for concurrent handler goroutines.
	DefaultMaxConcurrent = 4096
)

// Handler handles incoming DNS requests.
// Handlers MUST always return a response payload (or nil to abort).
type Handler interface {
	Handle(ctx context.Context, q *dns.Msg, meta QueryMeta, packMsgPayload func(m *dns.Msg) (*[]byte, error)) (respPayload *[]byte)
}

// QueryMeta contains metadata about the DNS query.
type QueryMeta struct {
	ClientAddr netip.Addr
	FromUDP    bool
}

var (
	errListenerCtxCanceled   = errors.New("listener ctx canceled")
	errConnectionCtxCanceled = errors.New("connection ctx canceled")
)

var (
	nopLogger = mlog.Nop()
)
