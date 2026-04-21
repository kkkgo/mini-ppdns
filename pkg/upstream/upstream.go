package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
	"github.com/kkkgo/mini-ppdns/pkg/upstream/transport"
)

const (
	// pipelineConcurrentLimit caps concurrent outstanding queries per
	// pipelined TCP/UDP connection. RFC 7766 suggests pipelining without
	// prescribing a ceiling; 64 is comfortable for a single resolver and
	// small enough that a misbehaving server can't run us out of qids.
	pipelineConcurrentLimit = 64

	// udpPipelineConcurrent is higher because a UDP socket's 16-bit qid
	// space is practically unconstrained — each query is a datagram, so
	// there's no head-of-line blocking to worry about.
	udpPipelineConcurrent = 4096

	// tcpReuseIdle is the default idle timeout for the reuse (non-
	// pipelined) TCP transport.
	tcpReuseIdle = 10 * time.Second

	// udpPipelineIdle is how long an idle UDP "pipeline" socket sticks
	// around before we rebuild it. Longer than TCP because UDP sockets
	// are cheap to hold and rebuilding pays on every conntrack expiry.
	udpPipelineIdle = 5 * time.Minute

	// dnsDefaultPort is the well-known DNS port.
	dnsDefaultPort = 53
)

// Upstream is a DNS upstream exchanger.
type Upstream interface {
	// ExchangeContext sends the wire-format query m to the upstream and
	// returns the response. m must be a valid DNS frame (>= 12 bytes).
	// The implementation must NOT retain or modify m.
	ExchangeContext(ctx context.Context, m []byte) (*[]byte, error)
	io.Closer
}

type Opt struct {
	// DialAddr overrides the network-level dial target inferred from the
	// upstream URL. Useful when the URL encodes a logical name but the
	// caller wants to pin a specific IP.
	DialAddr string

	// SoMark sets SO_MARK on the outbound socket (Linux).
	SoMark int

	// BindToDevice sets SO_BINDTODEVICE on the outbound socket (Linux).
	BindToDevice string

	// IdleTimeout bounds how long an idle long-lived connection is kept.
	IdleTimeout time.Duration

	// EnablePipeline activates RFC 7766 §6.2.1.1 pipelining on TCP.
	EnablePipeline bool

	// Logger for internal diagnostics. Nil is replaced with a no-op.
	Logger *mlog.Logger

	// EventObserver receives connection open/close events. Nil is
	// replaced with a no-op observer.
	EventObserver EventObserver
}

// NewUpstream constructs an Upstream from a URL-style address.
//
// Address format: [scheme://]host[:port]
//
// Supported schemes:
//   - udp (default when scheme is omitted): UDP with TCP fallback on truncation
//   - tcp: connection-reuse TCP resolver (no pipelining)
//   - tcp+pipeline: shorthand for tcp + EnablePipeline=true
func NewUpstream(addr string, opt Opt) (Upstream, error) {
	applyOptDefaults(&opt)

	u, err := parseUpstreamAddr(addr)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "tcp+pipeline" {
		u.Scheme = "tcp"
		opt.EnablePipeline = true
	}

	host := tryTrimIpv6Brackets(u.Host)
	dialer := &net.Dialer{
		Control: buildDialControl(socketOpts{
			so_mark:        opt.SoMark,
			bind_to_device: opt.BindToDevice,
		}),
	}

	switch u.Scheme {
	case "", "udp":
		return buildUDPUpstream(host, dialer, opt)
	case "tcp":
		return buildTCPUpstream(host, dialer, opt)
	default:
		return nil, fmt.Errorf("unsupported protocol [%s]", u.Scheme)
	}
}

func applyOptDefaults(opt *Opt) {
	if opt.Logger == nil {
		opt.Logger = mlog.Nop()
	}
	if opt.EventObserver == nil {
		opt.EventObserver = nopEO{}
	}
}

func parseUpstreamAddr(addr string) (*url.URL, error) {
	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address, %w", err)
	}
	return u, nil
}

// resolvedHostPort ensures host is a literal IP (upstream must be a
// numeric address — we don't bootstrap DNS from DNS) and joins it with
// the given default port.
func resolvedHostPort(urlHost, dialAddr string, defaultPort uint16) (string, error) {
	host, port, err := parseDialAddr(urlHost, dialAddr, defaultPort)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", fmt.Errorf("addr must be an ip address, %w", err)
	}
	return joinPort(host, port), nil
}

func buildUDPUpstream(urlHost string, dialer *net.Dialer, opt Opt) (Upstream, error) {
	addr, err := resolvedHostPort(urlHost, opt.DialAddr, dnsDefaultPort)
	if err != nil {
		return nil, err
	}

	dialUDPPipeline := func(ctx context.Context) (transport.DnsConn, error) {
		c, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, err
		}
		return transport.NewDnsConn(transport.TraditionalDnsConnOpts{
			WithLengthHeader:   false,
			IdleTimeout:        udpPipelineIdle,
			MaxConcurrentQuery: udpPipelineConcurrent,
		}, wrapConn(c, opt.EventObserver)), nil
	}
	dialTCPFallback := func(ctx context.Context) (transport.NetConn, error) {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return wrapConn(c, opt.EventObserver), nil
	}

	return &udpWithFallback{
		u: transport.NewPipelineTransport(transport.PipelineOpts{
			DialContext:                    dialUDPPipeline,
			MaxConcurrentQueryWhileDialing: udpPipelineConcurrent,
			Logger:                         opt.Logger,
		}),
		t: transport.NewReuseConnTransport(transport.ReuseConnOpts{
			DialContext: dialTCPFallback,
		}),
	}, nil
}

func buildTCPUpstream(urlHost string, dialer *net.Dialer, opt Opt) (Upstream, error) {
	host, port, err := parseDialAddr(urlHost, opt.DialAddr, dnsDefaultPort)
	if err != nil {
		return nil, fmt.Errorf("failed to init tcp dialer, %w", err)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, errors.New("failed to init tcp dialer, addr must be an ip address")
	}
	tcpAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	idle := opt.IdleTimeout
	if idle <= 0 {
		idle = tcpReuseIdle
	}

	dialNet := func(ctx context.Context) (transport.NetConn, error) {
		c, err := dialer.DialContext(ctx, "tcp", tcpAddr)
		if err != nil {
			return nil, err
		}
		return wrapConn(c, opt.EventObserver), nil
	}

	if !opt.EnablePipeline {
		return transport.NewReuseConnTransport(transport.ReuseConnOpts{
			DialContext: dialNet,
			IdleTimeout: idle,
		}), nil
	}

	dnsOpts := transport.TraditionalDnsConnOpts{
		WithLengthHeader:   true,
		IdleTimeout:        idle,
		MaxConcurrentQuery: pipelineConcurrentLimit,
	}
	dialDns := func(ctx context.Context) (transport.DnsConn, error) {
		c, err := dialNet(ctx)
		if err != nil {
			return nil, err
		}
		return transport.NewDnsConn(dnsOpts, c), nil
	}
	return transport.NewPipelineTransport(transport.PipelineOpts{
		DialContext:                    dialDns,
		MaxConcurrentQueryWhileDialing: pipelineConcurrentLimit,
		Logger:                         opt.Logger,
	}), nil
}

// udpWithFallback sends over UDP, then retries the same query over TCP
// if the UDP answer has the TC (truncated) flag set — the classic
// RFC 1035 fallback path.
type udpWithFallback struct {
	u *transport.PipelineTransport
	t *transport.ReuseConnTransport
}

func (u *udpWithFallback) ExchangeContext(ctx context.Context, q []byte) (*[]byte, error) {
	r, err := u.u.ExchangeContext(ctx, q)
	if err != nil {
		return nil, err
	}
	// Bounds check first (needs at least header flags byte 2), then TC.
	if len(*r) >= 3 && msgTruncated(*r) {
		pool.ReleaseBuf(r)
		return u.t.ExchangeContext(ctx, q)
	}
	return r, nil
}

func (u *udpWithFallback) Close() error {
	u.u.Close()
	u.t.Close()
	return nil
}

// ---- Connection event observer ----

// Event identifies the kind of connection lifecycle event fired to an
// EventObserver.
type Event int

const (
	EventConnOpen Event = iota
	EventConnClose
)

// EventObserver receives connection lifecycle events. Implementations
// must be safe for concurrent use; events fire from whichever goroutine
// happens to dial or close a connection.
type EventObserver interface {
	OnEvent(typ Event)
}

// nopEO is the zero-cost observer used when the caller did not supply one.
type nopEO struct{}

func (nopEO) OnEvent(Event) {}

// connWrapper decorates a net.Conn so Close fires an EventConnClose
// exactly once. Open is fired synchronously from wrapConn.
type connWrapper struct {
	net.Conn
	ob     EventObserver
	closed atomic.Bool
}

// wrapConn returns c decorated with open/close event firing on ob. When
// ob is nopEO the decoration is skipped entirely (no event, raw conn
// returned) to keep the common "no observer" path allocation-free.
// Passing nil c yields nil.
func wrapConn(c net.Conn, ob EventObserver) net.Conn {
	if c == nil {
		return nil
	}
	if _, noop := ob.(nopEO); noop {
		return c
	}
	ob.OnEvent(EventConnOpen)
	return &connWrapper{Conn: c, ob: ob}
}

func (c *connWrapper) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.ob.OnEvent(EventConnClose)
	}
	return c.Conn.Close()
}
