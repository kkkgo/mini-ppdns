/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
	"github.com/kkkgo/mini-ppdns/pkg/upstream/transport"

	"golang.org/x/net/proxy"
)

const (
	pipelineConcurrentLimit = 64
)

// Upstream represents a DNS upstream.
type Upstream interface {
	// ExchangeContext exchanges query message m to the upstream, and returns
	// response. It MUST NOT keep or modify m.
	// m MUST be a valid dns msg frame. It MUST be at least 12 bytes
	// (contain a valid dns header).
	ExchangeContext(ctx context.Context, m []byte) (*[]byte, error)

	io.Closer
}

type Opt struct {
	// DialAddr specifies the address the upstream will
	// actually dial to in the network layer by overwriting
	// the address inferred from upstream url.
	DialAddr string

	// Socks5 specifies the socks5 proxy server that the upstream
	// will connect though.
	Socks5 string

	// SoMark sets the socket SO_MARK option in unix system.
	SoMark int

	// BindToDevice sets the socket SO_BINDTODEVICE option in unix system.
	BindToDevice string

	// IdleTimeout specifies the idle timeout for long-connections.
	IdleTimeout time.Duration

	// EnablePipeline enables query pipelining support as RFC 7766 6.2.1.1 suggested.
	// Available for TCP upstream.
	EnablePipeline bool

	// Logger specifies the logger that the upstream will use.
	Logger *mlog.Logger

	// EventObserver can observe connection events.
	EventObserver EventObserver
}

// NewUpstream creates a upstream.
// addr has the format of: [protocol://]host[:port][/path].
// Supported protocol: udp/tcp. Default protocol is udp.
//
// Helper protocol:
//   - tcp+pipeline: Automatically set opt.EnablePipeline to true.
func NewUpstream(addr string, opt Opt) (_ Upstream, err error) {
	if opt.Logger == nil {
		opt.Logger = mlog.Nop()
	}
	if opt.EventObserver == nil {
		opt.EventObserver = nopEO{}
	}

	// parse protocol and server addr
	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	addrURL, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address, %w", err)
	}

	// Apply helper protocol
	switch addrURL.Scheme {
	case "tcp+pipeline":
		addrURL.Scheme = addrURL.Scheme[:3]
		opt.EnablePipeline = true
	}

	addrUrlHost := tryTrimIpv6Brackets(addrURL.Host)

	dialer := &net.Dialer{
		Control: getSocketControlFunc(socketOpts{
			so_mark:        opt.SoMark,
			bind_to_device: opt.BindToDevice,
		}),
	}

	newTcpDialer := func(dialAddrMustBeIp bool, defaultPort uint16) (func(ctx context.Context) (net.Conn, error), error) {
		host, port, err := parseDialAddr(addrUrlHost, opt.DialAddr, defaultPort)
		if err != nil {
			return nil, err
		}

		// Socks5 enabled.
		if s5Addr := opt.Socks5; len(s5Addr) > 0 {
			socks5Dialer, err := proxy.SOCKS5("tcp", s5Addr, nil, dialer)
			if err != nil {
				return nil, fmt.Errorf("failed to init socks5 dialer: %w", err)
			}

			contextDialer := socks5Dialer.(proxy.ContextDialer)
			dialAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
			return func(ctx context.Context) (net.Conn, error) {
				return contextDialer.DialContext(ctx, "tcp", dialAddr)
			}, nil
		}

		if _, err := netip.ParseAddr(host); err == nil {
			// Host is an ip addr. No need to resolve it.
			dialAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
			return func(ctx context.Context) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", dialAddr)
			}, nil
		} else {
			return nil, errors.New("addr must be an ip address")
		}
	}

	switch addrURL.Scheme {
	case "", "udp":
		const defaultPort = 53
		const maxConcurrentQueryPreConn = 4096 // Protocol limit is 65535.
		host, port, err := parseDialAddr(addrUrlHost, opt.DialAddr, defaultPort)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, fmt.Errorf("addr must be an ip address, %w", err)
		}
		dialAddr := joinPort(host, port)

		dialUdpPipeline := func(ctx context.Context) (transport.DnsConn, error) {
			c, err := dialer.DialContext(ctx, "udp", dialAddr)
			if err != nil {
				return nil, err
			}
			to := transport.TraditionalDnsConnOpts{
				WithLengthHeader:   false,
				IdleTimeout:        time.Minute * 5,
				MaxConcurrentQuery: maxConcurrentQueryPreConn,
			}
			return transport.NewDnsConn(to, wrapConn(c, opt.EventObserver)), nil
		}
		dialTcpNetConn := func(ctx context.Context) (transport.NetConn, error) {
			c, err := dialer.DialContext(ctx, "tcp", dialAddr)
			if err != nil {
				return nil, err
			}
			return wrapConn(c, opt.EventObserver), nil
		}

		return &udpWithFallback{
			u: transport.NewPipelineTransport(transport.PipelineOpts{
				DialContext:                    dialUdpPipeline,
				MaxConcurrentQueryWhileDialing: maxConcurrentQueryPreConn,
				Logger:                         opt.Logger,
			}),
			t: transport.NewReuseConnTransport(transport.ReuseConnOpts{DialContext: dialTcpNetConn}),
		}, nil
	case "tcp":
		const defaultPort = 53
		tcpDialer, err := newTcpDialer(true, defaultPort)
		if err != nil {
			return nil, fmt.Errorf("failed to init tcp dialer, %w", err)
		}
		idleTimeout := opt.IdleTimeout
		if idleTimeout <= 0 {
			idleTimeout = time.Second * 10
		}

		dialNetConn := func(ctx context.Context) (transport.NetConn, error) {
			c, err := tcpDialer(ctx)
			if err != nil {
				return nil, err
			}
			return wrapConn(c, opt.EventObserver), nil
		}
		if opt.EnablePipeline {
			to := transport.TraditionalDnsConnOpts{
				WithLengthHeader:   true,
				IdleTimeout:        idleTimeout,
				MaxConcurrentQuery: pipelineConcurrentLimit,
			}
			dialDnsConn := func(ctx context.Context) (transport.DnsConn, error) {
				c, err := dialNetConn(ctx)
				if err != nil {
					return nil, err
				}
				return transport.NewDnsConn(to, c), nil
			}
			return transport.NewPipelineTransport(transport.PipelineOpts{
				DialContext:                    dialDnsConn,
				MaxConcurrentQueryWhileDialing: pipelineConcurrentLimit,
				Logger:                         opt.Logger,
			}), nil
		}
		return transport.NewReuseConnTransport(transport.ReuseConnOpts{DialContext: dialNetConn, IdleTimeout: idleTimeout}), nil
	default:
		return nil, fmt.Errorf("unsupported protocol [%s]", addrURL.Scheme)
	}
}

type udpWithFallback struct {
	u *transport.PipelineTransport
	t *transport.ReuseConnTransport
}

func (u *udpWithFallback) ExchangeContext(ctx context.Context, q []byte) (*[]byte, error) {
	r, err := u.u.ExchangeContext(ctx, q)
	if err != nil {
		return nil, err
	}
	if msgTruncated(*r) {
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
