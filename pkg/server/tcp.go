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

package server

import (
	"context"
	"errors"

	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/dnsutils"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

const (
	defaultTCPIdleTimeout = time.Second * 10
	tcpFirstReadTimeout   = time.Second * 1
)

type TCPServerOpts struct {
	// Nil logger == nop
	Logger *mlog.Logger

	// Default is defaultTCPIdleTimeout.
	IdleTimeout time.Duration
}

// Start a server at l. Return if l had an Accept() error.
// Always return a non-nil error.
func ServeTCP(l net.Listener, h Handler, opts TCPServerOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	firstReadTimeout := tcpFirstReadTimeout
	if idleTimeout < firstReadTimeout {
		firstReadTimeout = idleTimeout
	}

	listenerCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(errListenerCtxCanceled)
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		// Handle connection
		tcpConnCtx, cancelConn := context.WithCancelCause(listenerCtx)
		go func() {
			defer c.Close()
			defer cancelConn(errConnectionCtxCanceled)

			firstRead := true
			for {
				if firstRead {
					firstRead = false
					c.SetReadDeadline(time.Now().Add(firstReadTimeout))
				} else {
					c.SetReadDeadline(time.Now().Add(idleTimeout))
				}
				req, _, err := dnsutils.ReadMsgFromTCP(c)
				if err != nil {
					return // read err, close the connection
				}

				// Handle query
				go func() {
					var clientAddr netip.Addr
					ta, ok := c.RemoteAddr().(*net.TCPAddr)
					if ok {
						clientAddr = ta.AddrPort().Addr()
					}
					r := h.Handle(tcpConnCtx, req, QueryMeta{ClientAddr: clientAddr, FromUDP: false}, pool.PackTCPBuffer)
					if r == nil {
						c.Close() // abort the connection
						return
					}
					defer pool.ReleaseBuf(r)

					if _, err := c.Write(*r); err != nil {
						logger.Warnf("failed to write response client=%v err=%v", c.RemoteAddr(), err)
						return
					}
				}()
			}
		}()
	}
}
