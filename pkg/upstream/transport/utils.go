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

package transport

import (
	"encoding/binary"
	"io"

	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
	"github.com/miekg/dns"
)

// Numeric constraint for integer and float types.
type Numeric interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}

const (
	dnsHeaderLen = 12 // minimum dns msg size
)

func copyMsgWithLenHdr(m []byte) (*[]byte, error) {
	l := len(m)
	if l > dns.MaxMsgSize {
		return nil, ErrPayloadOverFlow
	}
	bp := pool.GetBuf(l + 2)
	binary.BigEndian.PutUint16(*bp, uint16(l))
	copy((*bp)[2:], m)
	return bp, nil
}

func copyMsg(m []byte) *[]byte {
	bp := pool.GetBuf(len(m))
	copy((*bp), m)
	return bp
}

// readMsgUdp reads dns frame from r. r typically should be a udp connection.
// It uses a 4kb rx buffer and ignores any payload that is too small for a dns msg.
// If no error, the length of payload always >= 12 bytes.
func readMsgUdp(r io.Reader) (*[]byte, error) {
	payload := pool.GetBuf(4096)
	for {
		n, err := r.Read(*payload)
		if err != nil {
			pool.ReleaseBuf(payload)
			return nil, err
		}
		if n >= dnsHeaderLen {
			*payload = (*payload)[:n]
			return payload, nil
		}
	}
}

func setDefaultGZ[T Numeric](i *T, s, d T) {
	if s > 0 {
		*i = s
	} else {
		*i = d
	}
}

var nopLogger = mlog.Nop()

func setNonNilLogger(i **mlog.Logger, s *mlog.Logger) {
	if s != nil {
		*i = s
	} else {
		*i = nopLogger
	}
}
