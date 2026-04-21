package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

// ReservedExchanger is a single-use exchange slot handed out by a
// DnsConn. Exactly one of ExchangeReserved / WithdrawReserved must be
// called; skipping both leaks a pending-query slot on the underlying
// connection.
type ReservedExchanger interface {
	// ExchangeReserved writes q to the server and awaits the reply.
	// Implementations must not retain or mutate q. The returned buffer
	// is caller-owned — hand it back via pool.ReleaseBuf once done with
	// the response.
	ExchangeReserved(ctx context.Context, q []byte) (resp *[]byte, err error)

	// WithdrawReserved releases an unused reservation.
	WithdrawReserved()
}

// DnsConn is the DNS-aware connection contract the transport layer
// speaks to. ReserveNewQuery is non-blocking: (nil, false) means "full
// for now, try again"; (nil, true) means "dead, don't bother".
type DnsConn interface {
	ReserveNewQuery() (_ ReservedExchanger, closed bool)
	io.Closer
}

// NetConn is the subset of net.Conn semantics we need. Narrower than
// net.Conn so tests can supply a pipe-backed fake without pulling in
// the full interface.
type NetConn interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Defaults substituted in when a caller leaves an option field zero.
const (
	dialTimeoutDefault           = 5 * time.Second
	idleTimeoutDefault           = 10 * time.Second
	tdcMaxConcurrentQueryDefault = 32
	lazyConnQueueDefault         = 16

	// replyWaitLimit is how long a pipelined connection will wait for
	// ANY inbound frame (not necessarily the one we just sent) before
	// concluding the peer has gone silent. Crossing the limit closes
	// the connection so the upstream can redial.
	replyWaitLimit = 10 * time.Second
)

// Sentinel errors. Compare with errors.Is.
var (
	ErrClosedTransport                     = errors.New("transport is closed")
	ErrPayloadOverFlow                     = errors.New("dns payload exceeds size limit")
	ErrNewConnCannotReserveQueryExchanger  = errors.New("new connection could not reserve an exchange slot")
	ErrLazyConnCannotReserveQueryExchanger = errors.New("lazy connection could not reserve an exchange slot")
)

// maxUdpReadRetries bounds how many undersized UDP datagrams we swallow
// before giving up. Real DNS answers are always >= 12 bytes, so a flood
// of shorter packets is evidence of a scan or a broken peer.
const maxUdpReadRetries = 128

// Numeric is the set of integer/float types the setDefaultGZ helper
// accepts. Kept as a named constraint so the intent at call sites
// (numeric option with "zero means default") is self-documenting.
type Numeric interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}

// dnsHeaderLen is the 12-byte fixed DNS header; shorter frames cannot
// be valid messages.
const dnsHeaderLen = 12

// copyMsgWithLenHdr returns a fresh pool-backed buffer whose first two
// bytes are the big-endian length of m and whose remainder is m. Used
// to frame a raw DNS message for TCP/DoT transports.
func copyMsgWithLenHdr(m []byte) (*[]byte, error) {
	n := len(m)
	if n > dns.MaxMsgSize {
		return nil, ErrPayloadOverFlow
	}
	out := pool.GetBuf(n + 2)
	binary.BigEndian.PutUint16((*out)[:2], uint16(n))
	copy((*out)[2:], m)
	return out, nil
}

// copyMsg returns a pool-backed duplicate of m. Used when the caller
// needs an owned buffer (e.g. to write to a UDP socket while the
// original backing array may be recycled).
func copyMsg(m []byte) *[]byte {
	out := pool.GetBuf(len(m))
	copy(*out, m)
	return out
}

// readMsgUdp reads a single DNS datagram from r. The rx buffer is the
// protocol maximum (64 KiB) so EDNS0 responses up to that size aren't
// truncated. Undersized datagrams (< 12 bytes) are skipped and retried
// up to maxUdpReadRetries times — most often these are stray scan
// packets hitting the ephemeral port.
func readMsgUdp(r io.Reader) (*[]byte, error) {
	buf := pool.GetBuf(dns.MaxMsgSize)
	for range maxUdpReadRetries {
		n, err := r.Read(*buf)
		if err != nil {
			pool.ReleaseBuf(buf)
			return nil, err
		}
		if n >= dnsHeaderLen {
			*buf = (*buf)[:n]
			return buf, nil
		}
	}
	pool.ReleaseBuf(buf)
	return nil, fmt.Errorf("readMsgUdp: exceeded %d retries reading undersized packets", maxUdpReadRetries)
}

// setDefaultGZ writes src to *dst when src is strictly positive; otherwise
// writes dflt. "GZ" = "greater-than-zero" — the convention we use for
// duration/count option fields where zero means "use the default".
func setDefaultGZ[T Numeric](dst *T, src, dflt T) {
	if src > 0 {
		*dst = src
		return
	}
	*dst = dflt
}

var nopLogger = mlog.Nop()

// setNonNilLogger stores src in *dst, substituting a package-local
// no-op logger when src is nil. Keeps callers from sprinkling nil
// checks before every log call.
func setNonNilLogger(dst **mlog.Logger, src *mlog.Logger) {
	if src != nil {
		*dst = src
		return
	}
	*dst = nopLogger
}
