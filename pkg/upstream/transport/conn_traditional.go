package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kkkgo/mini-ppdns/pkg/dnsutils"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

// Sentinel errors. Compare with errors.Is.
var (
	ErrTDCTooManyQueries = errors.New("too many queries")
	ErrTDCClosed         = errors.New("dns connection closed")
)

// pendingSlabCap sizes the inline fast-path storage for the per-connection
// pending-query index. It's large enough to cover the default
// tdcMaxConcurrentQueryDefault (32) and the pipeline-side limit (64) with
// slack to spare; anything beyond this spills into a lazily-allocated
// overflow map. A naive `[65536]chan *[]byte` would cost ~256 KiB per
// connection and be almost entirely dead space — production DNS rarely
// multiplexes dozens of queries on one connection, let alone thousands.
const pendingSlabCap = 256

// udpResendMax bounds how many extra copies of the same query a UDP
// exchange will retransmit before giving up. The 1-second resend ticker
// could otherwise fire ~10 times against a silently-dead peer (under
// udpPipelineIdle = 5min and replyWaitLimit = 10s), each amplifying
// upstream bandwidth without changing the outcome. Three total sends
// (initial + 2 resends) matches typical stub resolver behavior.
const udpResendMax = 2

// pendingEntry holds the reply channel and the question metadata for one
// in-flight query. The qname/qtype pair is used by readLoop to verify
// that an inbound frame really belongs to the recorded waiter — this
// closes a misroute hazard where a late response arrives after qid
// recycling and would otherwise be delivered to whichever new exchange
// happened to grab the same qid.
//
// qname is stored as a private copy of the wire-format QNAME, lower-cased
// (ASCII only) so the case-insensitive comparison against an upstream
// echo can be a plain bytes.Equal. Empty qname means "no match check"
// (used by the zero-q benchmark path).
type pendingEntry struct {
	qname []byte
	qtype uint16
	ch    chan *[]byte
}

// slabSlot is one inline entry in the pending-query index. A nil entry.ch
// marks the slot free.
type slabSlot struct {
	qid   uint16
	entry pendingEntry
}

// pendingTable maps in-flight DNS qids to the goroutine waiting for the
// matching reply.
//
// Two storage tiers:
//   - slab:     fixed-size inline array sized for the common case. Inserts
//     are linear in pendingSlabCap worst-case but in practice
//     terminate within the first handful of probes.
//   - overflow: map, only materialised when the slab saturates.
//
// locate is the qid → tier index. A non-negative value is a slab index;
// -1 means the entry lives in overflow. A missing key means the qid is
// free.
//
// The zero value is ready to use: locate and overflow are created lazily
// so benchmarks can spin up a bare TraditionalDnsConn without a
// constructor.
type pendingTable struct {
	mu sync.RWMutex

	slab     [pendingSlabCap]slabSlot
	slabUsed int

	locate   map[uint16]int16
	overflow map[uint16]pendingEntry

	// cursor hints at the next qid to try. Wraps around the full 16-bit
	// space; pickQidLocked rejects collisions with live entries.
	cursor uint16

	// reserved tracks ReserveNewQuery handles that have not yet called
	// through to add(). Counted alongside live locate entries against
	// the maxCq cap so two ReserveNewQuery calls can't collectively
	// exceed it before either consumes its slot.
	reserved int
}

func (p *pendingTable) ensureLocateLocked() {
	if p.locate == nil {
		p.locate = make(map[uint16]int16, pendingSlabCap)
	}
}

// tryReserve claims one slot against the given cap if room remains. Every
// successful tryReserve must be paired with either an add() (which
// consumes the reservation conceptually but does not decrement it — the
// caller still owes a releaseReserve) or a releaseReserve() directly.
func (p *pendingTable) tryReserve(maxCq int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensureLocateLocked()
	if len(p.locate)+p.reserved >= maxCq {
		return false
	}
	p.reserved++
	return true
}

func (p *pendingTable) releaseReserve() {
	p.mu.Lock()
	if p.reserved > 0 {
		p.reserved--
	}
	p.mu.Unlock()
}

// pickQidLocked returns an unused qid, starting from the cursor. Caller
// holds p.mu for writing. In the common case this succeeds on the first
// iteration; the outer cap check guarantees at least one slot is free.
func (p *pendingTable) pickQidLocked() (uint16, bool) {
	for range 1 << 16 {
		qid := p.cursor
		p.cursor++
		if _, taken := p.locate[qid]; !taken {
			return qid, true
		}
	}
	return 0, false
}

// add registers a reply channel under a fresh qid and returns the pair.
// capLimit bounds total occupancy; a value of 0 means "only the 16-bit
// qid space caps us" (used by the benchmark path). qname/qtype identify
// the question section the upstream is expected to echo; the table keeps
// a private lower-cased copy of qname so subsequent caller mutations of
// the source slice cannot disturb the readLoop comparison. Pass an empty
// qname to skip the match check (legacy benchmark only).
// Returns (0, nil) when no slot is available.
func (p *pendingTable) add(capLimit int, qname []byte, qtype uint16) (uint16, chan *[]byte) {
	ch := make(chan *[]byte, 1)

	var qnameCopy []byte
	if len(qname) > 0 {
		qnameCopy = make([]byte, len(qname))
		for i, b := range qname {
			// ASCII fold only — DNS labels are 7-bit ASCII per RFC 1035.
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			qnameCopy[i] = b
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensureLocateLocked()

	if capLimit > 0 && len(p.locate) >= capLimit {
		return 0, nil
	}
	if len(p.locate) >= 1<<16 {
		return 0, nil
	}

	qid, ok := p.pickQidLocked()
	if !ok {
		return 0, nil
	}

	entry := pendingEntry{qname: qnameCopy, qtype: qtype, ch: ch}

	if p.slabUsed < pendingSlabCap {
		for i := range p.slab {
			if p.slab[i].entry.ch == nil {
				p.slab[i] = slabSlot{qid: qid, entry: entry}
				p.slabUsed++
				p.locate[qid] = int16(i)
				return qid, ch
			}
		}
		// slabUsed < pendingSlabCap should guarantee a free slot exists.
	}

	if p.overflow == nil {
		p.overflow = make(map[uint16]pendingEntry)
	}
	p.overflow[qid] = entry
	p.locate[qid] = -1
	return qid, ch
}

// lookup returns the entry currently registered for qid. The returned
// pendingEntry has a nil ch when no entry exists. The qname slice in the
// returned value is owned by the table and remains valid until the next
// remove for this qid.
func (p *pendingTable) lookup(qid uint16) pendingEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.locate == nil {
		return pendingEntry{}
	}
	loc, ok := p.locate[qid]
	if !ok {
		return pendingEntry{}
	}
	if loc >= 0 {
		return p.slab[loc].entry
	}
	return p.overflow[qid]
}

// remove releases qid. No-op if the qid is absent.
func (p *pendingTable) remove(qid uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.locate == nil {
		return
	}
	loc, ok := p.locate[qid]
	if !ok {
		return
	}
	delete(p.locate, qid)
	if loc >= 0 {
		p.slab[loc] = slabSlot{}
		p.slabUsed--
		return
	}
	delete(p.overflow, qid)
}

// extractQuestion parses the QNAME (raw wire bytes, no compression) and
// QTYPE from a packed DNS message. Compression pointers in the question
// section are illegal per RFC 1035 §4.1.4, so the parser rejects them.
// Returns ok=false on any malformed framing; readLoop and addQueueC use
// that to drop the frame without delivering.
func extractQuestion(msg []byte) (qname []byte, qtype uint16, ok bool) {
	const hdrLen = 12
	if len(msg) < hdrLen+5 { // header + at least root-label + qtype + qclass
		return nil, 0, false
	}
	p := hdrLen
	start := p
	for p < len(msg) {
		l := int(msg[p])
		if l == 0 { // root label terminator
			p++
			break
		}
		// Top two bits non-zero ⇒ pointer (0xc0) or reserved — disallowed
		// in the question section. 64..191 is structurally illegal because
		// max label length is 63.
		if l > 63 {
			return nil, 0, false
		}
		if p+1+l > len(msg) {
			return nil, 0, false
		}
		p += 1 + l
	}
	if p+4 > len(msg) {
		return nil, 0, false
	}
	return msg[start:p], binary.BigEndian.Uint16(msg[p:]), true
}

// equalNameNoCase compares two raw wire-format QNAMEs case-insensitively
// (ASCII only, matching RFC 1035 conformance). The stored side is already
// lower-cased by add(); we only need to fold the response side.
func equalNameNoCase(stored, fromWire []byte) bool {
	if len(stored) != len(fromWire) {
		return false
	}
	for i, b := range fromWire {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != stored[i] {
			return false
		}
	}
	return true
}

// --- TraditionalDnsConn ---

var _ DnsConn = (*TraditionalDnsConn)(nil)

// TraditionalDnsConn is the per-connection driver for DNS protocols that
// multiplex by qid on a single socket: plain UDP, TCP, and TLS. It hands
// out query slots through ReserveNewQuery and routes replies back to the
// waiting exchange via the pending-query table.
type TraditionalDnsConn struct {
	c           NetConn
	withLenHdr  bool
	idleTimeout time.Duration
	maxCq       int

	pending pendingTable

	closeGuard sync.Once
	closedCh   chan struct{}
	closed     atomic.Bool
	closeErr   error

	// awaitingReply is flipped on after we issue a write and have not yet
	// observed the next inbound frame. It drives a tighter read deadline
	// so a silently-dead peer surfaces quickly instead of hanging for the
	// full idle timeout.
	awaitingReply atomic.Bool
}

// TraditionalDnsConnOpts configures NewDnsConn.
type TraditionalDnsConnOpts struct {
	// WithLengthHeader enables the 2-byte big-endian length prefix that
	// TCP and DoT require before each DNS message. UDP leaves this off.
	WithLengthHeader bool

	// IdleTimeout bounds how long the read loop waits for the next
	// inbound frame. Zero uses idleTimeoutDefault.
	IdleTimeout time.Duration

	// MaxConcurrentQuery caps outstanding queries on this connection.
	// Zero uses tdcMaxConcurrentQueryDefault.
	MaxConcurrentQuery int
}

// NewDnsConn wraps conn and launches the read loop that dispatches
// replies to waiting exchanges. The caller keeps responsibility for
// Close(); conn is closed when the DnsConn is closed.
func NewDnsConn(opt TraditionalDnsConnOpts, conn NetConn) *TraditionalDnsConn {
	dc := &TraditionalDnsConn{
		c:          conn,
		withLenHdr: opt.WithLengthHeader,
		closedCh:   make(chan struct{}),
	}
	setDefaultGZ(&dc.idleTimeout, opt.IdleTimeout, idleTimeoutDefault)
	setDefaultGZ(&dc.maxCq, opt.MaxConcurrentQuery, tdcMaxConcurrentQueryDefault)
	go dc.readLoop()
	return dc
}

// exchange sends q out, waits for the matching reply, and restores the
// caller's original qid on the way out.
func (dc *TraditionalDnsConn) exchange(ctx context.Context, q []byte) (*[]byte, error) {
	select {
	case <-dc.closedCh:
		return nil, ErrTDCClosed
	default:
	}

	qid, respCh := dc.addQueueC(q)
	if respCh == nil {
		return nil, ErrTDCTooManyQueries
	}
	defer dc.deleteQueueC(qid)

	// Write deadlines are intentionally omitted: on stream sockets Write
	// only blocks once the kernel send buffer is full, which rarely
	// correlates with peer liveness. The read side's idle timeout is the
	// actual canary.
	if err := dc.writeQuery(q, qid); err != nil {
		dc.CloseWithErr(fmt.Errorf("write err, %w", err))
		return nil, err
	}

	// If the peer is healthy, *something* should arrive within
	// replyWaitLimit — not necessarily this query's reply. Tighten the
	// read deadline briefly so a silent socket trips fast. Racy with the
	// read-loop deadline refresh, but the worst case is a redundant
	// SetReadDeadline call.
	if dc.awaitingReply.CompareAndSwap(false, true) {
		dc.c.SetReadDeadline(time.Now().Add(replyWaitLimit))
	}

	resend, stopResend := dc.startResendTicker()
	defer stopResend()

	resends := 0
	for {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-dc.closedCh:
			return nil, dc.closeErr
		case resp := <-respCh:
			// Restore the caller's original qid — we only substituted
			// it for multiplexing over the shared socket.
			orig := binary.BigEndian.Uint16(q)
			binary.BigEndian.PutUint16(*resp, orig)
			return resp, nil
		case <-resend:
			if resends >= udpResendMax {
				// Peer hasn't answered after udpResendMax+1 attempts; stop
				// amplifying. Tear the conn down so future queries redial
				// instead of inheriting the suspect socket.
				dc.CloseWithErr(fmt.Errorf("udp resend exhausted (qid=%d)", qid))
				return nil, dc.closeErr
			}
			resends++
			if err := dc.writeQuery(q, qid); err != nil {
				dc.CloseWithErr(fmt.Errorf("write err, %w", err))
				return nil, err
			}
		}
	}
}

// startResendTicker yields a per-second tick on UDP to paper over lost
// datagrams, and a nil channel on framed transports where retransmit is
// the transport's job. The returned stop func is always safe to defer.
func (dc *TraditionalDnsConn) startResendTicker() (<-chan time.Time, func()) {
	if dc.withLenHdr {
		return nil, func() {}
	}
	t := time.NewTicker(time.Second)
	return t.C, t.Stop
}

// writeQuery frames q for the wire and patches in the multiplexed qid.
func (dc *TraditionalDnsConn) writeQuery(q []byte, assignedQid uint16) error {
	var payload *[]byte
	if dc.withLenHdr {
		p, err := copyMsgWithLenHdr(q)
		if err != nil {
			return err
		}
		payload = p
		binary.BigEndian.PutUint16((*payload)[2:], assignedQid)
	} else {
		payload = copyMsg(q)
		binary.BigEndian.PutUint16(*payload, assignedQid)
	}
	_, err := dc.c.Write(*payload)
	pool.ReleaseBuf(payload)
	return err
}

// readResp pulls the next frame off the wire using the protocol's framing.
func (dc *TraditionalDnsConn) readResp() (*[]byte, error) {
	if dc.withLenHdr {
		return dnsutils.ReadRawMsgFromTCP(dc.c)
	}
	return readMsgUdp(dc.c)
}

// readLoop fans inbound frames into the pending-query table. Runs for
// the life of the connection and exits on any read error.
func (dc *TraditionalDnsConn) readLoop() {
	for {
		dc.c.SetReadDeadline(time.Now().Add(dc.idleTimeout))
		frame, err := dc.readResp()
		if err != nil {
			dc.CloseWithErr(fmt.Errorf("read err, %w", err))
			return
		}
		dc.awaitingReply.Store(false)

		// Reject frames that can't even hold a DNS header. readResp's
		// underlying readers already enforce this for normal paths, but
		// keeping the assertion local guards against any future
		// transport that might surface a short read here.
		if len(*frame) < dnsHeaderLen {
			pool.ReleaseBuf(frame)
			continue
		}
		rid := binary.BigEndian.Uint16(*frame)
		entry := dc.pending.lookup(rid)
		if entry.ch == nil {
			// No waiter — caller timed out, or peer echoed a qid we
			// never issued. Drop and move on.
			pool.ReleaseBuf(frame)
			continue
		}
		// Verify the response's question matches the stored question.
		// This defends against qid recycling: if exchange A frees qid X
		// and exchange B reserves the same X for an unrelated query, A's
		// late response would otherwise be delivered as B's reply. With
		// the match check, the stale frame is dropped and B continues
		// waiting for its real reply (or times out cleanly).
		if len(entry.qname) > 0 {
			respQname, respQtype, ok := extractQuestion(*frame)
			if !ok || respQtype != entry.qtype || !equalNameNoCase(entry.qname, respQname) {
				pool.ReleaseBuf(frame)
				continue
			}
		}
		select {
		case entry.ch <- frame:
		default:
			// Waiter's channel is buffered(1); a full channel means the
			// waiter already left (ctx cancel, resend duplicate). Drop.
			pool.ReleaseBuf(frame)
		}
	}
}

// IsClosed reports whether the connection has been torn down.
func (dc *TraditionalDnsConn) IsClosed() bool {
	return dc.closed.Load()
}

// Close tears the connection down with ErrTDCClosed. Idempotent.
func (dc *TraditionalDnsConn) Close() error {
	dc.CloseWithErr(ErrTDCClosed)
	return nil
}

// CloseWithErr tears the connection down, reporting err to every waiting
// exchange via their reply channels. nil err is normalised to
// ErrTDCClosed. Idempotent.
func (dc *TraditionalDnsConn) CloseWithErr(err error) {
	if err == nil {
		err = ErrTDCClosed
	}
	dc.closeGuard.Do(func() {
		dc.closed.Store(true)
		dc.closeErr = err
		close(dc.closedCh)
		dc.c.Close()
	})
}

// --- internal queue accessors retained for the benchmark in conn_test.go
// which operates on a zero-value TraditionalDnsConn. ---

// addQueueC reserves a fresh qid + reply channel for the query bytes q.
// Returns (0, nil) when the pending table is full or q is malformed
// enough that we can't extract its question section. q must NOT include
// any TCP length header — pass the raw DNS message starting at the
// 12-byte DNS header.
func (dc *TraditionalDnsConn) addQueueC(q []byte) (uint16, chan *[]byte) {
	// Pass 0 so only the qid-space bound applies; the caller-facing cap is
	// enforced by ReserveNewQuery. This mirrors the original behaviour
	// where addQueueC only guarded against 65536 simultaneous qids.
	qname, qtype, ok := extractQuestion(q)
	if !ok {
		return 0, nil
	}
	return dc.pending.add(0, qname, qtype)
}

func (dc *TraditionalDnsConn) deleteQueueC(qid uint16) {
	dc.pending.remove(qid)
}

// --- reservation handshake used by ReservedExchanger ---

func (dc *TraditionalDnsConn) ReserveNewQuery() (_ ReservedExchanger, closed bool) {
	if dc.closed.Load() {
		return nil, true
	}
	if !dc.pending.tryReserve(dc.maxCq) {
		return nil, false
	}
	return (*tdcOneTimeExchanger)(dc), false
}

type tdcOneTimeExchanger TraditionalDnsConn

var _ ReservedExchanger = (*tdcOneTimeExchanger)(nil)

func (ote *tdcOneTimeExchanger) ExchangeReserved(ctx context.Context, q []byte) (*[]byte, error) {
	defer ote.WithdrawReserved()
	return (*TraditionalDnsConn)(ote).exchange(ctx, q)
}

func (ote *tdcOneTimeExchanger) WithdrawReserved() {
	(*TraditionalDnsConn)(ote).pending.releaseReserve()
}
