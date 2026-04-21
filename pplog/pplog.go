package pplog

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	channelSize = 4096
)

// sealBufPool reuses temporary buffers for seal() to avoid per-call heap allocations.
// Each buffer is large enough to hold inner plaintext + AEAD ciphertext.
var sealBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxPacketSize)
		return &b
	},
}

// Config holds the pplog reporter configuration.
type Config struct {
	UUID      string // UUID string (with hyphens)
	Server    string // UDP server address, e.g. "192.168.1.100:9999"
	Level     int    // Log detail level 1-5
	HeartBeat int    // Heartbeat interval in seconds (0 = disabled)
}

// Reporter sends log entries over UDP to a collector.
type Reporter struct {
	uuid         [16]byte
	level        int
	heartBeatSec int
	conn         net.Conn
	cipher       *Cipher
	ch           chan []byte // encoded packets ready to send
	seq          atomic.Uint32
	drop         atomic.Uint64
	writeErr     atomic.Uint64
	lastReport   atomic.Int64 // unix nanos of last Report() call
	wg           sync.WaitGroup
	done         chan struct{}
	closeOnce    sync.Once
	cipherMu     sync.Mutex // protects cipher during session rebuild
}

// NewReporter creates a new Reporter. Returns nil if config is incomplete.
func NewReporter(cfg Config) (*Reporter, error) {
	if cfg.Server == "" || cfg.UUID == "" {
		return nil, fmt.Errorf("pplog: server and uuid are required")
	}
	if cfg.Level < 1 || cfg.Level > 5 {
		return nil, fmt.Errorf("pplog: level must be 1-5, got %d", cfg.Level)
	}

	uuid, err := ParseUUID(cfg.UUID)
	if err != nil {
		return nil, fmt.Errorf("pplog: %w", err)
	}

	cipher, err := NewCipher(uuid)
	if err != nil {
		return nil, fmt.Errorf("pplog: cipher init: %w", err)
	}

	conn, err := net.Dial("udp", cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("pplog: dial %s: %w", cfg.Server, err)
	}

	r := &Reporter{
		uuid:         uuid,
		level:        cfg.Level,
		heartBeatSec: cfg.HeartBeat,
		conn:         conn,
		cipher:       cipher,
		ch:           make(chan []byte, channelSize),
		done:         make(chan struct{}),
	}

	r.wg.Add(1)
	go r.sender()
	if r.heartBeatSec > 0 && r.level >= 2 {
		r.wg.Add(1)
		go r.heartbeat()
	}
	return r, nil
}

// Level returns the configured log level.
func (r *Reporter) Level() int {
	return r.level
}

// nextSeqAndCipher returns the next sequence number together with the cipher it
// must be sealed with. Taking both under the same lock guarantees that a wrap
// cannot interleave a stale seq with a freshly-rebuilt session cipher.
//
// Returns a nil cipher to signal "drop this packet": on seq overflow we must
// rebuild the cipher (new sessionID) before we can reuse seq=1, otherwise the
// nonce = sessionID||seq would repeat and break ChaCha20-Poly1305 AEAD. If
// NewCipher fails (rand.Read failure), keeping seq at 0 forces subsequent
// callers back into this branch and keeps dropping until rand recovers.
func (r *Reporter) nextSeqAndCipher() (uint32, *Cipher) {
	r.cipherMu.Lock()
	defer r.cipherMu.Unlock()
	seq := r.seq.Add(1)
	if seq == 0 {
		newCipher, err := NewCipher(r.uuid)
		if err != nil {
			// Re-arm the wrap: next Add(1) must again return 0 so we retry the
			// rebuild instead of falling through with the stale cipher and a
			// reused (sessionID, seq) nonce — that would break ChaCha20-Poly1305.
			r.seq.Store(^uint32(0))
			return 0, nil
		}
		r.cipher = newCipher
		r.seq.Store(1)
		seq = 1
	}
	return seq, r.cipher
}

// Report sends a query log entry. Non-blocking: drops if channel is full.
func (r *Reporter) Report(entry *QueryEntry) {
	r.lastReport.Store(time.Now().UnixNano())

	level := r.level
	if level > 4 {
		level = 4 // Level 5 config means "send everything", but query entries max at level 4
	}

	seq, cipher := r.nextSeqAndCipher()
	if cipher == nil {
		r.drop.Add(1)
		return
	}
	ts := uint32(time.Now().Unix())

	// Encode payload into temp buffer, with fitPayload for level 3-4
	var payloadBuf [MaxPacketSize]byte
	var payloadLen int
	if level >= 3 {
		payloadLen = fitPayload(payloadBuf[:], entry, level, ts, MaxInnerPayload)
	} else {
		payloadLen = EncodeQueryEntry(payloadBuf[:], entry, level, ts)
	}

	pkt := r.seal(seq, cipher, byte(level), payloadBuf[:payloadLen])

	select {
	case r.ch <- pkt:
	default:
		r.drop.Add(1)
	}
}

// ReportEvent sends a Level 5 event log. Only sends if level >= 2.
func (r *Reporter) ReportEvent(severity byte, msg string) {
	if r.level < 2 {
		return
	}

	seq, cipher := r.nextSeqAndCipher()
	if cipher == nil {
		r.drop.Add(1)
		return
	}
	ts := uint32(time.Now().Unix())

	var payloadBuf [MaxPacketSize]byte
	entry := &EventEntry{Severity: severity, Message: msg}
	payloadLen := EncodeEventEntry(payloadBuf[:], entry, ts)

	pkt := r.seal(seq, cipher, 5, payloadBuf[:payloadLen])

	select {
	case r.ch <- pkt:
	default:
		r.drop.Add(1)
	}
}

// seal constructs an encrypted packet.
// Returns the complete packet ready to send.
// Uses sync.Pool to reuse the inner-plaintext buffer, reducing allocations
// from 3 (inner + Seal internal + pkt) to 1 (pkt only).
// The cipher is passed in so that the caller can pair it with the seq it
// obtained atomically (see nextSeqAndCipher), preventing a wrap from causing
// a stale seq to be sealed with a freshly-rebuilt session cipher.
func (r *Reporter) seal(seq uint32, cipher *Cipher, level byte, payload []byte) []byte {
	nonce := cipher.BuildNonce(seq)

	// Borrow a buffer from pool for inner plaintext
	bufp := sealBufPool.Get().(*[]byte)
	buf := *bufp

	// Build inner plaintext: SeqNum(4) + Level(1) + PayloadLen(2) + Payload
	innerLen := InnerHeaderSize + len(payload)
	inner := buf[:innerLen]
	binary.BigEndian.PutUint32(inner[0:4], seq)
	inner[4] = level
	binary.BigEndian.PutUint16(inner[5:7], uint16(len(payload)))
	copy(inner[7:], payload)

	// Build header (AD for AEAD)
	var header [HeaderSize]byte
	EncodeHeader(header[:], cipher.KeyHint(), nonce)

	// Encrypt: use buf[innerLen:innerLen] as dst to let Seal append in-place,
	// avoiding Seal's internal allocation when dst is nil.
	ciphertext := cipher.SealTo(buf[innerLen:innerLen], nonce, inner, header[:])

	// Assemble final packet: header + ciphertext (includes tag)
	// This allocation is unavoidable since pkt is sent through a channel.
	pkt := make([]byte, HeaderSize+len(ciphertext))
	copy(pkt[:HeaderSize], header[:])
	copy(pkt[HeaderSize:], ciphertext)

	sealBufPool.Put(bufp)
	return pkt
}

// Dropped returns the number of log entries dropped due to full channel.
func (r *Reporter) Dropped() uint64 {
	return r.drop.Load()
}

// WriteErrors returns the number of UDP write errors.
func (r *Reporter) WriteErrors() uint64 {
	return r.writeErr.Load()
}

// Close stops the reporter and waits for pending sends to flush.
// Satisfies io.Closer.
func (r *Reporter) Close() error {
	r.closeOnce.Do(func() {
		close(r.done)
		r.wg.Wait()
		r.conn.Close()
	})
	return nil
}

// heartbeat periodically emits a Level-5 liveness event. If a Report() has
// occurred within the interval, the tick is skipped — any query log already
// proves the process is alive.
func (r *Reporter) heartbeat() {
	defer r.wg.Done()
	interval := time.Duration(r.heartBeatSec) * time.Second
	msg := fmt.Sprintf("[pplog] heart_beat=%d", r.heartBeatSec)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			last := r.lastReport.Load()
			if last > 0 && now.Sub(time.Unix(0, last)) < interval {
				continue
			}
			r.ReportEvent(SeverityInfo, msg)
		case <-r.done:
			return
		}
	}
}

// sender is the single goroutine that writes packets to UDP.
func (r *Reporter) sender() {
	defer r.wg.Done()
	for {
		select {
		case pkt := <-r.ch:
			if _, err := r.conn.Write(pkt); err != nil {
				r.writeErr.Add(1)
			}
		case <-r.done:
			// Drain remaining packets
			for {
				select {
				case pkt := <-r.ch:
					if _, err := r.conn.Write(pkt); err != nil {
						r.writeErr.Add(1)
					}
				default:
					return
				}
			}
		}
	}
}
