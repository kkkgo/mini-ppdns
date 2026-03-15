package pplog

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	channelSize = 4096
)

// Config holds the pplog reporter configuration.
type Config struct {
	UUID   string // UUID string (with hyphens)
	Server string // UDP server address, e.g. "192.168.1.100:9999"
	Level  int    // Log detail level 1-5
}

// Reporter sends log entries over UDP to a collector.
type Reporter struct {
	uuid  [16]byte
	level int
	conn  net.Conn
	ch    chan []byte // encoded packets ready to send
	seq   atomic.Uint32
	drop  atomic.Uint64
	wg    sync.WaitGroup
	done  chan struct{}
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

	conn, err := net.Dial("udp", cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("pplog: dial %s: %w", cfg.Server, err)
	}

	r := &Reporter{
		uuid:  uuid,
		level: cfg.Level,
		conn:  conn,
		ch:    make(chan []byte, channelSize),
		done:  make(chan struct{}),
	}

	r.wg.Add(1)
	go r.sender()
	return r, nil
}

// Level returns the configured log level.
func (r *Reporter) Level() int {
	return r.level
}

// Report sends a query log entry. Non-blocking: drops if channel is full.
func (r *Reporter) Report(entry *QueryEntry) {
	level := r.level
	if level > 4 {
		level = 4 // Level 5 config means "send everything", but query entries max at level 4
	}

	var buf [MaxPacketSize]byte
	seq := r.seq.Add(1)
	ts := uint32(time.Now().Unix())

	payloadLen := EncodeQueryEntry(buf[HeaderSize:], entry, level, ts)
	EncodeHeader(buf[:], byte(level), seq, r.uuid, uint16(payloadLen))
	total := HeaderSize + payloadLen

	pkt := make([]byte, total)
	copy(pkt, buf[:total])

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

	var buf [MaxPacketSize]byte
	seq := r.seq.Add(1)
	ts := uint32(time.Now().Unix())

	entry := &EventEntry{Severity: severity, Message: msg}
	payloadLen := EncodeEventEntry(buf[HeaderSize:], entry, ts)
	EncodeHeader(buf[:], 5, seq, r.uuid, uint16(payloadLen))
	total := HeaderSize + payloadLen

	pkt := make([]byte, total)
	copy(pkt, buf[:total])

	select {
	case r.ch <- pkt:
	default:
		r.drop.Add(1)
	}
}

// Dropped returns the number of log entries dropped due to full channel.
func (r *Reporter) Dropped() uint64 {
	return r.drop.Load()
}

// Close stops the reporter and waits for pending sends to flush.
func (r *Reporter) Close() {
	close(r.done)
	r.wg.Wait()
	r.conn.Close()
}

// sender is the single goroutine that writes packets to UDP.
func (r *Reporter) sender() {
	defer r.wg.Done()
	for {
		select {
		case pkt := <-r.ch:
			r.conn.Write(pkt)
		case <-r.done:
			// Drain remaining packets
			for {
				select {
				case pkt := <-r.ch:
					r.conn.Write(pkt)
				default:
					return
				}
			}
		}
	}
}
