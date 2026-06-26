package mlog

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// asyncQueueCap bounds how many formatted log lines may be queued for the
// background writer before new lines are dropped. A stalled sink (slow
// console/pty/pipe whose kernel buffer fills and is not drained) backs up
// here instead of blocking the calling goroutine; once full, lines are
// dropped and counted. 4096 absorbs multi-second sink stalls at realistic
// DNS log rates while capping worst-case memory at a few MiB of pooled
// buffers.
const asyncQueueCap = 4096

// stripAnsi removes ANSI escape sequences from a string.
// Uses a fast path to skip processing when no escape sequences are present.
func stripAnsi(s string) string {
	if !strings.Contains(s, "\x1b") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		// CSI sequences are ESC '[' followed by zero or more parameter
		// bytes (0x30–0x3F) and intermediate bytes (0x20–0x2F), then a
		// final byte in 0x40–0x7E. The previous implementation only
		// handled SGR ('m'); other terminators (K, J, H, ...) leaked
		// through as raw control bytes into log files and the pplog
		// reporter stream.
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) {
				c := s[j]
				if c >= 0x40 && c <= 0x7E {
					break
				}
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

type EventReporter interface {
	ReportEvent(severity byte, msg string)
	Level() int
}

type LogConfig struct {
	Level      string
	File       string
	Production bool
}

// logLevel represents numeric log levels for efficient comparison.
type logLevel int

const (
	levelDebug logLevel = 0
	levelInfo  logLevel = 1
	levelWarn  logLevel = 2
	levelError logLevel = 3
	levelOff   logLevel = 4 // used by Nop()
)

// bufPool reuses []byte buffers for the entire log line (timestamp + prefix + message).
// By writing directly to the output as []byte, we avoid:
//   - string(b) conversion that standard log.Print requires
//   - log.Logger's internal buffer allocation in Output()
//
// This brings allocation behavior closer to zap's zero-allocation design.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 256)
		return &b
	},
}

// reporterBox wraps an EventReporter interface in a pointer so atomic.Pointer
// can hand out a lock-free snapshot (atomic.Pointer can't hold an interface value directly).
type reporterBox struct{ r EventReporter }

type Logger struct {
	level    logLevel
	color    bool
	out      io.Writer
	mu       sync.Mutex // protects out and writeErrReported
	file     *os.File   // non-nil if logging to file; needs Close()
	reporter atomic.Pointer[reporterBox]

	// writeErrReported ensures that when file writes start failing
	// (e.g. disk full), we emit exactly one fallback notice to os.Stderr
	// instead of silently dropping every subsequent log line.
	writeErrReported bool

	// Async write pipeline. Formatted lines are handed to logCh and drained
	// by a single writer goroutine; the actual (potentially blocking) Write
	// happens only on that goroutine. A stalled sink therefore drops log
	// lines (counted in dropped) instead of blocking the caller. This is
	// load-bearing: previously every log call did the Write while holding
	// l.mu, so a wedged sink (e.g. a daemon's inherited terminal/pipe whose
	// buffer fills under -debug) blocked every query handler on l.mu and the
	// resolver stopped answering. logCh/closeNotify are nil for loggers built
	// without the async writer (Nop), where enqueue writes synchronously.
	logCh       chan *[]byte
	closeNotify chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup
	dropped     atomic.Uint64
}

// loadReporter returns the currently attached EventReporter, or nil.
func (l *Logger) loadReporter() EventReporter {
	b := l.reporter.Load()
	if b == nil {
		return nil
	}
	return b.r
}

func NewLogger(lc LogConfig) (*Logger, error) {
	out := os.Stderr
	color := isTerminal(out.Fd())
	var file *os.File
	if lc.File != "" {
		f, err := os.OpenFile(lc.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		out = f
		file = f
		color = false
	}

	lvl := levelInfo
	switch lc.Level {
	case "debug":
		lvl = levelDebug
	case "warn":
		lvl = levelWarn
	case "error":
		lvl = levelError
	}

	lg := &Logger{
		level:       lvl,
		color:       color,
		out:         out,
		file:        file,
		logCh:       make(chan *[]byte, asyncQueueCap),
		closeNotify: make(chan struct{}),
	}
	lg.wg.Add(1)
	go lg.writeLoop()
	return lg, nil
}

// Close stops the background writer (flushing what is already queued, bounded
// so a wedged sink can't hang shutdown) and closes the underlying log file if
// one was opened.
func (l *Logger) Close() error {
	l.closeOnce.Do(func() {
		if l.closeNotify != nil {
			close(l.closeNotify)
		}
	})
	if l.logCh != nil {
		done := make(chan struct{})
		go func() {
			l.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// enqueue hands a fully-formatted line to the background writer. On a healthy
// sink this is a non-blocking channel send; when the queue is full (sink
// backed up) the line is dropped and counted so a stalled sink can never
// block the calling (hot-path) goroutine. A logger with no async writer
// (logCh == nil, e.g. Nop) writes synchronously under l.mu.
func (l *Logger) enqueue(bufp *[]byte) {
	if l.logCh == nil {
		l.writeOut(*bufp)
		bufPool.Put(bufp)
		return
	}
	select {
	case l.logCh <- bufp:
		// Handed off; the writer goroutine returns bufp to the pool.
	default:
		l.dropped.Add(1)
		bufPool.Put(bufp)
	}
}

// writeLoop is the single goroutine that performs the actual sink writes, so
// the Write call (which may block on a stalled sink) never runs on a caller's
// goroutine. It exits after closeNotify fires, draining whatever is already
// queued first.
func (l *Logger) writeLoop() {
	defer l.wg.Done()
	for {
		select {
		case bufp := <-l.logCh:
			l.writeOut(*bufp)
			bufPool.Put(bufp)
			if l.dropped.Load() > 0 {
				l.flushDroppedNotice()
			}
		case <-l.closeNotify:
			for {
				select {
				case bufp := <-l.logCh:
					l.writeOut(*bufp)
					bufPool.Put(bufp)
				default:
					return
				}
			}
		}
	}
}

// flushDroppedNotice emits a single line accounting for log lines dropped
// while the sink was backed up, so operators see that logs were lost rather
// than silently missing them. Runs only on the writer goroutine.
func (l *Logger) flushDroppedNotice() {
	n := l.dropped.Swap(0)
	if n == 0 {
		return
	}
	bufp := bufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = appendTimestamp(buf, time.Now())
	buf = l.appendPrefix(buf, "[WARN] ")
	buf = append(buf, "mlog: dropped "...)
	buf = strconv.AppendUint(buf, n, 10)
	buf = append(buf, " log line(s) under sink backpressure\n"...)
	l.writeOut(buf)
	*bufp = buf
	bufPool.Put(bufp)
}

// writeOut serializes a single buf write through l.mu using defer Unlock.
// Direct Lock + writeLocked + Unlock without defer would deadlock the
// logger forever if l.out.Write ever panicked (custom writer, exhausted
// resource, etc.), since later log calls would all block on l.mu.
func (l *Logger) writeOut(buf []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writeLocked(buf)
}

// writeLocked writes buf to the output while holding l.mu. If writing to a
// file fails (disk full, read-only FS, closed fd), every failing line is
// mirrored to os.Stderr so log content is not lost, while a one-shot notice
// explaining the fallback is printed only once. writeErrReported de-dupes
// the notice (not the mirroring) and resets on the next successful write.
//
// The previous behavior suppressed everything — notice and content — after
// the first failure, so a disk-full event silently dropped every subsequent
// line even though the "falling back to stderr" notice promised otherwise.
func (l *Logger) writeLocked(buf []byte) {
	_, err := l.out.Write(buf)
	if err == nil {
		if l.writeErrReported {
			l.writeErrReported = false
		}
		return
	}
	if l.file != nil {
		if !l.writeErrReported {
			l.writeErrReported = true
			fmt.Fprintf(os.Stderr, "mlog: log file write failed: %v; mirroring subsequent logs to stderr\n", err)
		}
		// Always mirror the failing line so logs survive while the file
		// remains unwritable. If stderr is also broken there is nothing
		// further we can do, so its error is intentionally ignored.
		os.Stderr.Write(buf)
	}
}

// Color returns true if the logger output supports ANSI color codes.
func (l *Logger) Color() bool {
	return l.color
}

// IsTerminal reports whether fd refers to a terminal (TTY/console). Exposed
// so callers (e.g. daemon setup) can decide whether to redirect a process's
// std streams away from an interactive terminal — a backgrounded resolver
// should never write its log stream to the controlling terminal.
func IsTerminal(fd uintptr) bool {
	return isTerminal(fd)
}

func (l *Logger) IsDebug() bool {
	return l.level <= levelDebug
}

// appendTimestamp appends "2006/01/02 15:04:05 " to buf using direct formatting,
// avoiding time.Format's string allocation.
func appendTimestamp(buf []byte, t time.Time) []byte {
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	buf = appendInt(buf, year, 4)
	buf = append(buf, '/')
	buf = appendInt(buf, int(month), 2)
	buf = append(buf, '/')
	buf = appendInt(buf, day, 2)
	buf = append(buf, ' ')
	buf = appendInt(buf, hour, 2)
	buf = append(buf, ':')
	buf = appendInt(buf, min, 2)
	buf = append(buf, ':')
	buf = appendInt(buf, sec, 2)
	buf = append(buf, ' ')
	return buf
}

// appendInt appends an integer with zero-padding to width. Defensively
// folds negatives to 0 — the only call sites pass calendar/clock fields
// that are non-negative by construction, but `val % 10` on a negative
// would emit non-ASCII bytes ('0' + (-3) is below '0'). Cheap to guard
// here so a future caller can't accidentally produce malformed log
// timestamps.
func appendInt(buf []byte, val int, width int) []byte {
	if val < 0 {
		val = 0
	}
	var tmp [4]byte
	pos := len(tmp)
	for i := 0; i < width; i++ {
		pos--
		tmp[pos] = byte('0' + val%10)
		val /= 10
	}
	return append(buf, tmp[pos:]...)
}

// appendPrefix writes a log-level prefix, colorized when the output supports it.
// Keeps the zero-alloc hot path by appending the literal escape sequences.
func (l *Logger) appendPrefix(buf []byte, prefix string) []byte {
	if prefix == "" {
		return buf
	}
	if l.color {
		switch prefix {
		case "[ERROR] ":
			return append(buf, "\x1b[91m[ERROR]\x1b[0m "...)
		case "[WARN] ":
			return append(buf, "\x1b[93m[WARN]\x1b[0m "...)
		}
	}
	return append(buf, prefix...)
}

// output writes a fully-formed log line directly to the writer.
// The entire line is assembled in a pooled []byte buffer — no string conversion,
// no intermediate allocations from log.Logger.Output().
func (l *Logger) output(prefix, msg string) { l.outputSync(prefix, msg, false) }

// outputSync builds a plain (non-field) line and emits it. With sync=false the
// line is handed to the async writer (default hot path); with sync=true it is
// written straight to the sink under l.mu — used by Fatal so the message is
// guaranteed flushed before os.Exit.
func (l *Logger) outputSync(prefix, msg string, sync bool) {
	bufp := bufPool.Get().(*[]byte)
	buf := (*bufp)[:0]

	buf = appendTimestamp(buf, time.Now())
	buf = l.appendPrefix(buf, prefix)
	buf = append(buf, msg...)
	if len(buf) == 0 || buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}

	*bufp = buf
	if sync {
		l.writeOut(buf)
		bufPool.Put(bufp)
	} else {
		l.enqueue(bufp)
	}
}

// needReport returns true if a reporter is attached and active.
func (l *Logger) needReport() bool {
	r := l.loadReporter()
	return r != nil && r.Level() >= 5
}

// outputf formats and writes a log line. When args is empty, format is used as-is
// (no fmt.Appendf call, no interface{} boxing).
// Only extracts the message string when a reporter is attached, avoiding the
// string([]byte) allocation on the hot path.
func (l *Logger) outputf(prefix, format string, args ...interface{}) string {
	bufp := bufPool.Get().(*[]byte)
	buf := (*bufp)[:0]

	buf = appendTimestamp(buf, time.Now())
	buf = l.appendPrefix(buf, prefix)

	// Record where the user message starts for reportEvent
	msgStart := len(buf)

	if len(args) == 0 {
		buf = append(buf, format...)
	} else {
		buf = fmt.Appendf(buf, format, args...)
	}

	// Only pay for string conversion when reporter needs it
	var msg string
	if l.needReport() {
		msg = string(buf[msgStart:])
	}

	if len(buf) == 0 || buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}

	*bufp = buf
	l.enqueue(bufp)
	return msg
}

// InfoBuild writes an info log line whose body is assembled by fn.
// See DebugBuild for semantics. Used by startup logs that want selective
// ANSI colors without paying the key=value encoder cost.
func (l *Logger) InfoBuild(fn func(buf []byte, color bool) []byte) {
	if l.level > levelInfo {
		return
	}
	bufp := bufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = appendTimestamp(buf, time.Now())
	msgStart := len(buf)
	buf = fn(buf, l.color)
	var reportMsg string
	if l.needReport() {
		reportMsg = stripAnsi(string(buf[msgStart:]))
	}
	if len(buf) == 0 || buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	*bufp = buf
	l.enqueue(bufp)
	if reportMsg != "" {
		l.reportEvent(1, reportMsg)
	}
}

// DebugBuild writes a debug log line whose body is assembled by fn.
// fn receives a []byte with the timestamp already appended and must return
// the extended buffer. `color` indicates whether the underlying writer
// supports ANSI colors — callers can inline escape codes when it is true.
// When the logger level is above debug, fn is not invoked at all, preserving
// the zero-cost behavior of filtered-out calls.
func (l *Logger) DebugBuild(fn func(buf []byte, color bool) []byte) {
	if l.level > levelDebug {
		return
	}
	bufp := bufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = appendTimestamp(buf, time.Now())
	buf = fn(buf, l.color)
	if len(buf) == 0 || buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	*bufp = buf
	l.enqueue(bufp)
}

// ErrorBuild writes an error log line whose body is assembled by fn.
// The "[ERROR] " prefix is added automatically and colorized when supported.
// The reporter receives an ANSI-stripped copy of the user message.
func (l *Logger) ErrorBuild(fn func(buf []byte, color bool) []byte) {
	if l.level > levelError {
		return
	}
	bufp := bufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = appendTimestamp(buf, time.Now())
	buf = l.appendPrefix(buf, "[ERROR] ")
	msgStart := len(buf)
	buf = fn(buf, l.color)
	var reportMsg string
	if l.needReport() {
		reportMsg = stripAnsi(string(buf[msgStart:]))
	}
	if len(buf) == 0 || buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	*bufp = buf
	l.enqueue(bufp)
	if reportMsg != "" {
		l.reportEvent(3, "[ERROR] "+reportMsg)
	}
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.level > levelDebug {
		return
	}
	l.outputf("", format, args...)
}

func (l *Logger) SetReporter(r EventReporter) {
	if r == nil {
		l.reporter.Store(nil)
		return
	}
	l.reporter.Store(&reporterBox{r: r})
}

func (l *Logger) reportEvent(severity byte, msg string) {
	r := l.loadReporter()
	if r != nil && r.Level() >= 5 {
		r.ReportEvent(severity, stripAnsi(msg))
	}
}

func (l *Logger) DebugEventf(format string, args ...interface{}) {
	if l.level <= levelDebug {
		msg := l.outputf("", format, args...)
		l.reportEvent(0, msg)
		return
	}
	// Even if debug is filtered, event still needs to be reported
	if l.needReport() {
		var msg string
		if len(args) == 0 {
			msg = format
		} else {
			msg = fmt.Sprintf(format, args...)
		}
		l.reportEvent(0, msg)
	}
}

func (l *Logger) Infof(format string, args ...interface{}) {
	if l.level > levelInfo {
		return
	}
	msg := l.outputf("", format, args...)
	l.reportEvent(1, msg)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	if l.level > levelWarn {
		return
	}
	msg := l.outputf("[WARN] ", format, args...)
	l.reportEvent(2, "[WARN] "+msg)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	if l.level > levelError {
		return
	}
	msg := l.outputf("[ERROR] ", format, args...)
	l.reportEvent(3, "[ERROR] "+msg)
}

func (l *Logger) Debug(msg string) {
	if l.level > levelDebug {
		return
	}
	l.output("", msg)
}

func (l *Logger) Info(msg string) {
	if l.level > levelInfo {
		return
	}
	l.output("", msg)
	l.reportEvent(1, msg)
}

func (l *Logger) Warn(msg string) {
	if l.level > levelWarn {
		return
	}
	l.output("[WARN] ", msg)
	l.reportEvent(2, "[WARN] "+msg)
}

func (l *Logger) Error(msg string) {
	if l.level > levelError {
		return
	}
	l.output("[ERROR] ", msg)
	l.reportEvent(3, "[ERROR] "+msg)
}

// Fatal honors the Nop level guard: a no-op logger must not exit the
// process. In production loggers Fatal still terminates as advertised.
func (l *Logger) Fatal(msg string) {
	if l.level > levelError {
		return
	}
	l.outputSync("[ERROR] ", msg, true)
	l.reportEvent(4, "[FATAL] "+msg)
	os.Exit(1)
}

func Nop() *Logger {
	return &Logger{level: levelOff, color: false, out: io.Discard}
}

// --- Field-based logging (zero-allocation, strongly-typed) ---
//
// These methods (Debugw, Infow, Warnw, Errorw, Fatalw) accept strongly-typed
// Field values instead of format strings. Benefits over printf-style:
//
//   - Zero interface{} boxing: Field is a concrete value type, no heap escape
//   - No fmt reflection: values are encoded via type-switch, not fmt.Sprintf
//   - Deferred evaluation: Stringer.String() is only called if the level check passes
//   - Structured output: key=value pairs, machine-parseable

// outputw writes a structured log line with fields to the writer.
// Returns the message portion for event reporting.
func (l *Logger) outputw(prefix, msg string, fields []Field) string {
	return l.outputwSync(prefix, msg, fields, false)
}

// outputwSync is outputw with an explicit sync flag. sync=true writes straight
// to the sink under l.mu (used by Fatalw so the final line is flushed before
// os.Exit); sync=false hands the line to the async writer.
func (l *Logger) outputwSync(prefix, msg string, fields []Field, sync bool) string {
	bufp := bufPool.Get().(*[]byte)
	buf := (*bufp)[:0]

	buf = appendTimestamp(buf, time.Now())
	buf = l.appendPrefix(buf, prefix)

	msgStart := len(buf)
	buf = append(buf, msg...)

	for i := range fields {
		buf = appendField(buf, fields[i])
	}

	var reportMsg string
	if l.needReport() {
		reportMsg = string(buf[msgStart:])
	}

	buf = append(buf, '\n')

	*bufp = buf
	if sync {
		l.writeOut(buf)
		bufPool.Put(bufp)
	} else {
		l.enqueue(bufp)
	}
	return reportMsg
}

// Debugw logs a debug message with structured fields.
// All field construction (including Stringer.String()) is skipped when debug level is filtered.
func (l *Logger) Debugw(msg string, fields ...Field) {
	if l.level > levelDebug {
		return
	}
	l.outputw("", msg, fields)
}

// DebugEventw logs a debug event with structured fields.
// Even when debug output is filtered, events are still reported to the EventReporter.
func (l *Logger) DebugEventw(msg string, fields ...Field) {
	if l.level <= levelDebug {
		reportMsg := l.outputw("", msg, fields)
		l.reportEvent(0, reportMsg)
		return
	}
	if r := l.loadReporter(); r != nil && r.Level() >= 5 {
		// Build message for reporter only
		bufp := bufPool.Get().(*[]byte)
		buf := (*bufp)[:0]
		buf = append(buf, msg...)
		for i := range fields {
			buf = appendField(buf, fields[i])
		}
		r.ReportEvent(0, string(buf))
		*bufp = buf
		bufPool.Put(bufp)
	}
}

// Infow logs an info message with structured fields.
func (l *Logger) Infow(msg string, fields ...Field) {
	if l.level > levelInfo {
		return
	}
	reportMsg := l.outputw("", msg, fields)
	l.reportEvent(1, reportMsg)
}

// Warnw logs a warning message with structured fields.
func (l *Logger) Warnw(msg string, fields ...Field) {
	if l.level > levelWarn {
		return
	}
	reportMsg := l.outputw("[WARN] ", msg, fields)
	l.reportEvent(2, "[WARN] "+reportMsg)
}

// Errorw logs an error message with structured fields.
func (l *Logger) Errorw(msg string, fields ...Field) {
	if l.level > levelError {
		return
	}
	reportMsg := l.outputw("[ERROR] ", msg, fields)
	l.reportEvent(3, "[ERROR] "+reportMsg)
}

// Fatalw logs a fatal error with structured fields, then exits.
// Honors the Nop level guard like Fatal.
func (l *Logger) Fatalw(msg string, fields ...Field) {
	if l.level > levelError {
		return
	}
	reportMsg := l.outputwSync("[ERROR] ", msg, fields, true)
	l.reportEvent(4, "[FATAL] "+reportMsg)
	os.Exit(1)
}
