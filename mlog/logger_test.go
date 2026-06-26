package mlog

import (
	"testing"
	"time"
)

// blockingWriter is a sink whose Write blocks until gate is closed,
// simulating a stalled console/pty/pipe whose kernel buffer is full and is
// not being drained.
type blockingWriter struct{ gate chan struct{} }

func (w *blockingWriter) Write(p []byte) (int, error) {
	<-w.gate
	return len(p), nil
}

// TestLoggerAsyncDoesNotBlockOnStalledSink pins the wedge fix: when the log
// sink blocks on Write, the logging hot path must NOT block. Before the async
// writer, every log call did the Write while holding l.mu, so a stalled sink
// (a daemon's inherited terminal/pipe filling up under -debug) blocked every
// query handler on l.mu, the UDP server's concurrency slots filled, and the
// resolver stopped answering ("drop 4096"). With the async writer, a stalled
// sink drops log lines instead of blocking callers.
func TestLoggerAsyncDoesNotBlockOnStalledSink(t *testing.T) {
	bw := &blockingWriter{gate: make(chan struct{})}
	l := &Logger{
		level:       levelDebug,
		out:         bw,
		logCh:       make(chan *[]byte, 8),
		closeNotify: make(chan struct{}),
	}
	l.wg.Add(1)
	go l.writeLoop()

	// The writer goroutine blocks forever in bw.Write on the first line; the
	// 8-slot queue then fills. Every subsequent call must still return
	// promptly (drop, not block).
	const n = 2000
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			l.Debugw("hot-path line", Int("i", i))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("logging blocked while the sink was stalled — the resolver would wedge")
	}
	if l.dropped.Load() == 0 {
		t.Fatal("expected dropped lines under a stalled sink, got 0")
	}

	// Release the sink and shut the writer down cleanly (no goroutine leak).
	close(bw.gate)
	_ = l.Close()
}

func TestLogger(t *testing.T) {
	l, err := NewLogger(LogConfig{Level: "debug"})
	if err != nil {
		t.Fatal(err)
	}

	l.Debugf("test debug %s", "arg")
	l.Infof("test info %d", 123)
	l.Warnf("test warn")
	l.Errorf("test error")
}

func TestLoggerColor(t *testing.T) {
	// Default stderr logger should detect terminal (may or may not be color in CI)
	l, err := NewLogger(LogConfig{Level: "debug"})
	if err != nil {
		t.Fatal(err)
	}
	// Just verify Color() doesn't panic and returns a boolean
	_ = l.Color()

	// File logger should always have color=false
	tmpFile := t.TempDir() + "/test.log"
	fl, err := NewLogger(LogConfig{Level: "info", File: tmpFile})
	if err != nil {
		t.Fatal(err)
	}
	if fl.Color() {
		t.Error("file logger should have color=false")
	}

	// Nop logger should have color=false
	nop := Nop()
	if nop.Color() {
		t.Error("nop logger should have color=false")
	}
}

// TestNopLoggerErrorAndFatalAreNoOp guards the Nop() level guard added
// to Error/Errorf/Errorw/Fatal/Fatalw/ErrorBuild. Before the guard,
// Fatal on a Nop logger called os.Exit(1), making "no-op" loggers
// production-unsafe in tests that exercise an error path. The Error
// variants would also touch io.Discard via the timestamp/format builders
// — wasted CPU but no observable side effects. This test exercises the
// non-Fatal entry points and verifies they return cleanly without
// triggering output (the level guard short-circuits before any work).
func TestNopLoggerErrorPathsAreNoOp(t *testing.T) {
	nop := Nop()
	// Each of these would have written through to io.Discard previously;
	// now they short-circuit at level. We can't directly observe the
	// "no work" property here — the test exists so that any future
	// regression that drops the guard will fail loudly when paired with
	// a Fatal-on-Nop expectation in downstream tests.
	nop.Error("ignored")
	nop.Errorf("ignored %d", 1)
	nop.Errorw("ignored", String("k", "v"))
	nop.ErrorBuild(func(buf []byte, color bool) []byte {
		// If the level guard regressed, this fn would actually run and
		// the test would still pass — so additionally verify level state.
		return append(buf, "should-not-run"...)
	})
	if nop.level != levelOff {
		t.Fatalf("Nop().level = %v, want levelOff", nop.level)
	}
}

func BenchmarkLogger(b *testing.B) {
	l, _ := NewLogger(LogConfig{Level: "info"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Infof("benchmark test key=value num=%d", 100)
	}
}

func BenchmarkLoggerAlloc(b *testing.B) {
	// Write to /dev/null to isolate allocation from I/O
	l, _ := NewLogger(LogConfig{Level: "info", File: "/dev/null"})
	defer l.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Infof("benchmark test key=value num=%d str=%s", 100, "hello")
	}
}

func BenchmarkLoggerNoArgs(b *testing.B) {
	l, _ := NewLogger(LogConfig{Level: "info", File: "/dev/null"})
	defer l.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Infof("benchmark test key=value no formatting")
	}
}

func BenchmarkLoggerFiltered(b *testing.B) {
	// Debug messages filtered by info-level logger — should be near-zero cost
	l, _ := NewLogger(LogConfig{Level: "info", File: "/dev/null"})
	defer l.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Debugf("this should be skipped num=%d", 100)
	}
}

// BenchmarkLoggerDNSQuery simulates a real DNS query log line with many dynamic args.
// This tests the worst case for interface{} boxing: 7 args of mixed types.
func BenchmarkLoggerDNSQuery(b *testing.B) {
	l, _ := NewLogger(LogConfig{Level: "debug", File: "/dev/null"})
	defer l.Close()
	domain := "example.com."
	upstream := "udp://8.8.8.8:53"
	clientIP := "192.168.1.100"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Debugf("%s use %s query %s %s %s %dms",
			clientIP, upstream, "A", domain, "NOERROR", 12)
	}
}

// BenchmarkLoggerDNSQueryFiltered tests the same log line but filtered out.
// Validates that interface{} boxing cost is avoided when level filters the message.
func BenchmarkLoggerDNSQueryFiltered(b *testing.B) {
	l, _ := NewLogger(LogConfig{Level: "info", File: "/dev/null"})
	defer l.Close()
	domain := "example.com."
	upstream := "udp://8.8.8.8:53"
	clientIP := "192.168.1.100"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Debugf("%s use %s query %s %s %s %dms",
			clientIP, upstream, "A", domain, "NOERROR", 12)
	}
}

// BenchmarkLoggerManyInts tests boxing of multiple integer args.
func BenchmarkLoggerManyInts(b *testing.B) {
	l, _ := NewLogger(LogConfig{Level: "info", File: "/dev/null"})
	defer l.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Infof("stats qps=%d cache=%d drop=%d err=%d lat=%d", 1500, 8192, 3, 0, 12)
	}
}

// BenchmarkLoggerDynamicStrings tests with dynamically constructed string args,
// simulating real handler.go patterns like colorize(c, code, text) + .String() calls.
func BenchmarkLoggerDynamicStrings(b *testing.B) {
	l, _ := NewLogger(LogConfig{Level: "debug", File: "/dev/null"})
	defer l.Close()
	// Simulate colorize() and .String() — dynamically allocated strings
	clientIP := "192.168.1.100"
	domain := "example.com."
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		up := "\x1b[33m" + "udp://8.8.8.8:53" + "\x1b[0m" // simulates colorize
		cip := "\x1b[36m" + clientIP + "\x1b[0m"
		dom := "\x1b[36m" + domain + "\x1b[0m"
		l.Debugf("%s use %s query %s %s %s %dms", cip, up, "A", dom, "NOERROR", 12)
	}
}

// BenchmarkLoggerDynamicStringsFiltered same but filtered — validates zero cost.
func BenchmarkLoggerDynamicStringsFiltered(b *testing.B) {
	l, _ := NewLogger(LogConfig{Level: "info", File: "/dev/null"})
	defer l.Close()
	clientIP := "192.168.1.100"
	domain := "example.com."
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		up := "\x1b[33m" + "udp://8.8.8.8:53" + "\x1b[0m"
		cip := "\x1b[36m" + clientIP + "\x1b[0m"
		dom := "\x1b[36m" + domain + "\x1b[0m"
		l.Debugf("%s use %s query %s %s %s %dms", cip, up, "A", dom, "NOERROR", 12)
	}
}
