package mlog

import (
	"testing"
)

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
