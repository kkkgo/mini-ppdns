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

func BenchmarkLogger(b *testing.B) {
	l, _ := NewLogger(LogConfig{Level: "info"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Infof("benchmark test key=value num=%d", 100)
	}
}
