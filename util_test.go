package main

import (
	"testing"
)

func TestCalculateCacheSize(t *testing.T) {
	tests := []struct {
		name     string
		availMem uint64
		wantSize int
	}{
		{"zero (fallback)", 0, maxCacheSize},
		{"large mem 4GB", 4 * 1024 * 1024 * 1024, maxCacheSize},
		{"256MB", 256 * 1024 * 1024, 26214}, // 268435456 / 5 / 2048
		{"32MB", 32 * 1024 * 1024, 3276},    // 33554432 / 5 / 2048
		{"very small 1MB", 1 * 1024 * 1024, minCacheSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateCacheSize(tt.availMem)
			if got != tt.wantSize {
				t.Errorf("calculateCacheSize(%d) = %d, want %d", tt.availMem, got, tt.wantSize)
			}
		})
	}
}
