package upstream

import "testing"

func TestParseDialAddr(t *testing.T) {
	tests := []struct {
		name        string
		urlHost     string
		dialAddr    string
		defaultPort uint16
		wantHost    string
		wantPort    uint16
		wantErr     bool
	}{
		{"host_only", "1.1.1.1", "", 53, "1.1.1.1", 53, false},
		{"host_with_port", "1.1.1.1:5353", "", 53, "1.1.1.1", 5353, false},
		{"dialAddr_override", "1.1.1.1", "8.8.8.8:853", 53, "8.8.8.8", 853, false},
		{"dialAddr_no_port", "1.1.1.1", "8.8.8.8", 53, "8.8.8.8", 53, false},
		{"ipv6", "::1", "", 53, "::1", 53, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseDialAddr(tt.urlHost, tt.dialAddr, tt.defaultPort)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestJoinPort(t *testing.T) {
	tests := []struct {
		host string
		port uint16
		want string
	}{
		{"1.1.1.1", 53, "1.1.1.1:53"},
		{"::1", 853, "[::1]:853"},
	}
	for _, tt := range tests {
		got := joinPort(tt.host, tt.port)
		if got != tt.want {
			t.Errorf("joinPort(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
		}
	}
}

func TestTryRemovePort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.1.1.1:53", "1.1.1.1"},
		{"1.1.1.1", "1.1.1.1"},
		{"[::1]:53", "::1"},
	}
	for _, tt := range tests {
		got := tryRemovePort(tt.input)
		if got != tt.want {
			t.Errorf("tryRemovePort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTrySplitHostPort(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"1.1.1.1:53", "1.1.1.1", 53, false},
		{"1.1.1.1", "1.1.1.1", 0, false},
		{"[::1]:853", "::1", 853, false},
		{"::1", "::1", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port, err := trySplitHostPort(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestTryTrimIpv6Brackets(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"[::1]", "::1"},
		{"::1", "::1"},
		{"1.1.1.1", "1.1.1.1"},
		{"a", "a"},
		{"", ""},
	}
	for _, tt := range tests {
		got := tryTrimIpv6Brackets(tt.input)
		if got != tt.want {
			t.Errorf("tryTrimIpv6Brackets(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMsgTruncated(t *testing.T) {
	// DNS header: byte 2, bit 1 is TC flag
	t.Run("truncated", func(t *testing.T) {
		b := make([]byte, 12)
		b[2] = 0x02 // TC bit set
		if !msgTruncated(b) {
			t.Fatal("should be truncated")
		}
	})

	t.Run("not_truncated", func(t *testing.T) {
		b := make([]byte, 12)
		b[2] = 0x00
		if msgTruncated(b) {
			t.Fatal("should not be truncated")
		}
	})

	t.Run("other_flags_set", func(t *testing.T) {
		b := make([]byte, 12)
		b[2] = 0x84 // QR=1, AA=1, TC=0
		if msgTruncated(b) {
			t.Fatal("should not be truncated")
		}
	})

	t.Run("all_flags_set", func(t *testing.T) {
		b := make([]byte, 12)
		b[2] = 0xFF // all bits set including TC
		if !msgTruncated(b) {
			t.Fatal("should be truncated")
		}
	})
}
