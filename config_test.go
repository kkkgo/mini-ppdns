package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/kkkgo/mini-ppdns/mlog"
)

func TestParseINI_Hook(t *testing.T) {
	content := `[hook]
exec="wget --spider -q -S http://www.google.com/generate_204"
exit_code=0
keyword="204"
sleep_time=30
retry_time=3
count=5
switch_fall_exec="echo dns down"
switch_main_exec="echo dns up"
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(path, []byte(content), 0644)

	var args ConfigArgs
	err := parseINI(path, &args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if args.Hook == nil {
		t.Fatal("expected Hook to be parsed")
	}
	if args.Hook.Exec != "wget --spider -q -S http://www.google.com/generate_204" {
		t.Errorf("unexpected exec: %q", args.Hook.Exec)
	}
	if !args.Hook.ExitCodeSet || args.Hook.ExitCode != 0 {
		t.Errorf("expected exit_code=0, got %d (set=%v)", args.Hook.ExitCode, args.Hook.ExitCodeSet)
	}
	if args.Hook.Keyword != "204" {
		t.Errorf("unexpected keyword: %q", args.Hook.Keyword)
	}
	if args.Hook.SleepTime != 30 {
		t.Errorf("expected sleep_time=30, got %d", args.Hook.SleepTime)
	}
	if args.Hook.RetryTime != 3 {
		t.Errorf("expected retry_time=3, got %d", args.Hook.RetryTime)
	}
	if args.Hook.Count != 5 {
		t.Errorf("expected count=5, got %d", args.Hook.Count)
	}
	if args.Hook.SwitchFallExec != "echo dns down" {
		t.Errorf("unexpected switch_fall_exec: %q", args.Hook.SwitchFallExec)
	}
	if args.Hook.SwitchMainExec != "echo dns up" {
		t.Errorf("unexpected switch_main_exec: %q", args.Hook.SwitchMainExec)
	}
}

func TestParseINI_HookDefaults(t *testing.T) {
	content := `[hook]
exec=ping -c1 8.8.8.8
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(path, []byte(content), 0644)

	var args ConfigArgs
	err := parseINI(path, &args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if args.Hook == nil {
		t.Fatal("expected Hook to be parsed")
	}
	if args.Hook.SleepTime != 60 {
		t.Errorf("expected default sleep_time=60, got %d", args.Hook.SleepTime)
	}
	if args.Hook.RetryTime != 5 {
		t.Errorf("expected default retry_time=5, got %d", args.Hook.RetryTime)
	}
	if args.Hook.Count != 10 {
		t.Errorf("expected default count=10, got %d", args.Hook.Count)
	}
	if args.Hook.ExitCodeSet {
		t.Error("exit_code should not be set when not configured")
	}
	if args.Hook.Keyword != "" {
		t.Error("keyword should be empty when not configured")
	}
}

// TestParseINI_TrustRcode: verify trust_rcode is parsed from INI file.
func TestParseINI_TrustRcode(t *testing.T) {
	content := `[adv]
trust_rcode=0,3
`
	tmpDir := t.TempDir()
	iniPath := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(iniPath, []byte(content), 0644)

	args := &ConfigArgs{}
	err := parseINI(iniPath, args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if len(args.TrustRcode) != 2 {
		t.Fatalf("expected 2 trust_rcode values, got %d", len(args.TrustRcode))
	}
	if args.TrustRcode[0] != 0 || args.TrustRcode[1] != 3 {
		t.Fatalf("expected [0,3], got %v", args.TrustRcode)
	}
}

// TestParseINI_TrustRcode_Empty: verify trust_rcode defaults to empty.
func TestParseINI_TrustRcode_Empty(t *testing.T) {
	content := `[adv]
qtime=250
`
	tmpDir := t.TempDir()
	iniPath := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(iniPath, []byte(content), 0644)

	args := &ConfigArgs{}
	err := parseINI(iniPath, args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if len(args.TrustRcode) != 0 {
		t.Fatalf("expected empty trust_rcode, got %v", args.TrustRcode)
	}
}

// TestParseINI_BogusPrivAndLeaseFile tests INI parsing for new PTR options.
func TestParseINI_BogusPrivAndLeaseFile(t *testing.T) {
	content := `[adv]
boguspriv=1
lease_file=/tmp/dhcp.leases,/tmp/dnsmasq.leases
hosts_file=/etc/hosts
`
	tmpDir := t.TempDir()
	iniPath := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(iniPath, []byte(content), 0644)

	args := &ConfigArgs{}
	err := parseINI(iniPath, args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if !args.BogusPriv {
		t.Fatal("expected BogusPriv=true")
	}
	if len(args.LeaseFile) != 2 {
		t.Fatalf("expected 2 lease files, got %d: %v", len(args.LeaseFile), args.LeaseFile)
	}
	if args.LeaseFile[0] != "/tmp/dhcp.leases" || args.LeaseFile[1] != "/tmp/dnsmasq.leases" {
		t.Fatalf("unexpected lease files: %v", args.LeaseFile)
	}
	if len(args.HostsFile) != 1 || args.HostsFile[0] != "/etc/hosts" {
		t.Fatalf("unexpected hosts files: %v", args.HostsFile)
	}
}

// TestParseINI_BogusPrivDisabled tests INI parsing with boguspriv=0.
func TestParseINI_BogusPrivDisabled(t *testing.T) {
	content := `[adv]
boguspriv=0
`
	tmpDir := t.TempDir()
	iniPath := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(iniPath, []byte(content), 0644)

	args := &ConfigArgs{}
	err := parseINI(iniPath, args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if args.BogusPriv {
		t.Fatal("expected BogusPriv=false when boguspriv=0")
	}
	if !args.BogusPrivSet {
		t.Fatal("expected BogusPrivSet=true when boguspriv is explicitly set to 0")
	}
}

// TestParseINI_BogusPrivNotSet tests that BogusPrivSet is false when boguspriv
// is not mentioned in the config file, so the caller can apply the default.
func TestParseINI_BogusPrivNotSet(t *testing.T) {
	content := `[adv]
qtime=300
`
	tmpDir := t.TempDir()
	iniPath := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(iniPath, []byte(content), 0644)

	args := &ConfigArgs{}
	err := parseINI(iniPath, args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if args.BogusPrivSet {
		t.Fatal("expected BogusPrivSet=false when boguspriv is not in config")
	}
	if args.BogusPriv {
		t.Fatal("expected BogusPriv=false (zero value) when not set in config")
	}
}

// TestParseINI_BogusPrivSetFlag tests that BogusPrivSet is true for all valid values.
func TestParseINI_BogusPrivSetFlag(t *testing.T) {
	tests := []struct {
		value    string
		wantPriv bool
	}{
		{"1", true},
		{"yes", true},
		{"true", true},
		{"0", false},
		{"no", false},
		{"false", false},
	}
	for _, tt := range tests {
		t.Run("boguspriv="+tt.value, func(t *testing.T) {
			content := "[adv]\nboguspriv=" + tt.value + "\n"
			tmpDir := t.TempDir()
			iniPath := filepath.Join(tmpDir, "test.ini")
			os.WriteFile(iniPath, []byte(content), 0644)

			args := &ConfigArgs{}
			err := parseINI(iniPath, args, mlog.Nop())
			if err != nil {
				t.Fatalf("parseINI error: %v", err)
			}
			if !args.BogusPrivSet {
				t.Fatal("expected BogusPrivSet=true")
			}
			if args.BogusPriv != tt.wantPriv {
				t.Fatalf("expected BogusPriv=%v, got %v", tt.wantPriv, args.BogusPriv)
			}
		})
	}
}

// TestParseINI_Hosts tests [hosts] section parsing.
func TestParseINI_Hosts(t *testing.T) {
	content := `[hosts]
# hosts entry
1.2.3.4 example.com
10.10.10.53 paopao.dns
2001:db8::1 v6.example.com
192.168.1.1 multi1.test multi2.test
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(path, []byte(content), 0644)

	var args ConfigArgs
	err := parseINI(path, &args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if args.Hosts == nil {
		t.Fatal("expected Hosts to be parsed")
	}

	// example.com -> 1.2.3.4
	ips := args.Hosts["example.com."]
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("unexpected example.com IPs: %v", ips)
	}

	// paopao.dns -> 10.10.10.53
	ips = args.Hosts["paopao.dns."]
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.10.10.53")) {
		t.Errorf("unexpected paopao.dns IPs: %v", ips)
	}

	// v6.example.com -> 2001:db8::1
	ips = args.Hosts["v6.example.com."]
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("unexpected v6.example.com IPs: %v", ips)
	}

	// multi1.test and multi2.test -> 192.168.1.1
	for _, domain := range []string{"multi1.test.", "multi2.test."} {
		ips = args.Hosts[domain]
		if len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.168.1.1")) {
			t.Errorf("unexpected %s IPs: %v", domain, ips)
		}
	}
}

// TestParseINI_HostsEmpty tests that empty [hosts] section is handled.
func TestParseINI_HostsEmpty(t *testing.T) {
	content := `[hosts]
# only comments
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(path, []byte(content), 0644)

	var args ConfigArgs
	err := parseINI(path, &args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if len(args.Hosts) != 0 {
		t.Fatalf("expected empty Hosts, got %v", args.Hosts)
	}
}

// TestParseINI_HostsInvalidIP tests that invalid IPs are skipped.
func TestParseINI_HostsInvalidIP(t *testing.T) {
	content := `[hosts]
notanip example.com
1.2.3.4 valid.com
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(path, []byte(content), 0644)

	var args ConfigArgs
	err := parseINI(path, &args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if len(args.Hosts) != 1 {
		t.Fatalf("expected 1 host entry, got %d", len(args.Hosts))
	}
	if _, ok := args.Hosts["valid.com."]; !ok {
		t.Fatal("expected valid.com entry")
	}
}

// TestParseINI_HostsMultipleIPs tests multiple IPs for the same domain.
func TestParseINI_HostsMultipleIPs(t *testing.T) {
	content := `[hosts]
1.2.3.4 example.com
5.6.7.8 example.com
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.ini")
	os.WriteFile(path, []byte(content), 0644)

	var args ConfigArgs
	err := parseINI(path, &args, mlog.Nop())
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	ips := args.Hosts["example.com."]
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs for example.com, got %d", len(ips))
	}
	if !ips[0].Equal(net.ParseIP("1.2.3.4")) || !ips[1].Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("unexpected IPs: %v", ips)
	}
}
