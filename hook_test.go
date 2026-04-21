package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
	"github.com/kkkgo/mini-ppdns/pkg/query_context"
	"github.com/kkkgo/mini-ppdns/pkg/upstream"
)

func TestHookMonitorCheck(t *testing.T) {
	ctx := context.Background()

	t.Run("exit code match", func(t *testing.T) {
		hm := &hookMonitor{
			cfg: &HookConfig{
				Exec:        "exit 0",
				ExitCode:    0,
				ExitCodeSet: true,
			},
		}
		if hm.check(ctx) != nil {
			t.Error("expected check to pass with exit code 0")
		}
	})

	t.Run("exit code mismatch", func(t *testing.T) {
		hm := &hookMonitor{
			cfg: &HookConfig{
				Exec:        "exit 1",
				ExitCode:    0,
				ExitCodeSet: true,
			},
		}
		if hm.check(ctx) == nil {
			t.Error("expected check to fail with exit code 1")
		}
	})

	t.Run("keyword match", func(t *testing.T) {
		hm := &hookMonitor{
			cfg: &HookConfig{
				Exec:    "echo hello world",
				Keyword: "world",
			},
		}
		if hm.check(ctx) != nil {
			t.Error("expected check to pass with keyword match")
		}
	})

	t.Run("keyword mismatch", func(t *testing.T) {
		hm := &hookMonitor{
			cfg: &HookConfig{
				Exec:    "echo hello",
				Keyword: "world",
			},
		}
		if hm.check(ctx) == nil {
			t.Error("expected check to fail with keyword mismatch")
		}
	})

	t.Run("both exit code and keyword", func(t *testing.T) {
		hm := &hookMonitor{
			cfg: &HookConfig{
				Exec:        "echo 204; exit 0",
				ExitCode:    0,
				ExitCodeSet: true,
				Keyword:     "204",
			},
		}
		if hm.check(ctx) != nil {
			t.Error("expected check to pass with both conditions met")
		}
	})

	t.Run("exit code ok but keyword miss", func(t *testing.T) {
		hm := &hookMonitor{
			cfg: &HookConfig{
				Exec:        "echo hello; exit 0",
				ExitCode:    0,
				ExitCodeSet: true,
				Keyword:     "204",
			},
		}
		if hm.check(ctx) == nil {
			t.Error("expected check to fail when keyword missing")
		}
	})

	t.Run("no conditions defaults to exit code 0", func(t *testing.T) {
		hm := &hookMonitor{
			cfg: &HookConfig{
				Exec: "exit 0",
			},
		}
		if hm.check(ctx) != nil {
			t.Error("expected check to pass with default behavior (exit 0)")
		}

		hm2 := &hookMonitor{
			cfg: &HookConfig{
				Exec: "exit 1",
			},
		}
		if hm2.check(ctx) == nil {
			t.Error("expected check to fail with default behavior (exit 1)")
		}
	})

	t.Run("command not found", func(t *testing.T) {
		hm := &hookMonitor{
			cfg: &HookConfig{
				Exec: "/nonexistent_binary_xyz",
			},
		}
		if hm.check(ctx) == nil {
			t.Error("expected check to fail for nonexistent command")
		}
	})
}

func TestHookMonitorRun(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	failed := &atomic.Bool{}

	// Use a command that always fails (exit 1)
	cfg := &HookConfig{
		Exec:      "exit 1",
		Count:     3,
		SleepTime: 1,
		RetryTime: 1,
	}

	hm := &hookMonitor{
		cfg:    cfg,
		failed: failed,
		logger: logger,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hm.run(ctx)

	// Wait for 3 failures (3 * 1s retry + some margin)
	time.Sleep(4 * time.Second)
	if !failed.Load() {
		t.Error("expected hookFailed to be true after count failures")
	}

	cancel()
}

func TestHookMonitorRecovery(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	failed := &atomic.Bool{}

	// Use a temp file as a flag: if it exists, the check fails; if removed, it succeeds
	tmpDir := t.TempDir()
	flagFile := filepath.Join(tmpDir, "fail_flag")
	os.WriteFile(flagFile, []byte(""), 0644)

	cfg := &HookConfig{
		Exec:      fmt.Sprintf("test ! -f %s", flagFile),
		Count:     2,
		SleepTime: 1,
		RetryTime: 1,
	}

	hm := &hookMonitor{
		cfg:    cfg,
		failed: failed,
		logger: logger,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hm.run(ctx)

	// Wait for failure detection (2 failures * 1s + margin)
	time.Sleep(3 * time.Second)
	if !failed.Load() {
		t.Fatal("expected hookFailed to be true")
	}

	// Remove the flag file to trigger recovery
	os.Remove(flagFile)

	// Wait for recovery (1s retry + margin)
	time.Sleep(3 * time.Second)
	if failed.Load() {
		t.Error("expected hookFailed to be false after recovery")
	}

	cancel()
}

func TestHookMonitorCacheFlushAndDelay(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	failed := &atomic.Bool{}
	dnsCache := cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10})

	// Add a dummy entry to cache
	dummyMsg := new(dns.Msg)
	dnsCache.Store(CacheKey{Name: "dummy.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, dummyMsg, time.Now().Add(1*time.Hour))

	// We use a temporary file to detect if switch_fall_exec ran
	tmpDir := t.TempDir()
	execFile := filepath.Join(tmpDir, "executed")

	cfg := &HookConfig{
		Exec:           "exit 1", // always fail
		Count:          1,
		SleepTime:      1,
		RetryTime:      1, // the delay for switch_fall_exec
		SwitchFallExec: fmt.Sprintf("touch %s", execFile),
	}

	hm := &hookMonitor{
		cfg:      cfg,
		failed:   failed,
		logger:   logger,
		dnsCache: dnsCache,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hm.run(ctx)

	// Wait 200ms: failure should be detected and cache flushed, but exec not yet run (needs 0.5s)
	time.Sleep(200 * time.Millisecond)
	if !failed.Load() {
		t.Fatal("expected hookFailed to be true")
	}
	if dnsCache.Len() != 0 {
		t.Errorf("expected cache to be flushed, got %d items", dnsCache.Len())
	}
	if _, err := os.Stat(execFile); !os.IsNotExist(err) {
		t.Errorf("expected SwitchFallExec not to run yet, but file exists")
	}

	// Wait more time to allow the switch_fall_exec to run (total > 0.5s)
	time.Sleep(600 * time.Millisecond)
	if _, err := os.Stat(execFile); os.IsNotExist(err) {
		t.Errorf("expected SwitchFallExec to run after retryTime/2, file does not exist")
	}

	cancel()
}

// TestProcessWithHookFailed verifies that when hookFailed is true,
// all queries bypass local DNS and go directly to fallback.
func TestProcessWithHookFailed(t *testing.T) {
	// Fallback server returns 2.2.2.2
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 2.2.2.2")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	hookState := &atomic.Bool{}
	hookState.Store(true) // simulate hook detecting main DNS is down

	handler := &miniHandler{
		logger:       logger,
		localForward: nil, // nil to ensure local is never called (would panic)
		cnForward:    fallbackFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		hookFailed:   hookState,
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected fallback answer")
	}
	if r.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Fatalf("expected 2.2.2.2 from fallback, got %v", r.Answer[0])
	}
}

// TestProcessHookNotFailed verifies that when hookFailed is false,
// queries go through normal local DNS path.
func TestProcessHookNotFailed(t *testing.T) {
	// Local server returns 1.1.1.1
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 1.1.1.1")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	// Fallback server returns 2.2.2.2
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 2.2.2.2")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	hookState := &atomic.Bool{}
	hookState.Store(false) // hook is healthy

	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    fallbackFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		hookFailed:   hookState,
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected local answer")
	}
	if r.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("expected 1.1.1.1 from local, got %v", r.Answer[0])
	}
}
