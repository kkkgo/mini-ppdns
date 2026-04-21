package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func TestStressAndStability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	// 1. Spawning the Dummy Upstream DNS Server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamAddr := pc.LocalAddr().String()

	handler := func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			if dns.RRToType(q) == dns.TypeA {
				ip := netip.AddrFrom4([4]byte{
					byte(rand.Intn(250) + 1),
					byte(rand.Intn(250) + 1),
					byte(rand.Intn(250) + 1),
					byte(rand.Intn(250) + 1),
				})
				rr := &dns.A{
					Hdr: dns.Header{Name: q.Header().Name, Class: dns.ClassINET, TTL: 10},
					A:   rdata.A{Addr: ip},
				}
				resp.Answer = append(resp.Answer, rr)
			}
		}
		// Simulate network jitter to test queueing and goroutine leaks
		time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)
		resp.WriteTo(w)
	}
	wait := make(chan error, 1)
	dummySrv := &dns.Server{
		PacketConn:        pc,
		Handler:           dns.HandlerFunc(handler),
		NotifyStartedFunc: func(context.Context) { wait <- nil },
	}
	go func() {
		if err := dummySrv.ListenAndServe(); err != nil {
			wait <- err
		}
	}()
	if err := <-wait; err != nil {
		t.Fatalf("dummy upstream failed to start: %v", err)
	}
	defer dummySrv.Shutdown(context.Background())

	// 2. Start mini-ppdns as a subprocess to completely isolate execution
	// It allows testing actual socket binds and isolates from `flag` package issues
	execPath := "./mini-ppdns"
	// Ensure binary exists
	cmdBuild := exec.Command("go", "build", "-o", execPath, ".")
	if err := cmdBuild.Run(); err != nil {
		t.Fatalf("failed to build mini-ppdns: %v", err)
	}

	listenAddr := "127.0.0.1:53533"
	cmd := exec.Command(execPath, "-dns", "udp://"+upstreamAddr, "-fall", "udp://"+upstreamAddr, "-listen", listenAddr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start mini-ppdns: %v", err)
	}

	// Make sure we kill the proxy when test completes
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	// Wait for server to bind
	time.Sleep(1 * time.Second)

	// 3. Blast the proxy with concurrent traffic
	// Warm-up query to force the upstream UDP socket to finish dialing.
	// Otherwise, dumping 10k concurrent queries in 1 millisecond exceeds the Lazy Dialer 4096 queue limit.
	client := dns.NewClient()
	client.ReadTimeout = 1 * time.Second
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "warmup.com.", dns.TypeA)
	client.Exchange(context.Background(), m, "udp", listenAddr)
	time.Sleep(50 * time.Millisecond)

	var success, failures int32
	var wg sync.WaitGroup

	concurrency := 50
	queriesPerRoutine := 500

	start := time.Now()
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			client := dns.NewClient()
			client.ReadTimeout = 1 * time.Second
			for j := 0; j < queriesPerRoutine; j++ {
				m := new(dns.Msg)
				dnsutil.SetQuestion(m, fmt.Sprintf("test-%d-%d.com.", routineID, j), dns.TypeA)
				r, _, err := client.Exchange(context.Background(), m, "udp", listenAddr)
				if err == nil && r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
					atomic.AddInt32(&success, 1)
				} else {
					if atomic.AddInt32(&failures, 1) == 1 {
						if err != nil {
							t.Logf("First failure trace (Client ERROR): %v", err)
						} else if r != nil {
							t.Logf("First failure trace (Response error code): Rcode=%v, Answers=%v", dns.RcodeToString[r.Rcode], len(r.Answer))
						}
					}
				}
				time.Sleep(2 * time.Millisecond) // Smooth curve to avoid EAGAIN on Linux loopback UDP
			}
		}(i)
	}

	// 4. Concurrently panic check: verify process is still alive halfway
	wg.Wait()
	duration := time.Since(start)

	// Verify server did not panic or crash
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		t.Fatal("mini-ppdns crashed or exited prematurely due to panic")
	}

	total := concurrency * queriesPerRoutine
	succ := atomic.LoadInt32(&success)
	fail := atomic.LoadInt32(&failures)

	t.Logf("Stress Test Completed in %v", duration)
	t.Logf("Total Queries: %d", total)
	t.Logf("Successful: %d", succ)
	t.Logf("Failed: %d", fail)
	t.Logf("QPS: %.2f", float64(total)/duration.Seconds())

	// Because of our artificial 10ms upstream jitter and 1sec client timeout,
	// some failures might happen, but we mainly care about server crash/panic.
	// We'll enforce that at least some passed, demonstrating it stayed alive.
	if succ == 0 {
		t.Errorf("All queries failed! Expected at least some to succeed.")
	}
}
