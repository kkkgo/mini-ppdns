package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
)

const (
	hookCheckTimeout = 30 * time.Second
	hookCmdTimeout   = 60 * time.Second
	// maxHookOutput caps how much stdout+stderr we retain from a hook's
	// check command. A runaway hook producing unbounded output cannot grow
	// the buffer past this size; excess bytes are dropped on the floor so
	// matching only sees the first maxHookOutput bytes.
	maxHookOutput = 64 * 1024
)

// boundedBuffer is a bytes.Buffer wrapper that stops accepting data once
// its contents reach max. Writes still report full consumption so exec's
// io-copy loop exits cleanly. Safe for single-writer use; exec.Cmd
// serializes writes when Stdout == Stderr, which is the only usage here.
type boundedBuffer struct {
	buf bytes.Buffer
	max int
}

func (w *boundedBuffer) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.max {
		return len(p), nil
	}
	if room := w.max - w.buf.Len(); len(p) > room {
		w.buf.Write(p[:room])
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *boundedBuffer) Bytes() []byte { return w.buf.Bytes() }

type hookMonitor struct {
	cfg      *HookConfig
	failed   *atomic.Bool
	logger   *mlog.Logger
	dnsCache *cache.Cache[CacheKey, *dns.Msg]

	// shutdownCtx is cancelled when the program begins to shut down. Hook
	// command goroutines watch it so they cannot outlive the main loop.
	shutdownCtx context.Context

	// cmdWg tracks in-flight switch-exec goroutines so main can wait for
	// them to finish before closing the logger.
	cmdWg sync.WaitGroup
}

// Wait blocks until all hook-spawned command goroutines have returned.
func (hm *hookMonitor) Wait() {
	hm.cmdWg.Wait()
}

// runCmdTracked runs cmdStr while holding a reference in cmdWg so that
// graceful shutdown can wait for it.
func (hm *hookMonitor) runCmdTracked(cmdStr string) {
	if cmdStr == "" {
		return
	}
	hm.cmdWg.Add(1)
	go func() {
		defer hm.cmdWg.Done()
		runExecCmd(hm.shutdownCtx, hm.logger, cmdStr)
	}()
}

func (hm *hookMonitor) run(ctx context.Context) {
	sleepTime := time.Duration(hm.cfg.SleepTime) * time.Second
	retryTime := time.Duration(hm.cfg.RetryTime) * time.Second
	failCount := 0
	wasDown := false

	for {
		err := hm.check(ctx)
		if err == nil {
			failCount = 0
			if wasDown {
				hm.failed.Store(false)
				wasDown = false
				hm.logger.Infow("[hook] main DNS recovered, switching back to main DNS")
				hm.runCmdTracked(hm.cfg.SwitchMainExec)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(sleepTime):
			}
		} else {
			failCount++
			hm.logger.DebugEventw("[hook] check failed",
				mlog.Int("count", failCount),
				mlog.Int("threshold", hm.cfg.Count),
				mlog.Err(err))
			if failCount >= hm.cfg.Count && !wasDown {
				hm.failed.Store(true)
				wasDown = true
				// Clear DNS cache so stale main-DNS results are purged immediately
				if hm.dnsCache != nil {
					hm.dnsCache.Flush()
					hm.logger.Infow("[hook] DNS cache flushed")
				}
				hm.logger.Warnw("[hook] main DNS marked DOWN, switching to fallback",
					mlog.Int("failures", failCount))
				// Wait retryTime before executing switch_fall_exec so fallback DNS
				// is active and available for the script (e.g. sending notifications)
				if hm.cfg.SwitchFallExec != "" {
					hm.cmdWg.Add(1)
					go func(cmd string) {
						defer hm.cmdWg.Done()
						select {
						case <-ctx.Done():
							return
						case <-time.After(retryTime / 2):
							if !hm.failed.Load() {
								return
							}
							// Run inline: we are already in a dedicated
							// goroutine for the delay, so runOptionalCmd's own
							// `go` wrapper would just add another hop.
							runExecCmd(hm.shutdownCtx, hm.logger, cmd)
						}
					}(hm.cfg.SwitchFallExec)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryTime):
			}
		}
	}
}

// shellCommand creates an exec.Cmd that runs cmdStr through the system shell.
// Uses SHELL env var on Unix (fallback /bin/sh), cmd.exe on Windows.
func shellCommand(ctx context.Context, cmdStr string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/C", cmdStr)
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return exec.CommandContext(ctx, shell, "-c", cmdStr)
}

func (hm *hookMonitor) check(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, hookCheckTimeout)
	defer cancel()

	cmd := shellCommand(checkCtx, hm.cfg.Exec)
	sink := &boundedBuffer{max: maxHookOutput}
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	output := sink.Bytes()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			// Command failed to run (not found, permission denied, timeout, etc.)
			return fmt.Errorf("execution failed: %v", err)
		}
	}

	// If neither exit_code nor keyword is configured, default: success = exit code 0
	if !hm.cfg.ExitCodeSet && hm.cfg.Keyword == "" {
		if exitCode == 0 {
			return nil
		}
		return fmt.Errorf("exit code %d (expected 0)", exitCode)
	}

	if hm.cfg.ExitCodeSet && exitCode != hm.cfg.ExitCode {
		return fmt.Errorf("exit code %d (expected %d)", exitCode, hm.cfg.ExitCode)
	}
	if hm.cfg.Keyword != "" && !bytes.Contains(output, []byte(hm.cfg.Keyword)) {
		return fmt.Errorf("output does not contain keyword %q", hm.cfg.Keyword)
	}
	return nil
}

// runExecCmd synchronously executes cmdStr with the hook command timeout,
// logging any failure. Callers already running in a goroutine should prefer
// this to avoid an unnecessary extra goroutine hop. If parentCtx is cancelled
// (shutdown), the spawned process is killed so it cannot outlive main.
func runExecCmd(parentCtx context.Context, logger *mlog.Logger, cmdStr string) {
	if cmdStr == "" {
		return
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, hookCmdTimeout)
	defer cancel()
	cmd := shellCommand(ctx, cmdStr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warnw("[hook] switch exec failed",
			mlog.String("cmd", cmdStr),
			mlog.Err(err),
			mlog.String("output", string(out)))
	}
}
