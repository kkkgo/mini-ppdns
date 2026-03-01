package pool

import (
	"testing"
	"time"
)

func TestGetTimer(t *testing.T) {
	timer := GetTimer(50 * time.Millisecond)
	select {
	case <-timer.C:
		// ok, timer fired
	case <-time.After(time.Second):
		t.Fatal("timer did not fire")
	}
	// Should not panic even after firing
	ReleaseTimer(timer)
}

func TestReleaseTimer_StoppedBeforeFire(t *testing.T) {
	timer := GetTimer(time.Hour) // long duration, won't fire
	ReleaseTimer(timer)
	// Should not panic
}

func TestGetTimer_Reuse(t *testing.T) {
	t1 := GetTimer(time.Hour)
	ReleaseTimer(t1)

	t2 := GetTimer(50 * time.Millisecond)
	select {
	case <-t2.C:
		// ok
	case <-time.After(time.Second):
		t.Fatal("reused timer did not fire")
	}
	ReleaseTimer(t2)
}

func TestResetAndDrainTimer(t *testing.T) {
	timer := GetTimer(time.Hour)
	ResetAndDrainTimer(timer, 50*time.Millisecond)

	select {
	case <-timer.C:
		// ok, timer fired after reset
	case <-time.After(time.Second):
		t.Fatal("reset timer did not fire")
	}
	ReleaseTimer(timer)
}

func TestResetAndDrainTimer_AfterFire(t *testing.T) {
	timer := GetTimer(10 * time.Millisecond)
	time.Sleep(50 * time.Millisecond) // let it fire

	// Reset after fire should work
	ResetAndDrainTimer(timer, 50*time.Millisecond)
	select {
	case <-timer.C:
		// ok
	case <-time.After(time.Second):
		t.Fatal("timer did not fire after reset")
	}
	ReleaseTimer(timer)
}

func BenchmarkGetReleaseTimer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t := GetTimer(time.Minute)
		ReleaseTimer(t)
	}
}
