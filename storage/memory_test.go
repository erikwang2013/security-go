// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package storage

import (
	"testing"
	"time"
)

func TestMemoryIncr(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	count, err := m.Incr("test", time.Second)
	if err != nil || count != 1 {
		t.Fatalf("expected count=1, got count=%d err=%v", count, err)
	}

	count, err = m.Incr("test", time.Second)
	if err != nil || count != 2 {
		t.Fatalf("expected count=2, got %d, err=%v", count, err)
	}
}

func TestMemoryWindowReset(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	m.Incr("test", time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	count, err := m.Incr("test", time.Millisecond)
	if err != nil || count != 1 {
		t.Fatalf("expected count=1 after window reset, got count=%d err=%v", count, err)
	}
}

func TestMemoryBlock(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	isBlocked, _ := m.IsBlocked("badip")
	if isBlocked {
		t.Fatal("expected not blocked initially")
	}

	m.Block("badip", 100*time.Millisecond)

	isBlocked, _ = m.IsBlocked("badip")
	if !isBlocked {
		t.Fatal("expected blocked after Block()")
	}

	time.Sleep(150 * time.Millisecond)

	isBlocked, _ = m.IsBlocked("badip")
	if isBlocked {
		t.Fatal("expected unblocked after duration")
	}
}

func TestMemoryGet(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	val, _ := m.Get("nonexistent")
	if val != 0 {
		t.Fatalf("expected 0 for nonexistent key")
	}

	m.Incr("exists", time.Minute)
	val, _ = m.Get("exists")
	if val != 1 {
		t.Fatalf("expected 1 for existing key")
	}
}

// A counter older than its own window must read as zero even before the
// reaper runs: Get has no window argument, so the window recorded by Incr is
// the only expiry it can use.
func TestMemoryGetHonorsWindow(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	if _, err := m.Incr("k", 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)

	if got, _ := m.Get("k"); got != 0 {
		t.Fatalf("Get after the window = %d, want 0", got)
	}
}

// The reaper previously dropped every entry after a hard-coded 5 minutes,
// even when Incr was given a longer window. Signer requests 10 minutes by
// default, so its nonces vanished halfway through their replay window.
func TestMemoryReapHonorsRecordedWindow(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	if _, err := m.Incr("k", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.events["k"].windowStart = time.Now().Add(-6 * time.Minute)
	m.mu.Unlock()

	m.reapOnce(time.Now())

	if got, _ := m.Get("k"); got != 1 {
		t.Fatalf("entry inside its 10m window was reaped: Get = %d, want 1", got)
	}
}

func TestMemoryReapDropsExpiredBlocks(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	if err := m.Block("bad", 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	m.reapOnce(time.Now())

	m.mu.RLock()
	_, ok := m.blocked["bad"]
	m.mu.RUnlock()
	if ok {
		t.Error("expired block entry was not reaped")
	}
}
