// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package redis

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newTestBackend(t *testing.T) (*Backend, *miniredis.Miniredis) {
	t.Helper()
	s := miniredis.RunT(t)
	return New(s.Addr(), "", 0), s
}

func TestIncrAndGet(t *testing.T) {
	b, _ := newTestBackend(t)
	defer b.Close()

	count, err := b.Incr("ip:1.2.3.4", time.Minute)
	if err != nil || count != 1 {
		t.Fatalf("expected count=1, got count=%d err=%v", count, err)
	}
	count, err = b.Incr("ip:1.2.3.4", time.Minute)
	if err != nil || count != 2 {
		t.Fatalf("expected count=2, got count=%d err=%v", count, err)
	}
	got, err := b.Get("ip:1.2.3.4")
	if err != nil || got != 2 {
		t.Fatalf("expected Get=2, got %d err=%v", got, err)
	}
}

func TestGetMissingKey(t *testing.T) {
	b, _ := newTestBackend(t)
	defer b.Close()

	got, err := b.Get("missing")
	if err != nil || got != 0 {
		t.Fatalf("expected 0 for missing key, got %d err=%v", got, err)
	}
}

func TestIncrWindowExpiry(t *testing.T) {
	b, s := newTestBackend(t)
	defer b.Close()

	b.Incr("ip:1.2.3.4", 30*time.Second)
	s.FastForward(31 * time.Second)

	count, err := b.Incr("ip:1.2.3.4", 30*time.Second)
	if err != nil || count != 1 {
		t.Fatalf("expected count reset to 1 after window, got %d err=%v", count, err)
	}
	got, err := b.Get("ip:1.2.3.4")
	if err != nil || got != 1 {
		t.Fatalf("expected Get=1 after reset, got %d err=%v", got, err)
	}
}

func TestBlockAndIsBlocked(t *testing.T) {
	b, s := newTestBackend(t)
	defer b.Close()

	blocked, err := b.IsBlocked("badip")
	if err != nil || blocked {
		t.Fatalf("expected not blocked initially, got %v err=%v", blocked, err)
	}

	if err := b.Block("badip", time.Minute); err != nil {
		t.Fatalf("Block failed: %v", err)
	}
	blocked, err = b.IsBlocked("badip")
	if err != nil || !blocked {
		t.Fatalf("expected blocked, got %v err=%v", blocked, err)
	}

	s.FastForward(61 * time.Second)
	blocked, err = b.IsBlocked("badip")
	if err != nil || blocked {
		t.Fatalf("expected unblocked after duration, got %v err=%v", blocked, err)
	}
}

func TestBlockIsSeparateFromCounters(t *testing.T) {
	b, _ := newTestBackend(t)
	defer b.Close()

	b.Incr("ip:1.2.3.4", time.Minute)
	b.Block("ip:1.2.3.4", time.Minute)

	// counter and block use different keys, neither affects the other
	if got, _ := b.Get("ip:1.2.3.4"); got != 1 {
		t.Fatalf("expected counter intact, got %d", got)
	}
	if blocked, _ := b.IsBlocked("1.2.3.4"); blocked {
		t.Fatal("block must be keyed with prefix, other key must not be blocked")
	}
	if blocked, _ := b.IsBlocked("ip:1.2.3.4"); !blocked {
		t.Fatal("expected blocked on original key")
	}
}

func TestClose(t *testing.T) {
	b, _ := newTestBackend(t)
	b.Incr("k", time.Minute)
	if err := b.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// second Close on an already-closed client should error, not panic
	if err := b.Close(); err == nil {
		t.Fatal("expected error on double Close")
	}
}
