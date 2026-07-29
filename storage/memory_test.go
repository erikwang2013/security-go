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
