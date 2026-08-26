// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package storage

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileIncrAndGet(t *testing.T) {
	f, err := NewFile(filepath.Join(t.TempDir(), "data.json"))
	if err != nil {
		t.Fatalf("NewFile failed: %v", err)
	}
	defer f.Close()

	count, err := f.Incr("ip", time.Minute)
	if err != nil || count != 1 {
		t.Fatalf("expected count=1, got count=%d err=%v", count, err)
	}
	count, err = f.Incr("ip", time.Minute)
	if err != nil || count != 2 {
		t.Fatalf("expected count=2, got count=%d err=%v", count, err)
	}
	got, err := f.Get("ip")
	if err != nil || got != 2 {
		t.Fatalf("expected Get=2, got %d err=%v", got, err)
	}
	got, _ = f.Get("missing")
	if got != 0 {
		t.Fatalf("expected 0 for missing key, got %d", got)
	}
}

func TestFileWindowReset(t *testing.T) {
	f, _ := NewFile(filepath.Join(t.TempDir(), "data.json"))
	defer f.Close()

	f.Incr("ip", 20*time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	count, err := f.Incr("ip", 20*time.Millisecond)
	if err != nil || count != 1 {
		t.Fatalf("expected count reset to 1 after window, got count=%d err=%v", count, err)
	}
}

func TestFileBlockAndIsBlocked(t *testing.T) {
	f, _ := NewFile(filepath.Join(t.TempDir(), "data.json"))
	defer f.Close()

	if blocked, _ := f.IsBlocked("bad"); blocked {
		t.Fatal("expected not blocked initially")
	}

	if err := f.Block("bad", 50*time.Millisecond); err != nil {
		t.Fatalf("Block failed: %v", err)
	}
	if blocked, _ := f.IsBlocked("bad"); !blocked {
		t.Fatal("expected blocked after Block()")
	}

	time.Sleep(100 * time.Millisecond)
	if blocked, _ := f.IsBlocked("bad"); blocked {
		t.Fatal("expected unblocked after duration")
	}
}

func TestFilePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile failed: %v", err)
	}
	f.Incr("ip", time.Minute)
	f.Incr("ip", time.Minute)
	f.Incr("other", time.Minute)
	f.Block("bad", time.Hour)
	if err := f.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	f2, err := NewFile(path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer f2.Close()

	got, _ := f2.Get("ip")
	if got != 2 {
		t.Fatalf("expected count 2 restored, got %d", got)
	}
	got, _ = f2.Get("other")
	if got != 1 {
		t.Fatalf("expected count 1 restored for other, got %d", got)
	}
	if blocked, _ := f2.IsBlocked("bad"); !blocked {
		t.Fatal("expected block state restored")
	}
	if blocked, _ := f2.IsBlocked("notbad"); blocked {
		t.Fatal("unrelated key must not be blocked")
	}

	// counter continues from restored value within same window
	count, err := f2.Incr("ip", time.Minute)
	if err != nil || count != 3 {
		t.Fatalf("expected count 3 after restore+incr, got %d err=%v", count, err)
	}
}

func TestFileConcurrentIncr(t *testing.T) {
	f, _ := NewFile(filepath.Join(t.TempDir(), "data.json"))
	defer f.Close()

	const goroutines = 20
	const perGoroutine = 100

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				f.Incr("ip", time.Minute)
			}
		}()
	}
	wg.Wait()

	got, _ := f.Get("ip")
	if got != goroutines*perGoroutine {
		t.Fatalf("expected %d, got %d", goroutines*perGoroutine, got)
	}
}

func TestFileInvalidPath(t *testing.T) {
	// NewFile does not create parent dirs; operations succeed in memory,
	// Close surfaces the write error.
	path := filepath.Join(t.TempDir(), "no", "such", "dir", "data.json")
	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile should not fail for missing dirs, got %v", err)
	}
	f.Incr("ip", time.Minute)
	if err := f.Close(); err == nil {
		t.Fatal("expected Close to fail for unwritable path")
	}
}

func TestFileCorruptDataLoadsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	if err := os.WriteFile(path, []byte("not json at all"), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile should tolerate corrupt data, got %v", err)
	}
	defer f.Close()

	if got, _ := f.Get("anything"); got != 0 {
		t.Fatalf("expected empty state after corrupt load, got %d", got)
	}
}

func TestFileCloseCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	f, _ := NewFile(path)
	f.Incr("ip", time.Minute)
	if err := f.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected data file to exist after Close, got %v", err)
	}
}
