// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"errors"
	"testing"
	"time"

	"github.com/erikwang2013/security-go"
	"github.com/erikwang2013/security-go/storage"
)

// failingBackend is a storage stub that fails the configured operation,
// used to exercise error paths of IPBlacklist.
type failingBackend struct {
	failIncr      bool
	failBlock     bool
	failIsBlocked bool
	count         int
}

func (f *failingBackend) Incr(key string, window time.Duration) (int, error) {
	if f.failIncr {
		return 0, errors.New("incr failed")
	}
	f.count++
	return f.count, nil
}

func (f *failingBackend) Get(key string) (int, error) { return f.count, nil }

func (f *failingBackend) Block(key string, duration time.Duration) error {
	if f.failBlock {
		return errors.New("block failed")
	}
	return nil
}

func (f *failingBackend) IsBlocked(key string) (bool, error) {
	if f.failIsBlocked {
		return false, errors.New("isblocked failed")
	}
	return false, nil
}

func (f *failingBackend) Close() error { return nil }

func TestIPBlacklistNotBlocked(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)

	r := b.Detect("192.168.1.1")
	if r.Detected {
		t.Fatal("expected no detection for unblocked IP")
	}
}

func TestIPBlacklistBlocked(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)

	mem.Block("10.0.0.1", time.Hour)
	r := b.Detect("10.0.0.1")
	if !r.Detected {
		t.Fatal("expected detection for blocked IP")
	}
	if r.Severity != security.SeverityHigh {
		t.Fatalf("expected SeverityHigh, got %v", r.Severity)
	}
	if r.Message == "" {
		t.Error("expected non-empty Message")
	}
	if r.Name != b.Name() {
		t.Errorf("expected result Name=%q, got %q", b.Name(), r.Name)
	}
}

func TestIPBlacklistRecordAttackBelowThreshold(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)
	b.Threshold = 5

	blocked, err := b.RecordAttack("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blocked {
		t.Fatal("expected not blocked below threshold")
	}
}

func TestIPBlacklistRecordAttackReachesThreshold(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)
	b.Threshold = 3

	for i := 0; i < 3; i++ {
		blocked, err := b.RecordAttack("10.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if i < 2 && blocked {
			t.Fatalf("expected not blocked at count %d", i+1)
		}
		if i == 2 && !blocked {
			t.Fatal("expected blocked when threshold reached")
		}
	}
}

func TestIPBlacklistThresholdOne(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)
	b.Threshold = 1

	blocked, err := b.RecordAttack("10.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !blocked {
		t.Fatal("expected blocked on first attack with Threshold=1")
	}
	if r := b.Detect("10.0.0.2"); !r.Detected {
		t.Fatal("expected Detect to report the newly blocked IP")
	}
}

func TestIPBlacklistRecordAttackIncrError(t *testing.T) {
	b := NewIPBlacklist(&failingBackend{failIncr: true})
	b.Threshold = 1

	blocked, err := b.RecordAttack("10.0.0.1")
	if err == nil {
		t.Fatal("expected error when storage Incr fails")
	}
	if blocked {
		t.Fatal("expected not blocked when storage Incr fails")
	}
}

func TestIPBlacklistRecordAttackBlockError(t *testing.T) {
	b := NewIPBlacklist(&failingBackend{failBlock: true})
	b.Threshold = 1

	blocked, err := b.RecordAttack("10.0.0.1")
	if err == nil {
		t.Fatal("expected error when storage Block fails")
	}
	if blocked {
		t.Fatal("expected not blocked when storage Block fails")
	}
}

func TestIPBlacklistDetectStorageError(t *testing.T) {
	b := NewIPBlacklist(&failingBackend{failIsBlocked: true})

	r := b.Detect("10.0.0.1")
	if r.Detected {
		t.Fatal("expected no detection when storage IsBlocked fails")
	}
}

func TestIPBlacklistDefaults(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)

	if b.Threshold != 5 {
		t.Fatalf("expected default Threshold=5, got %d", b.Threshold)
	}
	if b.Window == 0 {
		t.Fatal("expected non-zero default Window")
	}
	if b.BanDuration == 0 {
		t.Fatal("expected non-zero default BanDuration")
	}
}

func TestIPBlacklistName(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)

	if b.Name() != "ip_blacklist" {
		t.Fatalf("expected name 'ip_blacklist', got %s", b.Name())
	}
}
