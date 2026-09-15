// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"bytes"
	"testing"
	"time"
)

func TestMemoryStoreRoundTrip(t *testing.T) {
	st := NewMemoryStore()
	defer st.Close()

	if err := st.Save("key-1", []byte("value-1"), time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := st.Load("key-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, []byte("value-1")) {
		t.Fatalf("expected value-1, got %q", got)
	}
}

func TestMemoryStoreMissingKey(t *testing.T) {
	st := NewMemoryStore()
	defer st.Close()

	got, err := st.Load("absent")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for a missing key, got %q", got)
	}
}

func TestMemoryStoreExpiry(t *testing.T) {
	st := NewMemoryStore()
	defer st.Close()

	if err := st.Save("key-1", []byte("value-1"), 20*time.Millisecond); err != nil {
		t.Fatalf("Save: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	got, err := st.Load("key-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Fatalf("expected the value to expire, got %q", got)
	}
}

func TestMemoryStoreOverwrite(t *testing.T) {
	st := NewMemoryStore()
	defer st.Close()

	if err := st.Save("key-1", []byte("first"), time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := st.Save("key-1", []byte("second"), time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := st.Load("key-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, []byte("second")) {
		t.Fatalf("expected second, got %q", got)
	}
}

func TestMemoryStoreDelete(t *testing.T) {
	st := NewMemoryStore()
	defer st.Close()

	if err := st.Save("key-1", []byte("value-1"), time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := st.Delete("key-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err := st.Load("key-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil after delete, got %q", got)
	}
}

func TestMemoryStoreCopiesValue(t *testing.T) {
	st := NewMemoryStore()
	defer st.Close()

	value := []byte("value-1")
	if err := st.Save("key-1", value, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	value[0] = 'X' // a caller reusing its buffer must not corrupt the store

	got, err := st.Load("key-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, []byte("value-1")) {
		t.Fatalf("expected the stored copy to be unaffected, got %q", got)
	}

	got[0] = 'Y' // and mutating a loaded value must not corrupt it either
	again, err := st.Load("key-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(again, []byte("value-1")) {
		t.Fatalf("expected the stored copy to be unaffected, got %q", again)
	}
}

func TestMemoryStoreCloseTwice(t *testing.T) {
	st := NewMemoryStore()

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
