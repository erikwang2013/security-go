// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestBodySizeDefaults(t *testing.T) {
	b := NewBodySize(0)
	if b.MaxSize != 10*1024*1024 {
		t.Fatalf("expected default MaxSize=10MB, got %d", b.MaxSize)
	}
}

func TestBodySizeNegativeDefaults(t *testing.T) {
	b := NewBodySize(-1)
	if b.MaxSize != 10*1024*1024 {
		t.Fatalf("expected default MaxSize=10MB for negative input, got %d", b.MaxSize)
	}
}

func TestBodySizeExplicitValue(t *testing.T) {
	b := NewBodySize(5000)
	if b.MaxSize != 5000 {
		t.Fatalf("expected MaxSize=5000, got %d", b.MaxSize)
	}
}

func TestBodySizeDetectUnderLimit(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("512")
	if r.Detected {
		t.Fatal("expected no detection for body under limit")
	}
}

func TestBodySizeDetectOverLimit(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("2048")
	if !r.Detected {
		t.Fatal("expected detection for body over limit")
	}
	if r.Severity != security.SeverityLow {
		t.Fatalf("expected SeverityLow, got %v", r.Severity)
	}
	if r.Message == "" {
		t.Error("expected non-empty Message")
	}
	if r.Name != b.Name() {
		t.Errorf("expected result Name=%q, got %q", b.Name(), r.Name)
	}
}

func TestBodySizeDetectInvalidInput(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("not-a-number")
	if r.Detected {
		t.Fatal("expected no detection for invalid numeric input")
	}
}

func TestBodySizeDetectAtBoundary(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("1024")
	if r.Detected {
		t.Fatal("expected no detection at exact boundary")
	}
}

func TestBodySizeDetectJustOverBoundary(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("1025")
	if !r.Detected {
		t.Fatal("expected detection one byte over limit")
	}
}

func TestBodySizeDetectEmptyInput(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("")
	if r.Detected {
		t.Fatal("expected no detection for empty input")
	}
}

func TestBodySizeDetectNegative(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("-5")
	if r.Detected {
		t.Fatal("expected no detection for negative size")
	}
}

func TestBodySizeDetectOverflow(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("99999999999999999999999")
	if r.Detected {
		t.Fatal("expected no detection for int64 overflow input")
	}
}

func TestBodySizeName(t *testing.T) {
	b := NewBodySize(1024)
	if b.Name() != "body_size" {
		t.Fatalf("expected name 'body_size', got %s", b.Name())
	}
}
