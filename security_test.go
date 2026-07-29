// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package security

import (
	"net/http/httptest"
	"strings"
	"testing"
)

type mockDetector struct{ name string }

func (m *mockDetector) Name() string        { return m.name }
func (m *mockDetector) Detect(input string) *Result {
	if strings.Contains(input, "attack") {
		return &Result{Name: m.name, Detected: true, Severity: SeverityHigh, Message: "mock detection"}
	}
	return &Result{Name: m.name, Detected: false}
}

func TestEngineRegisterAndDetect(t *testing.T) {
	e := NewEngine()
	e.Register(&mockDetector{name: "mock"})

	r := e.Detect("mock", "attack")
	if r == nil || !r.Detected {
		t.Fatal("expected detection for 'attack'")
	}

	r = e.Detect("mock", "clean")
	if r == nil || r.Detected {
		t.Fatal("expected no detection for 'clean'")
	}
}

func TestEngineDetectAll(t *testing.T) {
	e := NewEngine()
	e.Register(&mockDetector{name: "a"})
	e.Register(&mockDetector{name: "b"})

	results := e.DetectAll("attack")
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	results = e.DetectAll("clean")
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestDetectUnknown(t *testing.T) {
	e := NewEngine()
	if r := e.Detect("nonexistent", "test"); r != nil {
		t.Fatal("expected nil for unknown detector")
	}
}

func TestDetectRequest(t *testing.T) {
	e := NewEngine()
	e.Register(&mockDetector{name: "mock"})

	req := httptest.NewRequest("GET", "/test?input=attack", nil)
	req.Header.Set("X-Test", "clean")

	results := e.DetectRequest(req)
	if len(results) < 1 {
		t.Fatal("expected at least 1 detection from URL query")
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityLow >= SeverityMedium || SeverityMedium >= SeverityHigh || SeverityHigh >= SeverityCritical {
		t.Fatal("severity ordering wrong")
	}
}
