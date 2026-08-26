// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package security

import (
	"net/http"
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

// evilDetector detects "evil" instead of "attack", used to verify overwrite on re-register.
type evilDetector struct{ name string }

func (m *evilDetector) Name() string        { return m.name }
func (m *evilDetector) Detect(input string) *Result {
	if strings.Contains(input, "evil") {
		return &Result{Name: m.name, Detected: true, Severity: SeverityCritical, Message: "evil detection"}
	}
	return &Result{Name: m.name, Detected: false}
}

func TestRegisterDuplicateOverwrites(t *testing.T) {
	e := NewEngine()
	e.Register(&mockDetector{name: "dup"})
	e.Register(&evilDetector{name: "dup"}) // same name, must replace

	if r := e.Detect("dup", "attack"); r == nil || r.Detected {
		t.Fatal("old detector should have been replaced")
	}
	r := e.Detect("dup", "evil")
	if r == nil || !r.Detected || r.Severity != SeverityCritical {
		t.Fatalf("expected new detector to detect 'evil', got %+v", r)
	}
}

func TestDetectAllOnlyReturnsDetected(t *testing.T) {
	e := NewEngine()
	e.Register(&mockDetector{name: "hit"})
	e.Register(&evilDetector{name: "miss"}) // never matches "attack"

	results := e.DetectAll("attack")
	if len(results) != 1 || results[0].Name != "hit" {
		t.Fatalf("expected only the matching detector's result, got %+v", results)
	}
}

func TestDetectRequestCollectsAllSources(t *testing.T) {
	e := NewEngine()
	e.Register(&mockDetector{name: "mock"})

	req := httptest.NewRequest("GET", "/attack?q=attack", nil)
	req.Header.Set("X-Attack", "attack")
	req.AddCookie(&http.Cookie{Name: "attack", Value: "attack"})

	results := e.DetectRequest(req)
	// 5 inputs: URL, query, X-Attack header, "Cookie: attack=attack" header
	// (AddCookie writes the Cookie header too), and cookie pair.
	if len(results) != 5 {
		t.Fatalf("expected 5 detections (URL, query, header, cookie header, cookie), got %d: %+v", len(results), results)
	}
}

func TestDetectRequestNoMatch(t *testing.T) {
	e := NewEngine()
	e.Register(&mockDetector{name: "mock"})

	req := httptest.NewRequest("GET", "/clean?q=clean", nil)
	req.Header.Set("X-Clean", "clean")
	req.AddCookie(&http.Cookie{Name: "clean", Value: "clean"})

	if results := e.DetectRequest(req); len(results) != 0 {
		t.Fatalf("expected no detections, got %d: %+v", len(results), results)
	}
}

func TestDetectRequestNilRequest(t *testing.T) {
	e := NewEngine()
	e.Register(&mockDetector{name: "mock"})

	if results := e.DetectRequest(nil); len(results) != 0 {
		t.Fatalf("expected no detections for nil request, got %d", len(results))
	}
}

func TestCollectRequestInputs(t *testing.T) {
	req := httptest.NewRequest("POST", "/path?key=val&key=val2", nil)
	req.Header.Set("X-Custom", "h1")
	req.Header.Set("X-Multi", "m1")
	req.Header.Add("X-Multi", "m2")
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc"})

	inputs := collectRequestInputs(req)
	joined := strings.Join(inputs, "\n")
	for _, want := range []string{
		"/path?key=val&key=val2", // URL
		"key=val&key=val2",       // query encode, appears twice (URL + encode line)
		"X-Custom: h1",           // header
		"X-Multi: m1",            // header multi-value
		"X-Multi: m2",
		"session=abc", // cookie
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected input %q in collected inputs:\n%s", want, joined)
		}
	}
	if strings.Count(joined, "key=val&key=val2") < 2 {
		t.Fatal("query values must be collected as both URL and encoded query")
	}
}

func TestCollectRequestInputsNilRequest(t *testing.T) {
	if inputs := collectRequestInputs(nil); len(inputs) != 0 {
		t.Fatalf("expected no inputs for nil request, got %d", len(inputs))
	}
}

func TestCollectRequestInputsNilURL(t *testing.T) {
	req := &http.Request{Header: http.Header{"X-Custom": []string{"v"}}}
	inputs := collectRequestInputs(req)
	if len(inputs) != 1 || inputs[0] != "X-Custom: v" {
		t.Fatalf("expected header only, got %+v", inputs)
	}
}
