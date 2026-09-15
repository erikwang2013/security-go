// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"strings"
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestNestedDepthName(t *testing.T) {
	d := &NestedDepth{}
	if d.Name() != "nested_depth" {
		t.Fatalf("expected name 'nested_depth', got %s", d.Name())
	}
}

func TestNestedDepthDefaults(t *testing.T) {
	d := NewNestedDepth(0, 0)
	if d.MaxDepth != defaultMaxDepth {
		t.Fatalf("expected MaxDepth %d, got %d", defaultMaxDepth, d.MaxDepth)
	}
	if d.MaxKeys != 0 {
		t.Fatalf("expected MaxKeys 0, got %d", d.MaxKeys)
	}
}

func TestNestedDepthShallow(t *testing.T) {
	d := NewNestedDepth(4, 0)
	if r := d.Detect(`{"a":1,"b":2}`); r.Detected {
		t.Fatalf("expected no detection for a shallow document, got %+v", r)
	}
}

func TestNestedDepthAtLimit(t *testing.T) {
	d := NewNestedDepth(3, 0)
	if r := d.Detect(`{"a":{"a":{"a":1}}}`); r.Detected {
		t.Fatalf("expected no detection at the exact depth limit, got %+v", r)
	}
}

func TestNestedDepthExceeded(t *testing.T) {
	d := NewNestedDepth(2, 0)
	r := d.Detect(`{"a":{"a":{"a":1}}}`)
	if !r.Detected {
		t.Fatal("expected detection for excessive nesting depth")
	}
	if r.Severity != security.SeverityHigh {
		t.Fatalf("expected SeverityHigh, got %v", r.Severity)
	}
	if r.Details["reason"] != "depth" {
		t.Fatalf("expected reason 'depth', got %v", r.Details["reason"])
	}
	if got, _ := r.Details["depth"].(int); got <= 2 {
		t.Fatalf("expected a depth above the limit, got %v", got)
	}
	if r.Message == "" {
		t.Error("expected a non-empty message")
	}
}

func TestNestedDepthArrayNesting(t *testing.T) {
	d := NewNestedDepth(2, 0)
	r := d.Detect(`[[[1]]]`)
	if !r.Detected {
		t.Fatal("expected detection for deeply nested arrays")
	}
	if r.Details["reason"] != "depth" {
		t.Fatalf("expected reason 'depth', got %v", r.Details["reason"])
	}
}

func TestNestedDepthDefaultLimitCatchesBomb(t *testing.T) {
	d := NewNestedDepth(0, 0)
	bomb := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
	r := d.Detect(bomb)
	if !r.Detected {
		t.Fatal("expected the default limit to catch a 40-level document")
	}
}

func TestNestedDepthTooManyKeys(t *testing.T) {
	d := NewNestedDepth(32, 2)
	r := d.Detect(`{"a":1,"b":2,"c":3}`)
	if !r.Detected {
		t.Fatal("expected detection for excessive element count")
	}
	if r.Details["reason"] != "keys" {
		t.Fatalf("expected reason 'keys', got %v", r.Details["reason"])
	}
	if got, _ := r.Details["keys"].(int); got <= 2 {
		t.Fatalf("expected an element count above the limit, got %v", got)
	}
}

func TestNestedDepthKeysUnlimited(t *testing.T) {
	d := NewNestedDepth(32, 0)
	if r := d.Detect(`{"a":1,"b":2,"c":3,"d":4,"e":5}`); r.Detected {
		t.Fatalf("expected no detection when MaxKeys is 0, got %+v", r)
	}
}

func TestNestedDepthEmpty(t *testing.T) {
	d := NewNestedDepth(4, 4)
	if r := d.Detect(""); r.Detected {
		t.Fatalf("expected no detection for empty input, got %+v", r)
	}
}

func TestNestedDepthRejectsNonJSON(t *testing.T) {
	d := NewNestedDepth(4, 4)
	for _, in := range []string{
		"hello world",
		"'; DROP TABLE users--",
		`<script>alert(1)</script>`,
		`<?xml version="1.0"?>`,
		"plain text with no structure",
	} {
		if r := d.Detect(in); r.Detected {
			t.Fatalf("expected no detection for non-JSON input %q, got %+v", in, r)
		}
	}
}

func TestNestedDepthTruncatedJSON(t *testing.T) {
	d := NewNestedDepth(2, 0)
	for _, in := range []string{`{"a":`, `[`, `{"a":{}}`, `"unterminated`} {
		if r := d.Detect(in); r.Detected {
			t.Fatalf("expected no detection for truncated input %q, got %+v", in, r)
		}
	}
}

func TestNestedDepthAttackInsideShallowJSON(t *testing.T) {
	d := NewNestedDepth(4, 0)
	// The payload is benign to this detector: it is well-formed and shallow.
	in := `{"q":"' OR 1=1--", "x":"<script>alert(1)</script>"}`
	if r := d.Detect(in); r.Detected {
		t.Fatalf("expected no detection for a shallow attack-bearing document, got %+v", r)
	}
}

func TestNestedDepthBombedAttackInput(t *testing.T) {
	d := NewNestedDepth(3, 0)
	// Attack payload is irrelevant; the document is structurally too deep.
	in := `{"q":` + strings.Repeat(`{"a":`, 10) + `"x"` + strings.Repeat("}", 10) + `}`
	r := d.Detect(in)
	if !r.Detected {
		t.Fatal("expected detection for an over-deep document")
	}
}

func TestNestedDepthDetailsCarryBothLimits(t *testing.T) {
	d := NewNestedDepth(2, 0)
	r := d.Detect(`{"a":{"a":{"a":1}}}`)
	if got, _ := r.Details["max_depth"].(int); got != 2 {
		t.Fatalf("expected max_depth 2, got %v", got)
	}
	if _, ok := r.Details["max_keys"]; !ok {
		t.Error("expected max_keys in Details")
	}
}
