// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestXPath(t *testing.T) {
	d := &XPath{}
	if got := d.Name(); got != "xpath_injection" {
		t.Fatalf("Name() = %q, want %q", got, "xpath_injection")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{"' or '1'='1", true},
		{"' and '1'='1", true},
		{"' or 1=1", true},
		{"' and 1=1", true},
		{"string-length(//user)", true},
		{"count(//user)", true},
		{"count(//user|//pass)", true},
		{"a|b/c|d", true},
		// benign / boundary
		{"normal text", false},
		{"hello", false},
		{"//books/book/title", false},
		{"//user[1]|//pass[1]", false},
		{"admin'", false},
		{"", false},
	}
	var meta *security.Result
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
		if tc.should && meta == nil {
			meta = r
		}
	}
	if meta == nil {
		t.Fatal("no detected case to verify metadata")
	}
	if meta.Severity != security.SeverityHigh {
		t.Errorf("detected severity = %v, want SeverityHigh", meta.Severity)
	}
	if meta.Message == "" {
		t.Error("detected Message must not be empty")
	}
	if meta.Details["pattern"] == nil {
		t.Error("detected Details must contain pattern")
	}
	if r := d.Detect("hello"); r.Name != d.Name() || r.Detected {
		t.Errorf("undetected result: Name=%q Detected=%v, want %q/false", r.Name, r.Detected, d.Name())
	}
}
