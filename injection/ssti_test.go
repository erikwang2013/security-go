// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestSSTI(t *testing.T) {
	d := &SSTI{}
	if got := d.Name(); got != "ssti" {
		t.Fatalf("Name() = %q, want %q", got, "ssti")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{"{{7*7}}", true},
		{"{{config.SECRET_KEY}}", true},
		{"${7*7}", true},
		{"<%= system('id') %>", true},
		{"<% system('id') %>", true},
		{"{{''.__class__.__mro__[2].__subclasses__()}}", true},
		{"{{self.__class__.__globals__}}", true},
		{"{# comment #}", true},
		{"x.getClass()", true},
		// benign / boundary
		{"normal text", false},
		{"{ not a template }", false},
		{"100% done", false},
		{"{{ unclosed", false},
		{"${ unclosed", false},
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
	if meta.Severity != security.SeverityCritical {
		t.Errorf("detected severity = %v, want SeverityCritical", meta.Severity)
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
