// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestGraphQL(t *testing.T) {
	d := &GraphQL{}
	if got := d.Name(); got != "graphql_injection" {
		t.Fatalf("Name() = %q, want %q", got, "graphql_injection")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{"{__schema{types{name}}}", true},
		{"{__type(name:\"User\"){name}}", true},
		{"{__typename}", true},
		{"mutation{deleteUser(id:1)}", true},
		{"query { __schema }", true},
		{"{a{b{c{d{e{f}}}}}", true},
		// benign / boundary
		{"query { user { name } }", false},
		{"normal text", false},
		{"__typography", false},
		{"mutation", false},
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
	if meta.Severity != security.SeverityMedium {
		t.Errorf("detected severity = %v, want SeverityMedium", meta.Severity)
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
