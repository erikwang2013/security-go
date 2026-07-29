// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestXPath(t *testing.T) {
	d := &XPath{}
	tests := []struct {
		input  string
		should bool
	}{
		{"' or '1'='1", true},
		{"' or 1=1", true},
		{"string-length(//user)", true},
		{"count(//user)", true},
		{"normal text", false},
		{"hello", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
