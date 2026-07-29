// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestOpenRedirect(t *testing.T) {
	d := &OpenRedirect{}
	tests := []struct {
		input  string
		should bool
	}{
		{"//evil.com", true},
		{"javascript:alert(1)", true},
		{"redirect_url=https://evil.com", true},
		{"dest=http://evil.com", true},
		{"%2F%2Fevil.com", true},
		{"normal text", false},
		{"https://example.com", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
