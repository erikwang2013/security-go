// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestCORS(t *testing.T) {
	d := &CORS{}
	tests := []struct {
		input  string
		should bool
	}{
		{"Origin: null", true},
		{"Access-Control-Allow-Origin: *", true},
		{"Access-Control-Allow-Credentials: true", true},
		{"normal text", false},
		{"hello world", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
