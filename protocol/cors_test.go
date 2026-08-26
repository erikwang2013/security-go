// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestCORS(t *testing.T) {
	d := &CORS{}
	if r := d.Detect(""); r == nil || r.Name != "cors" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected cors result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"Origin: null", true},
		{"Origin: NULL", true},
		{"Origin: https://example.com", false},
		{"Access-Control-Allow-Origin: *", true},
		{"Access-Control-Allow-Origin: *.example.com", true},
		{"Access-Control-Allow-Origin: https://example.com", false},
		{"Access-Control-Allow-Credentials: true", true},
		{"Access-Control-Allow-Credentials: TRUE", true},
		{"Access-Control-Allow-Credentials: false", false},
		{"Access-Control-Allow-Methods: GET, POST", false},
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
