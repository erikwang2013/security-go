// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestHeaderInjection(t *testing.T) {
	d := &HeaderInjection{}
	tests := []struct {
		input  string
		should bool
	}{
		{"foo%0d%0aSet-Cookie:evil=true", true},
		{"foo\\r\\nLocation:http://evil.com", true},
		{"foo\r\nX-Forwarded-For:evil", true},
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
