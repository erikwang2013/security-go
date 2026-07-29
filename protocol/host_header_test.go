// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestHostHeader(t *testing.T) {
	d := &HostHeader{}
	tests := []struct {
		input  string
		should bool
	}{
		{"Host: evil.com\r\nX-Forwarded-For: 127.0.0.1", true},
		{"X-Forwarded-Host: evil.com", true},
		{"X-Original-URL: /admin", true},
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
