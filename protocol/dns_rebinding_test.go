// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestDNSRebinding(t *testing.T) {
	d := &DNSRebinding{}
	tests := []struct {
		input  string
		should bool
	}{
		{"Host: 127.0.0.1", true},
		{"Host: 10.0.0.1", true},
		{"Host: 192.168.1.1", true},
		{"Host: localhost", true},
		{"Host: 172.16.0.1", true},
		{"Host: example.com", false},
		{"normal text", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
