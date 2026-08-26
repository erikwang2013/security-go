// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestDNSRebinding(t *testing.T) {
	d := &DNSRebinding{}
	if r := d.Detect(""); r == nil || r.Name != "dns_rebinding" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected dns_rebinding result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"Host: 127.0.0.1", true},
		{"Host: 10.0.0.1", true},
		{"Host: 192.168.1.1", true},
		{"Host: localhost", true},
		{"Host: 172.16.0.1", true},
		{"Host: 172.31.0.1", true},
		{"Host: 172.32.0.1", true},
		{"Host: [::1]", true},
		{"Host: ::1", true},
		{"Host: attacker", true},
		{"Host: 8.8.8.8", true},
		{"Host: example.com", false},
		{"Host: example.com:8080", false},
		{"Host: example.com\r\nX-Forwarded-For: 1.2.3.4", false},
		{"X-Forwarded-Host: 127.0.0.1", true},
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
