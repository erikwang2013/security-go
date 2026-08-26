// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestHostHeader(t *testing.T) {
	d := &HostHeader{}
	if r := d.Detect(""); r == nil || r.Name != "host_header" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected host_header result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"Host: evil.com\r\nX-Forwarded-For: 127.0.0.1", true},
		{"Host: evil.com\r\n", true},
		{"X-Forwarded-Host: evil.com", true},
		{"X-Forwarded-Server: evil.com", true},
		{"X-Original-URL: /admin", true},
		{"X-Rewrite-URL: /admin", true},
		{"Host: evil.com\nX-Forwarded-For: 127.0.0.1", false},
		{"Host: example.com", false},
		{"X-Forwarded-For: 127.0.0.1", false},
		{"X-Original-URI: /admin", false},
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
