// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestSSRF(t *testing.T) {
	d := &SSRF{}
	tests := []struct {
		input  string
		should bool
	}{
		{"http://169.254.169.254/latest/meta-data", true},
		{"http://127.0.0.1/admin", true},
		{"http://localhost:8080/admin", true},
		{"http://[::1]:8080/api", true},
		{"gopher://evil.com/_GET", true},
		{"dict://attacker.com:6379/info", true},
		{"file:///etc/passwd", true},
		{"http://10.0.0.1/internal", true},
		{"http://192.168.1.1/admin", true},
		{"http://metadata.google.internal/", true},
		{"http://example.com/page", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
