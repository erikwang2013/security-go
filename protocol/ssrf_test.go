// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestSSRF(t *testing.T) {
	d := &SSRF{}
	if r := d.Detect(""); r == nil || r.Name != "ssrf" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected ssrf result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"http://169.254.169.254/latest/meta-data", true},
		{"http://127.0.0.1/admin", true},
		{"https://127.0.0.1/admin", true},
		{"http://localhost:8080/admin", true},
		{"http://[::1]:8080/api", true},
		{"http://::1/api", true},
		{"http://0.0.0.0", true},
		{"gopher://evil.com/_GET", true},
		{"dict://attacker.com:6379/info", true},
		{"file:///etc/passwd", true},
		{"ftp://10.0.0.1/x", true},
		{"http://10.0.0.1/internal", true},
		{"http://192.168.1.1/admin", true},
		{"http://172.16.0.1", true},
		{"http://172.31.255.1", true},
		{"http://metadata.google.internal/", true},
		{"169.254.169.254", true},
		{"path/to/latest/meta-data", true},
		{"http://example.com/page", false},
		{"https://example.com:8443/x", false},
		{"http://172.32.0.1", false},
		{"http://172.15.0.1", false},
		{"127.0.0.1", false},
		{"example.com", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
