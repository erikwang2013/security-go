// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import "testing"

func TestDataLeak(t *testing.T) {
	d := &SensitiveDataLeak{}
	tests := []struct {
		input  string
		should bool
	}{
		{"AKIAIOSFODNN7EXAMPLE", true},
		{"-----BEGIN PRIVATE KEY-----", true},
		{"-----BEGIN CERTIFICATE-----", true},
		{"jdbc:mysql://user:pass@host:3306/db", true},
		{"api_key: abc123def456", true},
		{"access_token: xyz789", true},
		{"password: 'secret123'", true},
		{"ghp_1234567890abcdef1234567890abcdef12345678", true},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", true},
		{"normal text without secrets", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
