// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import "testing"

func TestDataLeak(t *testing.T) {
	d := &SensitiveDataLeak{}
	if r := d.Detect(""); r == nil || r.Name != "data_leak" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected data_leak result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"4111111111111111", true},
		{"4111 1111 1111 1111", true},
		{"1234-5678-9012-3456", true},
		{"4111 1111 1111", false},
		{"phone: 12345678901", false},
		{"AKIAIOSFODNN7EXAMPLE", true},
		{"AKIAIOSFODNN7EXAM", false},
		{"-----BEGIN PRIVATE KEY-----", true},
		{"-----BEGIN RSA PRIVATE KEY-----", true},
		{"-----BEGIN PUBLIC KEY-----", false},
		{"-----BEGIN CERTIFICATE-----", true},
		{"jdbc:mysql://user:pass@host:3306/db", true},
		{"redis://user:pass@host:6379", true},
		{"mongodb://user:pass@host:27017/db", true},
		{"api_key: abc123def456", true},
		{"API_SECRET=xyz123", true},
		{"apikey: abc123", true},
		{"access_token: xyz789", true},
		{"auth_token: xyz789", true},
		{"Bearer xyz", false},
		{"password: 'secret123'", true},
		{`password = "hunter2"`, true},
		{"sk-abcdefghijklmnopqrstuvwxyz123456", true},
		{"github_token: abc123", true},
		{"github_pat: abc123", true},
		{"ghp_1234567890abcdef1234567890abcdef12345678", true},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", true},
		{"normal text without secrets", false},
		{"version 1.2.3", false},
		{"order 12345", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
