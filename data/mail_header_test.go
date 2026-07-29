// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import "testing"

func TestMailHeader(t *testing.T) {
	d := &MailHeader{}
	tests := []struct {
		input  string
		should bool
	}{
		{"\nBcc: spam@evil.com", true},
		{"\r\nFrom: attacker@evil.com", true},
		{"Content-Type: multipart/mixed; boundary=evil", true},
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
