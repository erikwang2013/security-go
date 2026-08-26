// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import "testing"

func TestMailHeader(t *testing.T) {
	d := &MailHeader{}
	if r := d.Detect(""); r == nil || r.Name != "mail_header" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected mail_header result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"\nBcc: spam@evil.com", true},
		{"\nCc: spam@evil.com", true},
		{"\nTo: spam@evil.com", true},
		{"\nFrom: attacker@evil.com", true},
		{"\nReply-To: attacker@evil.com", true},
		{"\nSubject: hacked", true},
		{"\nContent-Type: text/html", true},
		{"\nMIME-Version: 1.0", true},
		{"%0d%0aBcc: spam@evil.com", true},
		{"%0D%0ACc: spam@evil.com", true},
		{"\r\nFrom: attacker@evil.com", true},
		{"\r\nCc: spam@evil.com", true},
		{"Content-Type: multipart/mixed; boundary=evil", true},
		{"Content-Type: text/plain", false},
		{"boundary=evil", true},
		{"From: attacker@evil.com", false},
		{"Bcc: spam@evil.com", false},
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
