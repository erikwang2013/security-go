// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestSSI(t *testing.T) {
	d := &SSI{}
	tests := []struct {
		input  string
		should bool
	}{
		{"<!--#exec cmd=\"cat /etc/passwd\"-->", true},
		{"<!--#include file=\"menu.html\"-->", true},
		{"<!--#echo var=\"DATE_LOCAL\"-->", true},
		{"<!--#config timefmt=\"%B %Y\"-->", true},
		{"<!--#exec cgi=\"/cgi-bin/evil\"-->", true},
		{"normal text", false},
		{"<!-- just a comment -->", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
