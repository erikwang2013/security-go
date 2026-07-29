// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import "testing"

func TestCSVInjection(t *testing.T) {
	d := &CSVInjection{}
	tests := []struct {
		input  string
		should bool
	}{
		{"=cmd('calc')", true},
		{"=HYPERLINK(\"http://evil.com\")", true},
		{"@SUM(1,2)", true},
		{"+SUM(1,2)", true},
		{"-SUM(1,2)", true},
		{"=A1+B2", true},
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
