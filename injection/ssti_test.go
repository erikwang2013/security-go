// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestSSTI(t *testing.T) {
	d := &SSTI{}
	tests := []struct {
		input  string
		should bool
	}{
		{"{{7*7}}", true},
		{"{{config.SECRET_KEY}}", true},
		{"${7*7}", true},
		{"<%= system('id') %>", true},
		{"{{''.__class__.__mro__[2].__subclasses__()}}", true},
		{"{{self.__class__.__globals__}}", true},
		{"normal text", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
