// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import "testing"

func TestPrototypePollution(t *testing.T) {
	d := &PrototypePollution{}
	tests := []struct {
		input  string
		should bool
	}{
		{`"__proto__": {"isAdmin": true}`, true},
		{`"constructor": {"prototype": {"isAdmin": true}}`, true},
		{`"prototype": {"isAdmin": true}`, true},
		{`__defineGetter__("isAdmin")`, true},
		{`__defineSetter__("isAdmin")`, true},
		{`[[__proto__]]`, true},
		{`.__proto__ = {}`, true},
		{`normal text`, false},
		{`{"name": "test"}`, false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
