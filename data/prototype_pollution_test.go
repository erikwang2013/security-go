// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import "testing"

func TestPrototypePollution(t *testing.T) {
	d := &PrototypePollution{}
	if r := d.Detect(""); r == nil || r.Name != "prototype_pollution" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected prototype_pollution result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{`"__proto__": {"isAdmin": true}`, true},
		{`'__proto__': {"isAdmin": true}`, true},
		{`"constructor": {"prototype": {"isAdmin": true}}`, true},
		{`"prototype": {"isAdmin": true}`, true},
		{`__defineGetter__("isAdmin")`, true},
		{`__defineSetter__("isAdmin")`, true},
		{`__lookupGetter__("isAdmin")`, true},
		{`__lookupSetter__("isAdmin")`, true},
		{`[[__proto__]]`, true},
		{`.__proto__ = {}`, true},
		{`constructor["prototype"]`, true},
		{`obj.constructor['prototype']`, true},
		{`normal text`, false},
		{`{"name": "test"}`, false},
		{`"__proto__"`, false},
		{`obj.__proto__`, false},
		{`"constructor"`, false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
