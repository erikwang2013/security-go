// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import "testing"

func TestDeserialization(t *testing.T) {
	d := &Deserialization{}
	tests := []struct {
		input  string
		should bool
	}{
		{"O:8:\"stdClass\":0:{}", true},
		{"C:11:\"ArrayObject\":21:{x:i:0;a:0:{}}", true},
		{"a:2:{i:0;s:4:\"test\";i:1;s:5:\"hello\";}", true},
		{"unserialize($payload)", true},
		{"__wakeup()", true},
		{"__destruct()", true},
		{"__PHP_Incomplete_Class", true},
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
