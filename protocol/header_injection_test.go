// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestHeaderInjection(t *testing.T) {
	d := &HeaderInjection{}
	if r := d.Detect(""); r == nil || r.Name != "header_injection" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected header_injection result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"foo%0d%0aSet-Cookie:evil=true", true},
		{"foo%0D%0ASet-Cookie:evil=true", true},
		{"foo%0d%0aX-Forwarded-For:evil", true},
		{"foo%0a%0dLocation:http://evil.com", false},
		{"foo\\r\\nLocation:http://evil.com", true},
		{"foo\\R\\NLocation:http://evil.com", false},
		{"foo\r\nX-Forwarded-For:evil", true},
		{"foo\r\nSet-Cookie:evil=true", true},
		{"normal text", false},
		{"hello world", false},
		{"foo\nbar", false},
		{"foo\nbar\nbaz", false},
		{"%0d", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
