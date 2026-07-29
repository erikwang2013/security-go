// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestRequestSmuggling(t *testing.T) {
	d := &RequestSmuggling{}
	tests := []struct {
		input  string
		should bool
	}{
		{"Transfer-Encoding: chunked\r\nContent-Length: 5", true},
		{"Transfer-Encoding: gzip, chunked", true},
		{"Transfer-Encoding: chunked", true},
		{"Content-Length: 0\r\nTransfer-Encoding: chunked", true},
		{"\x0bTransfer-Encoding: chunked", true},
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
