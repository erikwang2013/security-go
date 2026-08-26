// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestRequestSmuggling(t *testing.T) {
	d := &RequestSmuggling{}
	if r := d.Detect(""); r == nil || r.Name != "request_smuggling" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected request_smuggling result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"Transfer-Encoding: chunked\r\nContent-Length: 5", true},
		{"Transfer-Encoding: gzip, chunked", true},
		{"Transfer-Encoding: chunked", true},
		{"transfer-encoding : chunked", true},
		{"Content-Length: 0\r\nTransfer-Encoding: chunked", true},
		{"Content-Length: 13\r\nTransfer-Encoding: chunked", true},
		{"Content-Length: 13\r\nTransfer-Encoding: gzip", true},
		{"\x0bTransfer-Encoding: chunked", true},
		{"\x0bContent-Length: 5", false},
		{"Content-Length: 13", false},
		{"Transfer-Encoding: gzip", false},
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
