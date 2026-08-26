// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestWebSocket(t *testing.T) {
	d := &WebSocket{}
	if r := d.Detect(""); r == nil || r.Name != "websocket" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected websocket result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"Upgrade: websocket", true},
		{"upgrade: websocket", true},
		{"Connection: Upgrade", true},
		{"Connection: keep-alive, Upgrade", false},
		{"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", true},
		{"Sec-WebSocket-Key:", true},
		{"ws://evil.com/socket", true},
		{"wss://evil.com/socket", true},
		{"http://evil.com/socket", false},
		{"Origin: null\r\nUpgrade: websocket", true},
		{"Origin: null", false},
		{"Origin: https://example.com\r\nUpgrade: websocket", true},
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
