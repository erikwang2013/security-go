// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestWebSocket(t *testing.T) {
	d := &WebSocket{}
	tests := []struct {
		input  string
		should bool
	}{
		{"Upgrade: websocket", true},
		{"Connection: Upgrade", true},
		{"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", true},
		{"ws://evil.com/socket", true},
		{"wss://evil.com/socket", true},
		{"Origin: null\r\nUpgrade: websocket", true},
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
