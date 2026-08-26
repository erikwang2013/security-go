// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestOpenRedirect(t *testing.T) {
	d := &OpenRedirect{}
	if r := d.Detect(""); r == nil || r.Name != "open_redirect" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected open_redirect result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"//evil.com", true},
		{"  //evil.com", true},
		{"///evil.com", false},
		{"javascript:alert(1)", true},
		{"data:text/html,<script>alert(1)</script>", true},
		{"vbscript:msgbox(1)", true},
		{"xjavascript:alert(1)", false},
		{"redirect_url=https://evil.com", true},
		{"redirected_to=http://evil.com", true},
		{"redirect=//evil.com", true},
		{"redirect=/dashboard", false},
		{"dest=http://evil.com", true},
		{"target=//evil.com", true},
		{"next=//evil.com", true},
		{"url=https://evil.com", true},
		{"url=/images/a.png", false},
		{"%2F%2Fevil.com", true},
		{"%2f%2fevil.com", true},
		{"normal text", false},
		{"https://example.com", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
