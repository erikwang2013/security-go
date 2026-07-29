package injection

import "testing"

func TestXSS(t *testing.T) {
	d := &XSS{}
	tests := []struct {
		input  string
		should bool
	}{
		{"<script>alert(1)</script>", true},
		{"<img onerror=alert(1) src=x>", true},
		{"javascript:eval('xss')", true},
		{"<svg onload=alert(1)>", true},
		{"<body onload=alert(1)>", true},
		{"eval('alert(1)')", true},
		{"document.cookie", true},
		{"<iframe src=evil.com>", true},
		{"hello world", false},
		{"normal text without html", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
