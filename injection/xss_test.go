// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestXSS(t *testing.T) {
	d := &XSS{}
	if got := d.Name(); got != "xss" {
		t.Fatalf("Name() = %q, want %q", got, "xss")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{"<script>alert(1)</script>", true},
		{"<SCRIPT>alert(1)</SCRIPT>", true},
		{"</script>", true},
		{"<img onerror=alert(1) src=x>", true},
		{"<IMG SRC=x ONERROR=alert(1)>", true},
		{"<svg onload=alert(1)>", true},
		{"<body onload=alert(1)>", true},
		{"<input onfocus=alert(1)>", true},
		{"onmouseover=alert(1)", true},
		{"javascript:eval('xss')", true},
		{"JavaScript:alert(1)", true},
		{"<iframe src=evil.com>", true},
		{"<embed src=evil.swf>", true},
		{"<object data=evil.swf>", true},
		{"expression(alert(1))", true},
		{"url(javascript:alert(1))", true},
		{"<link rel=stylesheet href=evil.css>", true},
		{"<meta http-equiv=refresh content=0;url=evil.com>", true},
		{"eval('alert(1)')", true},
		{"EVAL('alert(1)')", true},
		{"document.cookie", true},
		{"document.write('x')", true},
		{"<base href=evil.com>", true},
		{"fromCharCode(97,108,101,114,116)", true},
		{"&#x3c;script&#x3e;", true},
		// benign / boundary
		{"hello world", false},
		{"normal text without html", false},
		{"https://example.com/page", false},
		{"q=donation=5", false},
		{"q=action=1", false},
		{"q=condition=all", false},
		{"email@example.com", false},
		{"", false},
	}
	var meta *security.Result
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
		if tc.should && meta == nil {
			meta = r
		}
	}
	if meta == nil {
		t.Fatal("no detected case to verify metadata")
	}
	if meta.Severity != security.SeverityHigh {
		t.Errorf("detected severity = %v, want SeverityHigh", meta.Severity)
	}
	if meta.Message == "" {
		t.Error("detected Message must not be empty")
	}
	if meta.Details["pattern"] == nil {
		t.Error("detected Details must contain pattern")
	}
	if r := d.Detect("hello"); r.Name != d.Name() || r.Detected {
		t.Errorf("undetected result: Name=%q Detected=%v, want %q/false", r.Name, r.Detected, d.Name())
	}
}
