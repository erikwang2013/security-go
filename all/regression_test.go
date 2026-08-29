// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package all

import (
	"net/http"
	"testing"

	"github.com/erikwang2013/security-go"
)

// Regression: benign query params must not be blocked (no High/Critical),
// while real attack payloads must still be flagged.
func TestFalsePositiveRegression(t *testing.T) {
	e := newEngineWithAll()

	benign := []string{
		"q=hello--world",
		"q=2024--2025",
		"q=donation=5",
		"q=concat(",
		"q=eval(",
		"q=color='#ff0000'",
		"q=c# where clause",
		"q=a || b",
		"q=python exec(",
		"q=it's--what",
		"q=5) --",
		"q=x=1)# --",
	}
	for _, input := range benign {
		for _, r := range e.DetectAll(input) {
			if r.Severity >= security.SeverityHigh {
				t.Errorf("benign %q: got %s severity=%v (blocked), want < High", input, r.Name, r.Severity)
			}
		}
	}

	attacks := []struct {
		input       string
		minSeverity security.Severity
	}{
		{"' OR '1'='1", security.SeverityCritical},
		{"UNION SELECT * FROM users", security.SeverityCritical},
		{"1' AND 1=1 --", security.SeverityCritical},
		{"1') OR ('1'='1", security.SeverityCritical},
		{"admin'--", security.SeverityCritical},
		{"--select * from users", security.SeverityCritical},
		{"UNION SELECT CONCAT(0x7e,user(),0x7e)", security.SeverityCritical},
		{"<script>alert(1)</script>", security.SeverityHigh},
		{"<img onerror=alert(1)>", security.SeverityHigh},
		{"<div onmouseover=alert(1)>", security.SeverityHigh},
		{"eval(document.cookie)", security.SeverityHigh},
		{"javascript:eval('xss')", security.SeverityHigh},
		{"<?php system('id'); ?>", security.SeverityHigh},
		{"$(cat /etc/passwd)", security.SeverityCritical},
		{"|| nc -e /bin/sh", security.SeverityCritical},
		{"ls || cat /etc/passwd", security.SeverityCritical},
	}
	for _, tc := range attacks {
		got := security.SeverityLow
		for _, r := range e.DetectAll(tc.input) {
			if r.Severity > got {
				got = r.Severity
			}
		}
		if got < tc.minSeverity {
			t.Errorf("attack %q: max severity=%v, want >= %v", tc.input, got, tc.minSeverity)
		}
	}
}

// URL-encoded payloads must be caught by DetectRequest's decode-and-rescan.
func TestEncodedPayloads(t *testing.T) {
	e := security.NewEngine()
	RegisterAll(e)
	cases := []struct {
		url string
	}{
		{"http://x/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E"},
		{"http://x/api/login?u=1%27%20OR%20%271%27%3D%271"},
		{"http://x/api/search?q=%27%20OR%20%271%27%3D%271"},
		{"http://x/api/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"},
		{"http://x/api/search?q=..%2F..%2Fetc%2Fpasswd"},
	}
	for _, tc := range cases {
		r, _ := http.NewRequest("GET", tc.url, nil)
		blocked := false
		for _, res := range e.DetectRequest(r) {
			if res.Severity >= security.SeverityHigh {
				blocked = true
				break
			}
		}
		if !blocked {
			t.Errorf("encoded attack not blocked: %s", tc.url)
		}
	}
}
