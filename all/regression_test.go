// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package all

import (
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
