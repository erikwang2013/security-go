// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var xpathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+'?`),
	regexp.MustCompile(`(?i)'\s*(?:or|and)\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`\|.*/.*\|`),
}

// bare XPath functions are common in generic code ("count(", "length(")
var xpathMediumPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bstring-length\s*\(`),
	regexp.MustCompile(`(?i)\bcount\s*\(`),
}

// XPath detects XPath injection attempts.
type XPath struct{}

func (d *XPath) Name() string {
	return "xpath_injection"
}

func (d *XPath) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, xpathPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "XPath injection pattern detected: " + m,
			Severity: security.SeverityHigh,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	if m, ok := security.FirstMatch(input, xpathMediumPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Suspicious XPath function reference detected: " + m,
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
