// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script`),
	regexp.MustCompile(`(?i)</script>`),
	// event handler only counts inside an HTML tag; bare `onxxx=` in plain
	// text (e.g. "donation=5") no longer triggers
	regexp.MustCompile(`(?i)<[a-z][^>]*\s+on[a-z]+\s*=`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)<iframe`),
	regexp.MustCompile(`(?i)<embed`),
	regexp.MustCompile(`(?i)<object`),
	regexp.MustCompile(`(?i)<svg[^>]*onload`),
	regexp.MustCompile(`(?i)<img[^>]*onerror`),
	regexp.MustCompile(`(?i)<body[^>]*onload`),
	regexp.MustCompile(`(?i)<input[^>]*onfocus`),
	regexp.MustCompile(`(?i)expression\s*\(`),
	regexp.MustCompile(`(?i)url\s*\(\s*["']?\s*(?:javascript|data):`),
	regexp.MustCompile(`(?i)<link`),
	regexp.MustCompile(`(?i)<meta`),
	regexp.MustCompile(`(?i)document\.(?:write|cookie)`),
	regexp.MustCompile(`(?i)<base[^>]*href`),
	regexp.MustCompile(`(?i)fromCharCode\s*\(`),
	regexp.MustCompile(`(?i)&#x?[0-9a-f]+;?`),
}

var xssEvalPattern = regexp.MustCompile(`(?i)eval\s*\(`)

// XSS detects Cross-Site Scripting injection attempts.
type XSS struct{}

func (d *XSS) Name() string {
	return "xss"
}

func (d *XSS) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, xssPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "XSS injection pattern detected: " + m,
			Severity: security.SeverityHigh,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	// bare eval() without any other XSS signal is suspicious but not an
	// active payload: Medium (logged, not blocking)
	if m := xssEvalPattern.String(); xssEvalPattern.MatchString(input) {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "XSS eval() usage detected: " + m,
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
