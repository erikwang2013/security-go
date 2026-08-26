// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script`),
	regexp.MustCompile(`(?i)</script>`),
	regexp.MustCompile(`(?i)on[a-z]+\s*=`),
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
	regexp.MustCompile(`(?i)eval\s*\(`),
	regexp.MustCompile(`(?i)document\.(?:write|cookie)`),
	regexp.MustCompile(`(?i)<base[^>]*href`),
	regexp.MustCompile(`(?i)fromCharCode\s*\(`),
	regexp.MustCompile(`(?i)&#x?[0-9a-f]+;?`),
}

// XSS detects Cross-Site Scripting injection attempts.
type XSS struct{}

func (d *XSS) Name() string {
	return "xss"
}

func (d *XSS) Detect(input string) *security.Result {
	for _, p := range xssPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "XSS injection pattern detected: " + p.String(),
				Severity: security.SeverityHigh,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
