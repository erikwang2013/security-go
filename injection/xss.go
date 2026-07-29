package injection

import (
	"regexp"

	"github.com/bag/security-go"
)

var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`<script`),
	regexp.MustCompile(`</script>`),
	regexp.MustCompile(`on[a-z]+\s*=`),
	regexp.MustCompile(`javascript\s*:`),
	regexp.MustCompile(`<iframe`),
	regexp.MustCompile(`<embed`),
	regexp.MustCompile(`<object`),
	regexp.MustCompile(`<svg[^>]*onload`),
	regexp.MustCompile(`<img[^>]*onerror`),
	regexp.MustCompile(`<body[^>]*onload`),
	regexp.MustCompile(`<input[^>]*onfocus`),
	regexp.MustCompile(`expression\s*\(`),
	regexp.MustCompile(`url\s*\(\s*["']?\s*(?:javascript|data):`),
	regexp.MustCompile(`<link`),
	regexp.MustCompile(`<meta`),
	regexp.MustCompile(`eval\s*\(`),
	regexp.MustCompile(`document\.(?:write|cookie)`),
	regexp.MustCompile(`<base[^>]*href`),
	regexp.MustCompile(`fromCharCode\s*\(`),
	regexp.MustCompile(`&#x?[0-9a-f]+;?`),
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
