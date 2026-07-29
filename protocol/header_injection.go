package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var headerInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`%0[dD]%0[aA]`),
	regexp.MustCompile(`\\r\\n`),
	regexp.MustCompile(`\r\n`),
	regexp.MustCompile(`(?i)%0d%0a(?:Set-Cookie|Location|Content-Length|Content-Type|Transfer-Encoding|X-):`),
}

type HeaderInjectionDetector struct{}

func (d HeaderInjectionDetector) Name() string {
	return "HTTP Header Injection"
}

func (d HeaderInjectionDetector) Detect(input string) *security.Result {
	for _, p := range headerInjectionPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityHigh,
				Message:  "HTTP header injection pattern detected: CRLF injection or header manipulation",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
