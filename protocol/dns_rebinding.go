package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var dnsRebindingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Host:\s*(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)`),
	regexp.MustCompile(`(?i)Host:\s*localhost`),
	regexp.MustCompile(`(?i)Host:\s*\[?::1\]?`),
	regexp.MustCompile(`(?i)Host:\s*\w+$`),
	regexp.MustCompile(`(?i)Host:\s*\d+\.\d+\.\d+\.\d+`),
}

type DNSRebinding struct{}

func (d DNSRebinding) Name() string {
	return "dns_rebinding"
}

func (d DNSRebinding) Detect(input string) *security.Result {
	for _, p := range dnsRebindingPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityHigh,
				Message:  "DNS rebinding pattern detected: Host header targeting internal network",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
