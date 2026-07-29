package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var hostHeaderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Host:\s*.*\r\n`),
	regexp.MustCompile(`(?i)X-Forwarded-(?:Host|Server):\s*`),
	regexp.MustCompile(`(?i)X-(?:Original|Rewrite)-URL:\s*`),
}

type HostHeaderDetector struct{}

func (d HostHeaderDetector) Name() string {
	return "Host Header Attack"
}

func (d HostHeaderDetector) Detect(input string) *security.Result {
	for _, p := range hostHeaderPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityMedium,
				Message:  "Host header attack pattern detected: malicious host or forwarding header",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
