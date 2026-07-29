package data

import (
	"regexp"

	"github.com/bag/security-go"
)

var mailPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\n\s*(?:Bcc|Cc|To|From|Reply-To|Subject|Content-Type|MIME-Version):\s*`),
	regexp.MustCompile(`(?i)%0[dD]%0[aA](?:Bcc|Cc|To|From|Reply-To):`),
	regexp.MustCompile(`(?i)\r\n(?:Bcc|Cc|To|From|Reply-To):`),
	regexp.MustCompile(`(?i)Content-Type:\s*multipart/`),
	regexp.MustCompile(`(?i)boundary=`),
}

// MailHeaderDetector detects mail header injection attacks.
type MailHeaderDetector struct{}

// Name returns the detector name.
func (m *MailHeaderDetector) Name() string {
	return "mail_header_injection"
}

// Detect checks input for mail header injection patterns.
func (m *MailHeaderDetector) Detect(input string) *security.Result {
	for _, p := range mailPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     m.Name(),
				Detected: true,
				Message:  "Mail header injection pattern detected: " + p.String(),
				Severity: security.SeverityCritical,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: m.Name(), Detected: false}
}
