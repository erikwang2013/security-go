// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var mailPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\n\s*(?:Bcc|Cc|To|From|Reply-To|Subject|Content-Type|MIME-Version):\s*`),
	regexp.MustCompile(`(?i)%0[dD]%0[aA](?:Bcc|Cc|To|From|Reply-To):`),
	regexp.MustCompile(`(?i)\r\n(?:Bcc|Cc|To|From|Reply-To):`),
	regexp.MustCompile(`(?i)Content-Type:\s*multipart/`),
	regexp.MustCompile(`(?i)boundary=`),
}

// MailHeader detects mail header injection attacks.
type MailHeader struct{}

// Name returns the detector name.
func (m *MailHeader) Name() string {
	return "mail_header"
}

// Detect checks input for mail header injection patterns.
func (m *MailHeader) Detect(input string) *security.Result {
	if match, ok := security.FirstMatch(input, mailPatterns); ok {
		return &security.Result{
			Name:     m.Name(),
			Detected: true,
			Message:  "Mail header injection pattern detected: " + match,
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"pattern": match,
			},
		}
	}
	return &security.Result{Name: m.Name(), Detected: false}
}
