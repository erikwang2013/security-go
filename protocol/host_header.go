// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var hostHeaderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Host:\s*.*\r\n`),
	regexp.MustCompile(`(?i)X-Forwarded-(?:Host|Server):\s*`),
	regexp.MustCompile(`(?i)X-(?:Original|Rewrite)-URL:\s*`),
}

type HostHeader struct{}

func (d HostHeader) Name() string {
	return "host_header"
}

func (d HostHeader) Detect(input string) *security.Result {
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
