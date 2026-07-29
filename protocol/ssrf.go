// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var ssrfPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)https?://(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)`),
	regexp.MustCompile(`(?i)https?://localhost`),
	regexp.MustCompile(`(?i)https?://\[?::1\]?`),
	regexp.MustCompile(`(?i)https?://0\.0\.0\.0`),
	regexp.MustCompile(`(?i)(?:gopher|dict|file|ftp)://`),
	regexp.MustCompile(`(?i)169\.254\.169\.254`),
	regexp.MustCompile(`(?i)/latest/meta-data`),
	regexp.MustCompile(`(?i)metadata\.google\.internal`),
}

type SSRF struct{}

func (d SSRF) Name() string {
	return "ssrf"
}

func (d SSRF) Detect(input string) *security.Result {
	for _, p := range ssrfPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityHigh,
				Message:  "SSRF attack pattern detected: internal or restricted URL target",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
