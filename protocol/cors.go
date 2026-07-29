// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var corsPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Origin:\s*null`),
	regexp.MustCompile(`(?i)Access-Control-Allow-Origin:\s*\*`),
	regexp.MustCompile(`(?i)Access-Control-Allow-Credentials:\s*true`),
}

type CORS struct{}

func (d CORS) Name() string {
	return "cors"
}

func (d CORS) Detect(input string) *security.Result {
	for _, p := range corsPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityMedium,
				Message:  "CORS bypass pattern detected: overly permissive CORS configuration",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
