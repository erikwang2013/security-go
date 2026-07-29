package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var xxePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)\s+["']`),
	regexp.MustCompile(`(?i)<!ENTITY\s+%\s+\w+\s+`),
	regexp.MustCompile(`(?i)<!DOCTYPE\s+\w+\s+\[`),
	regexp.MustCompile(`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["'](?:file|php|http|ftp|gopher|dict|data|expect)://`),
	regexp.MustCompile(`(?i)%\w+;`),
	regexp.MustCompile(`(?i)&[a-z]+;`),
}

type XXE struct{}

func (d XXE) Name() string {
	return "xxe"
}

func (d XXE) Detect(input string) *security.Result {
	for _, p := range xxePatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityHigh,
				Message:  "XXE attack pattern detected: XML external entity injection",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
