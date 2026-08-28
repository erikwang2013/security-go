// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var xxePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)\s+["']`),
	regexp.MustCompile(`(?i)<!ENTITY\s+%\s+\w+\s+`),
	regexp.MustCompile(`(?i)<!DOCTYPE\s+\w+\s+\[`),
	regexp.MustCompile(`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["'](?:file|php|http|ftp|gopher|dict|data|expect)://`),
	regexp.MustCompile(`(?i)%\w+;`),
	regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
}

type XXE struct{}

func (d *XXE) Name() string {
	return "xxe"
}

func (d *XXE) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, xxePatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Severity: security.SeverityHigh,
			Message:  "XXE attack pattern detected: XML external entity injection",
			Details: map[string]interface{}{
				"matched_pattern": m,
				"input":           input,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
