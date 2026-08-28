// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var nosqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"?\$(?:ne|gt|gte|lt|lte|eq|in|nin|regex|where|or|and|nor|not|exists|type|mod|text|search|expr)\b"?:?\s*["'\[]`),
	regexp.MustCompile(`(?i)\{.*"\$(?:ne|gt|regex|where)"\s*:`),
	regexp.MustCompile(`(?i)"\$where"\s*:\s*"`),
}

// NoSQL detects NoSQL injection attempts (MongoDB operators, $where).
type NoSQL struct{}

func (d *NoSQL) Name() string {
	return "nosql_injection"
}

func (d *NoSQL) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, nosqlPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "NoSQL injection pattern detected: " + m,
			Severity: security.SeverityHigh,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
