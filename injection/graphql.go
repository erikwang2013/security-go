// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var graphqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b__schema\b`),
	regexp.MustCompile(`(?i)\b__type\b`),
	regexp.MustCompile(`(?i)\b__typename\b`),
	regexp.MustCompile(`\{[^}]*\{[^}]*\{[^}]*\{[^}]*\{[^}]*\{`),
	regexp.MustCompile(`(?i)\bmutation\s*\{`),
}

// GraphQL detects GraphQL injection/introspection attempts.
type GraphQL struct{}

func (d *GraphQL) Name() string {
	return "graphql_injection"
}

func (d *GraphQL) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, graphqlPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "GraphQL injection/introspection pattern detected: " + m,
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
