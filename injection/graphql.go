package injection

import (
	"regexp"

	"github.com/bag/security-go"
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
	return "GraphQL"
}

func (d *GraphQL) Detect(input string) *security.Result {
	for _, p := range graphqlPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "GraphQL injection/introspection pattern detected: " + p.String(),
				Severity: security.SeverityMedium,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
