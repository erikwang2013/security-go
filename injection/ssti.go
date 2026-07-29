package injection

import (
	"regexp"

	"github.com/bag/security-go"
)

var sstiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\{\{[^}]*\}\}`),
	regexp.MustCompile(`(?i)\$\{[^}]*\}`),
	regexp.MustCompile(`<%[^%]*%>`),
	regexp.MustCompile(`(?i)\{\#[^}]*\#\}`),
	regexp.MustCompile(`(?i)\{\{[^}]*__(?:class|mro|subclasses|globals|builtins)__[^}]*\}\}`),
	regexp.MustCompile(`(?i)\{\{[^}]*config[^}]*\}\}`),
	regexp.MustCompile(`(?i)\.getClass\b`),
}

// SSTI detects Server-Side Template Injection attempts.
type SSTI struct{}

func (d *SSTI) Name() string {
	return "ssti"
}

func (d *SSTI) Detect(input string) *security.Result {
	for _, p := range sstiPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "SSTI injection pattern detected: " + p.String(),
				Severity: security.SeverityCritical,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
