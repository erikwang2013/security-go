// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var sstiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\{\{[^}]*__(?:class|mro|subclasses|globals|builtins)__[^}]*\}\}`),
	regexp.MustCompile(`(?i)\{\{[^}]*config[^}]*\}\}`),
	regexp.MustCompile(`(?i)\{\#[^}]*\#\}`),
}

// generic template markers are common in normal text (Vue/Handlebars/JS
// template literals, Java getClass tutorials): Medium, not blocking
var sstiMediumPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\{\{[^}]*\}\}`),
	regexp.MustCompile(`(?i)\$\{[^}]*\}`),
	regexp.MustCompile(`<%[^%]*%>`),
	regexp.MustCompile(`(?i)\.getClass\b`),
}

// SSTI detects Server-Side Template Injection attempts.
type SSTI struct{}

func (d *SSTI) Name() string {
	return "ssti"
}

func (d *SSTI) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, sstiPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "SSTI injection pattern detected: " + m,
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	if m, ok := security.FirstMatch(input, sstiMediumPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Suspicious template marker detected: " + m,
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
