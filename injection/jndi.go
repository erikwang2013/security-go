// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var jndiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\$\{jndi:`),
	regexp.MustCompile(`(?i)\$\{lower:j\}`),
	regexp.MustCompile(`(?i)\$\{upper:j\}`),
	regexp.MustCompile(`(?i)\$\{env:`),
	regexp.MustCompile(`(?i)\$\{(?:sys|java):`),
	regexp.MustCompile(`(?i)\$\{::-j\}`),
	regexp.MustCompile(`(?i)\$\{date:`),
	regexp.MustCompile(`(?i)\$\{(?:lower|upper):[^}]*[jJ][nN][dD][iI]`),
	regexp.MustCompile(`(?i)ldaps?://`),
	regexp.MustCompile(`(?i)rmi://`),
	regexp.MustCompile(`(?i)dns://`),
}

// JNDI detects JNDI/Log4Shell injection attempts.
type JNDI struct{}

func (d *JNDI) Name() string {
	return "jndi_injection"
}

func (d *JNDI) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, jndiPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "JNDI/Log4Shell injection pattern detected: " + m,
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
