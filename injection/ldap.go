// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var ldapPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\(\s*(?:\||&|!|=|>=?|<=?|~=)`),
	regexp.MustCompile(`(?i)\(\s*objectClass\s*=\s*\*?\)`),
	regexp.MustCompile(`(?i)\(\s*cn\s*=\s*\*\)`),
	regexp.MustCompile(`\(\s*\|\(`),
	regexp.MustCompile(`\(\s*&\(`),
	regexp.MustCompile(`\(\s*!\s*\(\s*`),
	regexp.MustCompile(`%28(?:\||&|\*|%29)`),
}

// LDAP detects LDAP injection attempts.
type LDAP struct{}

func (d *LDAP) Name() string {
	return "ldap_injection"
}

func (d *LDAP) Detect(input string) *security.Result {
	for _, p := range ldapPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "LDAP injection pattern detected: " + p.String(),
				Severity: security.SeverityHigh,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
