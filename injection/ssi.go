// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var ssiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`<!--\s*#(?:exec|include|echo|config|fsize|flastmod|printenv|set|if)\b`),
	regexp.MustCompile(`<!--\s*#exec\s+(?:cmd|cgi)=`),
	regexp.MustCompile(`<!--\s*#include\s+(?:file|virtual)=`),
	regexp.MustCompile(`<!--\s*#echo\s+var=`),
}

// SSI detects Server-Side Include injection attempts.
type SSI struct{}

func (d *SSI) Name() string {
	return "ssi_injection"
}

func (d *SSI) Detect(input string) *security.Result {
	for _, p := range ssiPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "SSI injection pattern detected: " + p.String(),
				Severity: security.SeverityHigh,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
