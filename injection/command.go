// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var commandPatterns = []*regexp.Regexp{
	regexp.MustCompile("`[^`]+`"),
	regexp.MustCompile(`\$\([^)]*\)`),
	regexp.MustCompile(`\|\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)`),
	regexp.MustCompile(`(?i)/dev/tcp/`),
	regexp.MustCompile(`(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(`),
	regexp.MustCompile(`&&\s*(?:cat|ls|id|whoami|wget|curl)`),
	regexp.MustCompile(`;\s*(?:cat|ls|id|whoami)`),
	regexp.MustCompile(`\|\|`),
	regexp.MustCompile(`(?i)%0a`),
	regexp.MustCompile(`(?i)\bping\s+-c`),
	regexp.MustCompile(`(?i)\bnslookup\s+`),
	regexp.MustCompile(`>/dev/null`),
}

// Command detects command injection attempts.
type Command struct{}

func (d *Command) Name() string {
	return "command_injection"
}

func (d *Command) Detect(input string) *security.Result {
	for _, p := range commandPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "Command injection pattern detected: " + p.String(),
				Severity: security.SeverityCritical,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
