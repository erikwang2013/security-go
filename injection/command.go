// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var commandPatterns = []*regexp.Regexp{
	regexp.MustCompile("`[^`]+`"),
	regexp.MustCompile(`\$\([^)]*\)`),
	regexp.MustCompile(`(?i)\|\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)`),
	regexp.MustCompile(`(?i)/dev/tcp/`),
	// require a quoted or variable argument: bare `exec(` in plain text
	// (e.g. "python exec(") is a function call, not injection
	regexp.MustCompile(`(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:['"]|\$|[0-9])`),
	regexp.MustCompile(`(?i)&&\s*(?:cat|ls|id|whoami|wget|curl)`),
	regexp.MustCompile(`(?i);\s*(?:cat|ls|id|whoami)`),
	// bare `||` in normal text ("a || b") is not injection; require a
	// command word after it, matching the `|` / `&&` / `;` siblings above
	regexp.MustCompile(`(?i)\|\|\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|echo|rm|mv|chmod|cp|touch|kill|mkdir|pkill|reboot|shutdown)`),
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
	if m, ok := security.FirstMatch(input, commandPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Command injection pattern detected: " + m,
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
