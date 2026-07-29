package file

import (
	"regexp"

	"github.com/bag/security-go"
)

var pathTraversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\./`),
	regexp.MustCompile(`\.\.\\`),
	regexp.MustCompile(`%2e%2e[/\\]`),
	regexp.MustCompile(`%252e%252e[/\\]`),
	regexp.MustCompile(`(?i)\.\.%2f`),
	regexp.MustCompile(`(?i)\.\.%5c`),
	regexp.MustCompile(`(?i)php://filter`),
	regexp.MustCompile(`(?i)php://input`),
	regexp.MustCompile(`(?i)data://`),
	regexp.MustCompile(`(?i)expect://`),
	regexp.MustCompile(`(?i)phar://`),
	regexp.MustCompile(`(?i)zip://`),
	regexp.MustCompile(`(?i)file:///`),
	regexp.MustCompile(`/etc/(?:passwd|shadow|hosts|group)`),
	regexp.MustCompile(`(?i)C:\\Windows\\(?:System32|win\.ini)`),
	regexp.MustCompile(`%00`),
	regexp.MustCompile(`\x00`),
}

// PathTraversal is a detector for path traversal attacks.
type PathTraversal struct{}

// Name returns the detector name.
func (d *PathTraversal) Name() string {
	return "Path Traversal"
}

// Detect checks the input for path traversal patterns.
func (d *PathTraversal) Detect(input string) *security.Result {
	for _, p := range pathTraversalPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "Path traversal attack detected: " + p.String(),
				Severity: security.SeverityHigh,
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
