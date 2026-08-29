// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var pathTraversalPatterns = []*regexp.Regexp{
	// encoded forms and wrappers are deliberate evasion, and real traversal
	// attacks carry the target path (/etc/passwd, file:///...): all High
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

// bare `../` / `..\` is ubiquitous in relative URLs and normal text
// (q=2024/../2025, "../img/logo.png"): Medium, not blocking
var pathTraversalMediumPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\./`),
	regexp.MustCompile(`\.\.\\`),
}

// PathTraversal is a detector for path traversal attacks.
type PathTraversal struct{}

// Name returns the detector name.
func (d *PathTraversal) Name() string {
	return "path_traversal"
}

// Detect checks the input for path traversal patterns.
func (d *PathTraversal) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, pathTraversalPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Path traversal attack detected: " + m,
			Severity: security.SeverityHigh,
		}
	}
	if m, ok := security.FirstMatch(input, pathTraversalMediumPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Suspicious path component detected: " + m,
			Severity: security.SeverityMedium,
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
