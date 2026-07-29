// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import (
	"regexp"

	"github.com/bag/security-go"
)

var leakPatterns = []struct {
	pattern *regexp.Regexp
	name    string
}{
	{regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`), "Credit Card Number"},
	{regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), "AWS Access Key"},
	{regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`), "Private Key"},
	{regexp.MustCompile(`-----BEGIN\s+CERTIFICATE-----`), "Certificate"},
	{regexp.MustCompile(`(?i)(?:jdbc|mysql|postgres|mongodb|redis|sqlserver)://[^/\s]+`), "DB Connection String"},
	{regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['"]?\w+`), "API Key"},
	{regexp.MustCompile(`(?i)(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['"]?\w+`), "Access Token"},
	{regexp.MustCompile(`(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`), "JWT Token"},
	{regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]`), "Password in plaintext"},
	{regexp.MustCompile(`(?i)sk-[A-Za-z0-9]{32,}`), "OpenAI API Key"},
	{regexp.MustCompile(`(?i)github[_-]?(?:token|pat)\s*[:=]\s*['"]?[A-Za-z0-9_]+`), "GitHub Token"},
	{regexp.MustCompile(`(?i)ghp_[A-Za-z0-9]{36}`), "GitHub Personal Access Token"},
}

// SensitiveDataLeak is a detector for sensitive data leaks.
type SensitiveDataLeak struct{}

// Name returns the detector name.
func (d *SensitiveDataLeak) Name() string {
	return "data_leak"
}

// Detect checks the input for sensitive data patterns.
func (d *SensitiveDataLeak) Detect(input string) *security.Result {
	for _, lp := range leakPatterns {
		if lp.pattern.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "Sensitive data detected: " + lp.name,
				Severity: security.SeverityCritical,
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
