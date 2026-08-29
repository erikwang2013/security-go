// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var protoPollutionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)__defineGetter__\s*\(`),
	regexp.MustCompile(`(?i)__defineSetter__\s*\(`),
	regexp.MustCompile(`(?i)__lookupGetter__\s*\(`),
	regexp.MustCompile(`(?i)__lookupSetter__\s*\(`),
	regexp.MustCompile(`(?i)\[\[__proto__\]\]`),
	regexp.MustCompile(`\.__proto__\s*=`),
	regexp.MustCompile(`(?i)\bconstructor\b\s*\[\s*['"]prototype['"]\s*\]`),
}

// bare JSON object keys ("constructor": x) are common in legit JSON
// documents/config: Medium, not blocking
var protoPollutionMediumPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)["']__proto__["']\s*:`),
	regexp.MustCompile(`(?i)["']constructor["']\s*:`),
	regexp.MustCompile(`(?i)["']prototype["']\s*:`),
}

// PrototypePollution detects JavaScript prototype pollution attacks.
type PrototypePollution struct{}

// Name returns the detector name.
func (p *PrototypePollution) Name() string {
	return "prototype_pollution"
}

// Detect checks input for JavaScript prototype pollution patterns.
func (p *PrototypePollution) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, protoPollutionPatterns); ok {
		return &security.Result{
			Name:     p.Name(),
			Detected: true,
			Message:  "JavaScript prototype pollution pattern detected: " + m,
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	if m, ok := security.FirstMatch(input, protoPollutionMediumPatterns); ok {
		return &security.Result{
			Name:     p.Name(),
			Detected: true,
			Message:  "Suspicious prototype key reference detected: " + m,
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: p.Name(), Detected: false}
}
