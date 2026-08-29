// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var deserPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)O:\d+:`),
	regexp.MustCompile(`(?i)C:\d+:`),
	regexp.MustCompile(`(?i)a:\d+:\{`),
	regexp.MustCompile(`(?i)s:\d+:"`),
	regexp.MustCompile(`(?i)__PHP_Incomplete_Class`),
}

// function names are common in PHP tutorials (unserialize(, __toString)
var deserMediumPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:unserialize|__wakeup|__destruct|__toString|__call|__get|__set|__isset|__unset|__sleep)\s*\(`),
}

// Deserialization detects PHP deserialization attacks.
type Deserialization struct{}

// Name returns the detector name.
func (d *Deserialization) Name() string {
	return "deserialization"
}

// Detect checks input for PHP deserialization attack patterns.
func (d *Deserialization) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, deserPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "PHP deserialization attack pattern detected: " + m,
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	if m, ok := security.FirstMatch(input, deserMediumPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Suspicious deserialization function reference detected: " + m,
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
