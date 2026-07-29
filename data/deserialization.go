package data

import (
	"regexp"

	"github.com/bag/security-go"
)

var deserPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)O:\d+:`),
	regexp.MustCompile(`(?i)C:\d+:`),
	regexp.MustCompile(`(?i)a:\d+:\{`),
	regexp.MustCompile(`(?i)(?:unserialize|__wakeup|__destruct|__toString|__call|__get|__set|__isset|__unset|__sleep)\s*\(`),
	regexp.MustCompile(`(?i)s:\d+:"`),
	regexp.MustCompile(`(?i)__PHP_Incomplete_Class`),
}

// Deserialization detects PHP deserialization attacks.
type Deserialization struct{}

// Name returns the detector name.
func (d *Deserialization) Name() string {
	return "deserialization"
}

// Detect checks input for PHP deserialization attack patterns.
func (d *Deserialization) Detect(input string) *security.Result {
	for _, p := range deserPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "PHP deserialization attack pattern detected: " + p.String(),
				Severity: security.SeverityCritical,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
