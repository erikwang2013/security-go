// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var csvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\s*=(?:cmd|HYPERLINK|DDE|IMPORTXML|IMPORTDATA|WEBSERVICE|IMPORTFEED)\s*\(`),
	regexp.MustCompile(`^\s*@(?:SUM|AVERAGE|COUNT|MAX|MIN|ROUND|IF|VLOOKUP|HLOOKUP)\s*\(`),
	regexp.MustCompile(`^\s*\+\s*(?:SUM|AVERAGE|COUNT|MAX|MIN)\s*\(`),
	regexp.MustCompile(`^\s*-\s*(?:SUM|AVERAGE|COUNT|MAX|MIN)\s*\(`),
	regexp.MustCompile(`^\s*=\s*\w+\+`),
}

// CSVInjection detects CSV/Excel formula injection attacks.
type CSVInjection struct{}

// Name returns the detector name.
func (c *CSVInjection) Name() string {
	return "csv_injection"
}

// Detect checks input for CSV formula injection patterns.
func (c *CSVInjection) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, csvPatterns); ok {
		return &security.Result{
			Name:     c.Name(),
			Detected: true,
			Message:  "CSV formula injection pattern detected: " + m,
			Severity: security.SeverityHigh,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: c.Name(), Detected: false}
}
