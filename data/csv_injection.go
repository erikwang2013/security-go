package data

import (
	"regexp"

	"github.com/bag/security-go"
)

var csvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\s*=(?:cmd|HYPERLINK|DDE|IMPORTXML|IMPORTDATA|WEBSERVICE|IMPORTFEED)\s*\(`),
	regexp.MustCompile(`^\s*@(?:SUM|AVERAGE|COUNT|MAX|MIN|ROUND|IF|VLOOKUP|HLOOKUP)\s*\(`),
	regexp.MustCompile(`^\s*\+\s*(?:SUM|AVERAGE|COUNT|MAX|MIN)\s*\(`),
	regexp.MustCompile(`^\s*-\s*(?:SUM|AVERAGE|COUNT|MAX|MIN)\s*\(`),
	regexp.MustCompile(`^\s*=\s*\w+\+`),
}

// CSVInjectionDetector detects CSV/Excel formula injection attacks.
type CSVInjectionDetector struct{}

// Name returns the detector name.
func (c *CSVInjectionDetector) Name() string {
	return "csv_injection"
}

// Detect checks input for CSV formula injection patterns.
func (c *CSVInjectionDetector) Detect(input string) *security.Result {
	for _, p := range csvPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     c.Name(),
				Detected: true,
				Message:  "CSV formula injection pattern detected: " + p.String(),
				Severity: security.SeverityHigh,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: c.Name(), Detected: false}
}
