package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var corsPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Origin:\s*null`),
	regexp.MustCompile(`(?i)Access-Control-Allow-Origin:\s*\*`),
	regexp.MustCompile(`(?i)Access-Control-Allow-Credentials:\s*true`),
}

type CORSDetector struct{}

func (d CORSDetector) Name() string {
	return "CORS Bypass"
}

func (d CORSDetector) Detect(input string) *security.Result {
	for _, p := range corsPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityMedium,
				Message:  "CORS bypass pattern detected: overly permissive CORS configuration",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
