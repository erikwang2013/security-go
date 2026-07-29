package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var openRedirectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*//[^/]`),
	regexp.MustCompile(`(?i)^\s*(?:javascript|data|vbscript):`),
	regexp.MustCompile(`(?i)redirect(?:ed)?(?:_to|_url)?\s*=\s*(?:https?:)?//`),
	regexp.MustCompile(`(?i)(?:dest|target|next|return|goto|url)\s*=\s*(?:https?:)?//`),
	regexp.MustCompile(`(?i)%2[fF].*%2[fF]`),
}

type OpenRedirectDetector struct{}

func (d OpenRedirectDetector) Name() string {
	return "Open Redirect"
}

func (d OpenRedirectDetector) Detect(input string) *security.Result {
	for _, p := range openRedirectPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityMedium,
				Message:  "Open redirect pattern detected: external or protocol-based redirect",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
