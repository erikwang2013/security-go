// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var openRedirectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*//[^/]`),
	regexp.MustCompile(`(?i)^\s*(?:javascript|data|vbscript):`),
	regexp.MustCompile(`(?i)redirect(?:ed)?(?:_to|_url)?\s*=\s*(?:https?:)?//`),
	regexp.MustCompile(`(?i)(?:dest|target|next|return|goto|url)\s*=\s*(?:https?:)?//`),
	regexp.MustCompile(`(?i)%2[fF].*%2[fF]`),
}

type OpenRedirect struct{}

func (d *OpenRedirect) Name() string {
	return "open_redirect"
}

func (d *OpenRedirect) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, openRedirectPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Severity: security.SeverityMedium,
			Message:  "Open redirect pattern detected: external or protocol-based redirect",
			Details: map[string]interface{}{
				"matched_pattern": m,
				"input":           input,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
