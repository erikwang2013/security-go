// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var requestSmugglingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Transfer-Encoding:\s*chunked.*\r\n.*Content-Length:`),
	regexp.MustCompile(`(?i)Transfer-Encoding:\s*.*,\s*chunked`),
	regexp.MustCompile(`(?i)Transfer-Encoding\s*:\s*chunked`),
	regexp.MustCompile(`(?i)Content-Length:\s*\d+.*\r\n.*Transfer-Encoding:`),
	regexp.MustCompile(`\x0bTransfer-Encoding`),
}

type RequestSmuggling struct{}

func (d *RequestSmuggling) Name() string {
	return "request_smuggling"
}

func (d *RequestSmuggling) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, requestSmugglingPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Severity: security.SeverityCritical,
			Message:  "HTTP request smuggling pattern detected: content-length / transfer-encoding conflict",
			Details: map[string]interface{}{
				"matched_pattern": m,
				"input":           input,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
