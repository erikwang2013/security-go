// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var requestSmugglingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Transfer-Encoding:\s*chunked.*\r\n.*Content-Length:`),
	regexp.MustCompile(`(?i)Transfer-Encoding:\s*.*,\s*chunked`),
	regexp.MustCompile(`(?i)Transfer-Encoding\s*:\s*chunked`),
	regexp.MustCompile(`(?i)Content-Length:\s*0.*\r\n.*Transfer-Encoding:`),
	regexp.MustCompile(`(?i)Transfer-encoding:\s*chunked`),
	regexp.MustCompile(`\x0bTransfer-Encoding`),
}

type RequestSmuggling struct{}

func (d RequestSmuggling) Name() string {
	return "request_smuggling"
}

func (d RequestSmuggling) Detect(input string) *security.Result {
	for _, p := range requestSmugglingPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityCritical,
				Message:  "HTTP request smuggling pattern detected: content-length / transfer-encoding conflict",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
