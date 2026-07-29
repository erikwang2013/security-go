// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import (
	"regexp"

	"github.com/bag/security-go"
)

var websocketPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Upgrade:\s*websocket`),
	regexp.MustCompile(`(?i)Connection:\s*Upgrade`),
	regexp.MustCompile(`(?i)Sec-WebSocket-Key:\s*`),
	regexp.MustCompile(`ws://`),
	regexp.MustCompile(`wss://`),
	regexp.MustCompile(`(?i)Origin:\s*null.*Upgrade:\s*websocket`),
}

type WebSocket struct{}

func (d WebSocket) Name() string {
	return "websocket"
}

func (d WebSocket) Detect(input string) *security.Result {
	for _, p := range websocketPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Severity: security.SeverityMedium,
				Message:  "WebSocket hijacking pattern detected: potential cross-site WebSocket hijack",
				Details: map[string]interface{}{
					"matched_pattern": p.String(),
					"input":           input,
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
