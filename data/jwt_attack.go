// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/erikwang2013/security-go"
)

// JWTAttack detects JWT-based attacks without using regex.
type JWTAttack struct{}

// Name returns the detector name.
func (j *JWTAttack) Name() string {
	return "jwt_attack"
}

// Detect checks a JWT token for attack indicators:
//   - alg: "none" in header
//   - kid containing path traversal (../ or ..\)
//   - three parts with empty signature
func (j *JWTAttack) Detect(input string) *security.Result {
	parts := strings.Split(strings.TrimSpace(input), ".")
	if len(parts) < 2 {
		return &security.Result{Name: j.Name(), Detected: false}
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		return &security.Result{Name: j.Name(), Detected: false}
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return &security.Result{Name: j.Name(), Detected: false}
	}

	// Check alg: "none"
	if alg, ok := header["alg"].(string); ok && strings.EqualFold(alg, "none") {
		return &security.Result{
			Name:     j.Name(),
			Detected: true,
			Message:  "JWT token uses alg=none, allowing signature bypass",
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"reason": "alg_none",
				"alg":    alg,
			},
		}
	}

	// Check kid for path traversal
	if kid, ok := header["kid"].(string); ok && (strings.Contains(kid, "../") || strings.Contains(kid, `..\`)) {
		return &security.Result{
			Name:     j.Name(),
			Detected: true,
			Message:  "JWT kid contains path traversal sequence",
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"reason": "kid_path_traversal",
				"kid":    kid,
			},
		}
	}

	// Check three parts with empty signature
	if len(parts) == 3 && parts[2] == "" {
		return &security.Result{
			Name:     j.Name(),
			Detected: true,
			Message:  "JWT token has three parts but empty signature",
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"reason": "empty_signature",
			},
		}
	}

	return &security.Result{Name: j.Name(), Detected: false}
}
