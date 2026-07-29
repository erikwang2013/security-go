package httpval

import (
	"net/url"
	"strings"

	"github.com/bag/security-go"
)

// CSRFOrigin validates the Origin header against a configured host and allowlist.
type CSRFOrigin struct {
	Host      string
	AllowList []string
}

// Name returns the detector name.
func (c *CSRFOrigin) Name() string {
	return "csrf_origin"
}

// Detect parses the Origin header and compares it against the configured host
// and allowlist. An empty origin returns no detection.
func (c *CSRFOrigin) Detect(input string) *security.Result {
	if input == "" {
		return nil
	}
	u, err := url.Parse(input)
	if err != nil {
		return nil
	}
	host := u.Host
	if host == "" {
		host = u.Hostname()
	}
	if strings.EqualFold(host, c.Host) {
		return nil
	}
	for _, allowed := range c.AllowList {
		if strings.EqualFold(host, allowed) {
			return nil
		}
	}
	return &security.Result{
		Name:     c.Name(),
		Detected: true,
		Message:  "CSRF origin mismatch: " + host,
		Severity: security.SeverityMedium,
	}
}
