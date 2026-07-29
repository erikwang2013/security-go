package httpval

import (
	"mime"

	"github.com/bag/security-go"
)

// ContentType validates the request Content-Type header against a whitelist.
type ContentType struct {
	Allowed map[string]bool
}

// NewContentType creates a ContentType detector with the given allowed types.
func NewContentType(allowed []string) *ContentType {
	ct := &ContentType{Allowed: make(map[string]bool)}
	for _, a := range allowed {
		ct.Allowed[a] = true
	}
	return ct
}

// Name returns the detector name.
func (c *ContentType) Name() string {
	return "content_type"
}

// Detect parses the Content-Type header and checks it against the allowed map.
func (c *ContentType) Detect(input string) *security.Result {
	mt, _, err := mime.ParseMediaType(input)
	if err != nil {
		return nil
	}
	if len(c.Allowed) == 0 || c.Allowed[mt] {
		return nil
	}
	return &security.Result{
		Name:     c.Name(),
		Detected: true,
		Message:  "Content-Type not allowed: " + mt,
		Severity: security.SeverityLow,
	}
}
