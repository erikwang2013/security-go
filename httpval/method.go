package httpval

import "github.com/bag/security-go"

var allowedMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"HEAD":    true,
	"OPTIONS": true,
	"PATCH":   true,
}

// Method validates the HTTP request method against a fixed whitelist.
type Method struct{}

// Name returns the detector name.
func (m *Method) Name() string {
	return "http_method"
}

// Detect checks whether the HTTP method is in the allowed list.
func (m *Method) Detect(input string) *security.Result {
	if !allowedMethods[input] {
		return &security.Result{
			Name:     m.Name(),
			Detected: true,
			Message:  "Invalid HTTP method: " + input,
			Severity: security.SeverityLow,
		}
	}
	return nil
}
