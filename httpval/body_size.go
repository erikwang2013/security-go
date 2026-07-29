package httpval

import (
	"strconv"

	"github.com/bag/security-go"
)

// BodySize validates the request body size against a maximum limit.
type BodySize struct {
	MaxSize int64
}

// NewBodySize creates a BodySize detector. If maxSize <= 0, defaults to 10MB.
func NewBodySize(maxSize int64) *BodySize {
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024
	}
	return &BodySize{MaxSize: maxSize}
}

// Name returns the detector name.
func (b *BodySize) Name() string {
	return "body_size"
}

// Detect parses input as an int64 body size and checks it against the limit.
// If parsing fails, no detection is returned.
func (b *BodySize) Detect(input string) *security.Result {
	size, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return nil
	}
	if size > b.MaxSize {
		return &security.Result{
			Name:     b.Name(),
			Detected: true,
			Message:  "Request body exceeds maximum size",
			Severity: security.SeverityLow,
		}
	}
	return nil
}
