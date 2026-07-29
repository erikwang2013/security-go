// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"testing"

	"github.com/erikwang2013/security-go"
	"github.com/erikwang2013/security-go/storage"
)

// ---- BodySize ----

func TestBodySizeDefaults(t *testing.T) {
	b := NewBodySize(0)
	if b.MaxSize != 10*1024*1024 {
		t.Fatalf("expected default MaxSize=10MB, got %d", b.MaxSize)
	}
}

func TestBodySizeNegativeDefaults(t *testing.T) {
	b := NewBodySize(-1)
	if b.MaxSize != 10*1024*1024 {
		t.Fatalf("expected default MaxSize=10MB for negative input, got %d", b.MaxSize)
	}
}

func TestBodySizeExplicitValue(t *testing.T) {
	b := NewBodySize(5000)
	if b.MaxSize != 5000 {
		t.Fatalf("expected MaxSize=5000, got %d", b.MaxSize)
	}
}

func TestBodySizeDetectUnderLimit(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("512")
	if r.Detected {
		t.Fatal("expected no detection for body under limit")
	}
}

func TestBodySizeDetectOverLimit(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("2048")
	if !r.Detected {
		t.Fatal("expected detection for body over limit")
	}
	if r.Severity != security.SeverityLow {
		t.Fatalf("expected SeverityLow, got %v", r.Severity)
	}
}

func TestBodySizeDetectInvalidInput(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("not-a-number")
	if r.Detected {
		t.Fatal("expected no detection for invalid numeric input")
	}
}

func TestBodySizeDetectAtBoundary(t *testing.T) {
	b := NewBodySize(1024)
	r := b.Detect("1024")
	if r.Detected {
		t.Fatal("expected no detection at exact boundary")
	}
}

func TestBodySizeName(t *testing.T) {
	b := NewBodySize(1024)
	if b.Name() != "body_size" {
		t.Fatalf("expected name 'body_size', got %s", b.Name())
	}
}

// ---- ContentType ----

func TestContentTypeAllowed(t *testing.T) {
	c := NewContentType([]string{"application/json", "text/plain"})
	r := c.Detect("application/json")
	if r.Detected {
		t.Fatal("expected application/json to be allowed")
	}
}

func TestContentTypeDenied(t *testing.T) {
	c := NewContentType([]string{"application/json"})
	r := c.Detect("text/html")
	if !r.Detected {
		t.Fatal("expected text/html to be denied")
	}
}

func TestContentTypeEmptyAllowList(t *testing.T) {
	c := NewContentType([]string{})
	r := c.Detect("application/json")
	if !r.Detected {
		t.Fatal("expected detection when AllowList is empty (deny-all)")
	}
}

func TestContentTypeNilAllowList(t *testing.T) {
	c := NewContentType(nil)
	r := c.Detect("application/json")
	if !r.Detected {
		t.Fatal("expected detection when AllowList is nil (deny-all)")
	}
}

func TestContentTypeInvalidInput(t *testing.T) {
	c := NewContentType([]string{"application/json"})
	r := c.Detect("not a valid content-type")
	if r.Detected {
		t.Fatal("expected no detection for unparseable content-type")
	}
}

func TestContentTypeWithParams(t *testing.T) {
	c := NewContentType([]string{"application/json"})
	r := c.Detect("application/json; charset=utf-8")
	if r.Detected {
		t.Fatal("expected application/json (with params) to be allowed")
	}
}

func TestContentTypeName(t *testing.T) {
	c := NewContentType([]string{"application/json"})
	if c.Name() != "content_type" {
		t.Fatalf("expected name 'content_type', got %s", c.Name())
	}
}

// ---- CSRFOrigin ----

func TestCSRFOriginEmpty(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("")
	if r.Detected {
		t.Fatal("expected no detection for empty origin")
	}
}

func TestCSRFOriginMatchingHost(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("https://example.com/path")
	if r.Detected {
		t.Fatal("expected no detection for matching host origin")
	}
}

func TestCSRFOriginMatchingHostCaseInsensitive(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("https://EXAMPLE.COM/path")
	if r.Detected {
		t.Fatal("expected no detection for case-insensitive host match")
	}
}

func TestCSRFOriginMismatchedHost(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("https://evil.com/path")
	if !r.Detected {
		t.Fatal("expected detection for mismatched origin host")
	}
}

func TestCSRFOriginAllowListMatch(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com", AllowList: []string{"cdn.example.com", "api.example.com"}}
	r := c.Detect("https://api.example.com/path")
	if r.Detected {
		t.Fatal("expected no detection for allowlist match")
	}
}

func TestCSRFOriginAllowListNoMatch(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com", AllowList: []string{"cdn.example.com"}}
	r := c.Detect("https://evil.com/path")
	if !r.Detected {
		t.Fatal("expected detection when neither host nor allowlist match")
	}
}

func TestCSRFOriginInvalidURL(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("://invalid")
	if r.Detected {
		t.Fatal("expected no detection for unparseable origin URL")
	}
}

func TestCSRFOriginName(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	if c.Name() != "csrf_origin" {
		t.Fatalf("expected name 'csrf_origin', got %s", c.Name())
	}
}

// ---- IPBlacklist ----

func TestIPBlacklistNotBlocked(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)

	r := b.Detect("192.168.1.1")
	if r.Detected {
		t.Fatal("expected no detection for unblocked IP")
	}
}

func TestIPBlacklistBlocked(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)

	mem.Block("10.0.0.1", 3600)
	r := b.Detect("10.0.0.1")
	if !r.Detected {
		t.Fatal("expected detection for blocked IP")
	}
}

func TestIPBlacklistRecordAttackBelowThreshold(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)
	b.Threshold = 5

	blocked, err := b.RecordAttack("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blocked {
		t.Fatal("expected not blocked below threshold")
	}
}

func TestIPBlacklistRecordAttackReachesThreshold(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)
	b.Threshold = 3

	for i := 0; i < 3; i++ {
		blocked, err := b.RecordAttack("10.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if i < 2 && blocked {
			t.Fatalf("expected not blocked at count %d", i+1)
		}
		if i == 2 && !blocked {
			t.Fatal("expected blocked when threshold reached")
		}
	}
}

func TestIPBlacklistDefaults(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)

	if b.Threshold != 5 {
		t.Fatalf("expected default Threshold=5, got %d", b.Threshold)
	}
	if b.Window == 0 {
		t.Fatal("expected non-zero default Window")
	}
	if b.BanDuration == 0 {
		t.Fatal("expected non-zero default BanDuration")
	}
}

func TestIPBlacklistName(t *testing.T) {
	mem := storage.NewMemory()
	defer mem.Close()
	b := NewIPBlacklist(mem)

	if b.Name() != "ip_blacklist" {
		t.Fatalf("expected name 'ip_blacklist', got %s", b.Name())
	}
}

// ---- Method ----

func TestMethodAllowed(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	d := &Method{}
	for _, method := range methods {
		r := d.Detect(method)
		if r.Detected {
			t.Errorf("expected method %s to be allowed", method)
		}
	}
}

func TestMethodDisallowed(t *testing.T) {
	d := &Method{}
	tests := []string{"TRACE", "CONNECT", "CUSTOM", "DEBUG", ""}
	for _, method := range tests {
		r := d.Detect(method)
		if !r.Detected {
			t.Errorf("expected method %q to be disallowed", method)
		}
	}
}

func TestMethodName(t *testing.T) {
	d := &Method{}
	if d.Name() != "http_method" {
		t.Fatalf("expected name 'http_method', got %s", d.Name())
	}
}
