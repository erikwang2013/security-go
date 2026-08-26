// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

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

func TestCSRFOriginMatchingHostTrailingSlash(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("https://example.com/")
	if r.Detected {
		t.Fatal("expected no detection for matching host with trailing slash")
	}
}

func TestCSRFOriginMismatchedHost(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("https://evil.com/path")
	if !r.Detected {
		t.Fatal("expected detection for mismatched origin host")
	}
	if r.Severity != security.SeverityMedium {
		t.Fatalf("expected SeverityMedium, got %v", r.Severity)
	}
	if r.Message == "" {
		t.Error("expected non-empty Message")
	}
	if r.Name != c.Name() {
		t.Errorf("expected result Name=%q, got %q", c.Name(), r.Name)
	}
}

func TestCSRFOriginPortMismatch(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("https://example.com:8080/path")
	if !r.Detected {
		t.Fatal("expected detection when port makes host differ from configured Host")
	}
}

func TestCSRFOriginNoScheme(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com"}
	r := c.Detect("example.com/path")
	if !r.Detected {
		t.Fatal("expected detection for origin without scheme (not an absolute URI)")
	}
}

func TestCSRFOriginAllowListMatch(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com", AllowList: []string{"cdn.example.com", "api.example.com"}}
	r := c.Detect("https://api.example.com/path")
	if r.Detected {
		t.Fatal("expected no detection for allowlist match")
	}
}

func TestCSRFOriginAllowListCaseInsensitive(t *testing.T) {
	c := &CSRFOrigin{Host: "example.com", AllowList: []string{"api.example.com"}}
	r := c.Detect("https://API.EXAMPLE.COM/path")
	if r.Detected {
		t.Fatal("expected no detection for case-insensitive allowlist match")
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
