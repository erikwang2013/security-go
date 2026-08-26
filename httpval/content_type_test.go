// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

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
	if r.Severity != security.SeverityLow {
		t.Fatalf("expected SeverityLow, got %v", r.Severity)
	}
	if r.Message == "" {
		t.Error("expected non-empty Message")
	}
	if r.Name != c.Name() {
		t.Errorf("expected result Name=%q, got %q", c.Name(), r.Name)
	}
}

func TestContentTypeUppercaseMediaType(t *testing.T) {
	c := NewContentType([]string{"application/json"})
	r := c.Detect("Application/JSON")
	if r.Detected {
		t.Fatal("expected Application/JSON (parsed case-insensitively) to be allowed")
	}
}

func TestContentTypeWildcardDenied(t *testing.T) {
	c := NewContentType([]string{"application/json"})
	r := c.Detect("*/*")
	if !r.Detected {
		t.Fatal("expected */* to be denied when not in allowlist")
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

func TestContentTypeEmptyInput(t *testing.T) {
	c := NewContentType([]string{"application/json"})
	r := c.Detect("")
	if r.Detected {
		t.Fatal("expected no detection for empty input")
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
