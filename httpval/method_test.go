// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

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

func TestMethodLowercaseDisallowed(t *testing.T) {
	d := &Method{}
	for _, method := range []string{"get", "post", "GeT"} {
		r := d.Detect(method)
		if !r.Detected {
			t.Errorf("expected case-mixed method %q to be disallowed", method)
		}
	}
}

func TestMethodWhitespaceDisallowed(t *testing.T) {
	d := &Method{}
	r := d.Detect(" GET")
	if !r.Detected {
		t.Error("expected method with leading whitespace to be disallowed")
	}
}

func TestMethodDetectedMetadata(t *testing.T) {
	d := &Method{}
	r := d.Detect("TRACE")
	if r.Name != d.Name() {
		t.Errorf("expected result Name=%q, got %q", d.Name(), r.Name)
	}
	if r.Severity != security.SeverityLow {
		t.Errorf("expected SeverityLow, got %v", r.Severity)
	}
	if r.Message == "" {
		t.Error("expected non-empty Message")
	}
}

func TestMethodName(t *testing.T) {
	d := &Method{}
	if d.Name() != "http_method" {
		t.Fatalf("expected name 'http_method', got %s", d.Name())
	}
}
