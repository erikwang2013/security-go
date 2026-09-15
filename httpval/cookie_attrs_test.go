// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestCookieAttrsName(t *testing.T) {
	c := &CookieAttrs{}
	if c.Name() != "cookie_attrs" {
		t.Fatalf("expected name 'cookie_attrs', got %s", c.Name())
	}
}

func TestCookieAttrsCompleteCookie(t *testing.T) {
	c := NewCookieAttrs(true, true, true)
	in := "session=abc; Path=/; HttpOnly; Secure; SameSite=Strict"
	if r := c.Detect(in); r.Detected {
		t.Fatalf("expected no detection for a fully specified cookie, got %+v", r)
	}
}

func TestCookieAttrsHeaderPrefixForm(t *testing.T) {
	c := NewCookieAttrs(true, true, true)
	in := "Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax"
	if r := c.Detect(in); r.Detected {
		t.Fatalf("expected the \"Set-Cookie: \" prefix form to be accepted, got %+v", r)
	}
}

func TestCookieAttrsCaseInsensitive(t *testing.T) {
	c := NewCookieAttrs(true, true, true)
	in := "session=abc; path=/; httponly; secure; samesite=lax"
	if r := c.Detect(in); r.Detected {
		t.Fatalf("expected lowercase attributes to count, got %+v", r)
	}
}

func TestCookieAttrsNameCollisionWithAttribute(t *testing.T) {
	// A cookie merely *named* like an attribute does not satisfy the
	// requirement: otherwise "samesite=1" would defeat the SameSite check.
	for _, in := range []string{"samesite=1; Path=/", "httponly=1; Path=/", "secure=1; Path=/"} {
		c := NewCookieAttrs(true, true, true)
		if r := c.Detect(in); !r.Detected {
			t.Fatalf("input %q: expected detection, a cookie name is not an attribute", in)
		}
	}
}

func TestCookieAttrsNameCollisionWithRealAttribute(t *testing.T) {
	c := NewCookieAttrs(true, true, true)
	in := "samesite=1; Secure; HttpOnly; SameSite=Lax"
	if r := c.Detect(in); r.Detected {
		t.Fatalf("expected the real attributes to count alongside a colliding name, got %+v", r)
	}
}

func TestCookieAttrsMissingSecure(t *testing.T) {
	c := NewCookieAttrs(true, true, true)
	in := "session=abc; Path=/; HttpOnly; SameSite=Strict"
	r := c.Detect(in)
	if !r.Detected {
		t.Fatal("expected detection when Secure is missing")
	}
	if r.Severity != security.SeverityMedium {
		t.Fatalf("expected SeverityMedium, got %v", r.Severity)
	}
	if r.Details["cookie"] != "session" {
		t.Fatalf("expected cookie name 'session', got %v", r.Details["cookie"])
	}
	missing, ok := r.Details["missing"].([]string)
	if !ok || len(missing) != 1 || missing[0] != "Secure" {
		t.Fatalf("expected missing [\"Secure\"], got %v", r.Details["missing"])
	}
}

func TestCookieAttrsMissingAllReportedTogether(t *testing.T) {
	c := NewCookieAttrs(true, true, true)
	r := c.Detect("session=abc; Path=/")
	if !r.Detected {
		t.Fatal("expected detection when every required attribute is absent")
	}
	missing, ok := r.Details["missing"].([]string)
	if !ok || len(missing) != 3 {
		t.Fatalf("expected one result listing all 3 missing attributes, got %v", r.Details["missing"])
	}
	for _, want := range []string{"Secure", "HttpOnly", "SameSite"} {
		found := false
		for _, got := range missing {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing = %v does not contain %q", missing, want)
		}
	}
}

func TestCookieAttrsNoRequirements(t *testing.T) {
	c := NewCookieAttrs(false, false, false)
	if r := c.Detect("session=abc"); r.Detected {
		t.Fatalf("expected no detection when nothing is required, got %+v", r)
	}
}

func TestCookieAttrsSameSitePresentEmptyValue(t *testing.T) {
	c := NewCookieAttrs(false, false, true)
	if r := c.Detect("session=abc; SameSite="); r.Detected {
		t.Fatalf("expected SameSite= to count as present, got %+v", r)
	}
}

func TestCookieAttrsSameSitePresentUnknownValue(t *testing.T) {
	c := NewCookieAttrs(false, false, true)
	if r := c.Detect("session=abc; SameSite=Off"); r.Detected {
		t.Fatalf("expected an unknown SameSite value to still count as present, got %+v", r)
	}
}

func TestCookieAttrsValueTooLong(t *testing.T) {
	c := &CookieAttrs{MaxValueLen: 5}
	r := c.Detect("session=averylongvalue")
	if !r.Detected {
		t.Fatal("expected detection for an overlong cookie value")
	}
	if r.Severity != security.SeverityHigh {
		t.Fatalf("expected SeverityHigh, got %v", r.Severity)
	}
	if r.Details["cookie"] != "session" {
		t.Fatalf("expected cookie name 'session', got %v", r.Details["cookie"])
	}
	if got, _ := r.Details["length"].(int); got != 14 {
		t.Fatalf("expected length 14, got %v", got)
	}
	if got, _ := r.Details["max_length"].(int); got != 5 {
		t.Fatalf("expected max_length 5, got %v", got)
	}
}

func TestCookieAttrsValueAtLimit(t *testing.T) {
	c := &CookieAttrs{MaxValueLen: 5}
	if r := c.Detect("session=abcde"); r.Detected {
		t.Fatalf("expected no detection at exactly the length limit, got %+v", r)
	}
}

func TestCookieAttrsValueLengthUnlimited(t *testing.T) {
	c := &CookieAttrs{MaxValueLen: 0}
	if r := c.Detect("session=averylongvalue"); r.Detected {
		t.Fatalf("expected no detection when MaxValueLen is 0, got %+v", r)
	}
}

func TestCookieAttrsEmptyValueFlagged(t *testing.T) {
	c := &CookieAttrs{RequireNonEmpty: true}
	r := c.Detect("session=; Max-Age=0")
	if !r.Detected {
		t.Fatal("expected detection for an empty cookie value")
	}
	if r.Severity != security.SeverityMedium {
		t.Fatalf("expected SeverityMedium, got %v", r.Severity)
	}
	if r.Details["cookie"] != "session" {
		t.Fatalf("expected cookie name 'session', got %v", r.Details["cookie"])
	}
}

func TestCookieAttrsEmptyValueTolerated(t *testing.T) {
	c := &CookieAttrs{}
	if r := c.Detect("session=; Max-Age=0"); r.Detected {
		t.Fatalf("expected an empty value to be tolerated by default, got %+v", r)
	}
}

func TestCookieAttrsAttributesWinOverLength(t *testing.T) {
	// Attribute checks run first, so a cookie that fails both reports the
	// more useful finding.
	c := &CookieAttrs{RequireSecure: true, MaxValueLen: 2}
	r := c.Detect("session=averylongvalue")
	missing, ok := r.Details["missing"].([]string)
	if !ok || len(missing) != 1 || missing[0] != "Secure" {
		t.Fatalf("expected the attribute finding to win, got %+v", r)
	}
}

func TestCookieAttrsEmptyInput(t *testing.T) {
	c := NewCookieAttrs(true, true, true)
	if r := c.Detect(""); r.Detected {
		t.Fatalf("expected no detection for empty input, got %+v", r)
	}
}

func TestCookieAttrsUnparseable(t *testing.T) {
	c := NewCookieAttrs(true, true, true)
	for _, in := range []string{"this is not a cookie", "abc", "a b c d e"} {
		if r := c.Detect(in); r.Detected {
			t.Fatalf("expected no detection for unparseable input %q, got %+v", in, r)
		}
	}
}
