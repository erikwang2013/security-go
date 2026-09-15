// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/erikwang2013/security-go"
)

// CookieAttrs validates a Set-Cookie header value and flags insecure
// configuration: missing Secure / HttpOnly / SameSite, an overlong value, or an
// empty value.
type CookieAttrs struct {
	RequireSecure   bool
	RequireHttpOnly bool
	RequireSameSite bool
	MaxValueLen     int // 0 = unlimited
	RequireNonEmpty bool
}

// NewCookieAttrs creates a CookieAttrs detector.
func NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite bool) *CookieAttrs {
	return &CookieAttrs{
		RequireSecure:   requireSecure,
		RequireHttpOnly: requireHttpOnly,
		RequireSameSite: requireSameSite,
	}
}

// Name returns the detector name.
func (c *CookieAttrs) Name() string {
	return "cookie_attrs"
}

// Detect validates one Set-Cookie value. The input may be the raw value or the
// library's "Set-Cookie: value" header form; both are accepted. Input that
// parses to no cookie is never reported.
func (c *CookieAttrs) Detect(input string) *security.Result {
	raw := stripCookiePrefix(strings.TrimSpace(input))
	cookie, err := http.ParseSetCookie(raw)
	if err != nil || cookie == nil {
		return &security.Result{Name: c.Name(), Detected: false}
	}

	// Attributes are read back out of the raw value: http.Cookie drops
	// Secure, HttpOnly and SameSite, so cookie.String() cannot see them.
	if missing := c.missingAttrs(raw); len(missing) > 0 {
		return &security.Result{
			Name:     c.Name(),
			Detected: true,
			Message:  "Set-Cookie missing attributes: " + strings.Join(missing, ", "),
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"cookie":  cookie.Name,
				"missing": missing,
			},
		}
	}
	if c.MaxValueLen > 0 && len(cookie.Value) > c.MaxValueLen {
		return &security.Result{
			Name:     c.Name(),
			Detected: true,
			Message:  "Set-Cookie value exceeds " + strconv.Itoa(c.MaxValueLen) + " bytes",
			Severity: security.SeverityHigh,
			Details: map[string]interface{}{
				"cookie":     cookie.Name,
				"length":     len(cookie.Value),
				"max_length": c.MaxValueLen,
			},
		}
	}
	if c.RequireNonEmpty && cookie.Value == "" {
		return &security.Result{
			Name:     c.Name(),
			Detected: true,
			Message:  "Set-Cookie has an empty value",
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"cookie": cookie.Name,
			},
		}
	}
	return &security.Result{Name: c.Name(), Detected: false}
}

// missingAttrs returns the display names of the required attributes absent from
// the raw Set-Cookie value. Attribute names are matched case-insensitively, and
// a present attribute counts even with an empty or unknown value.
func (c *CookieAttrs) missingAttrs(raw string) []string {
	var missing []string
	if c.RequireSecure && !hasAttr(raw, "secure") {
		missing = append(missing, "Secure")
	}
	if c.RequireHttpOnly && !hasAttr(raw, "httponly") {
		missing = append(missing, "HttpOnly")
	}
	if c.RequireSameSite && !hasAttr(raw, "samesite") {
		missing = append(missing, "SameSite")
	}
	return missing
}

// stripCookiePrefix removes a leading "Set-Cookie:" header prefix, as produced
// by the library's "Key: value" header form.
func stripCookiePrefix(input string) string {
	for {
		rest := strings.TrimSpace(input)
		if !strings.HasPrefix(strings.ToLower(rest), "set-cookie:") {
			return rest
		}
		input = rest[len("set-cookie:"):]
	}
}

// hasAttr reports whether the raw Set-Cookie value carries the named attribute,
// matching both "name" and "name=value" forms. The first field is the
// name=value pair and is skipped, so a cookie that is merely *named* secure,
// httponly or samesite does not read as carrying that attribute.
func hasAttr(raw, name string) bool {
	fields := strings.Split(raw, ";")
	for _, field := range fields[1:] {
		f := strings.ToLower(strings.TrimSpace(field))
		if f == "" {
			continue
		}
		if f == name || strings.HasPrefix(f, name+"=") {
			return true
		}
	}
	return false
}
