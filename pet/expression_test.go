// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package pet

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Expressions are part of the package API, so their order and slugs are
// effectively public: the README gallery and ExpressionHandler URLs both
// depend on them staying stable.
func TestExpressionsInDisplayOrder(t *testing.T) {
	want := []string{
		"smile", "joy", "cry", "depressed", "terrified", "angry",
		"coquettish", "cute", "pleasing", "knocking", "facepalm", "tongue",
	}
	got := Expressions()
	if len(got) != len(want) {
		t.Fatalf("Expressions() returned %d forms, want %d", len(got), len(want))
	}
	if got[0] != Smile || got[len(got)-1] != Tongue {
		t.Errorf("Expressions() must start at Smile and end at Tongue, got %v..%v", got[0], got[len(got)-1])
	}
	for i, e := range got {
		if e.String() != want[i] {
			t.Errorf("form %d = %q, want %q", i, e.String(), want[i])
		}
	}
}

func TestExpressionOfResolvesSlugs(t *testing.T) {
	for _, e := range Expressions() {
		got, ok := ExpressionOf(e.String())
		if !ok {
			t.Errorf("ExpressionOf(%q) reported unknown", e.String())
			continue
		}
		if got != e {
			t.Errorf("ExpressionOf(%q) = %v, want %v", e.String(), got, e)
		}
	}
	for _, name := range []string{"", "nope", "Smile", "smile.svg"} {
		if _, ok := ExpressionOf(name); ok {
			t.Errorf("ExpressionOf(%q) should be unknown", name)
		}
	}
}

func TestSVGForExpressionReturnsDistinctArt(t *testing.T) {
	// The English name is baked into each SVG's aria-label; asserting it
	// catches a table entry paired with the wrong file.
	titles := map[string]string{
		"smile": "Smile", "joy": "Joy", "cry": "Cry", "depressed": "Depressed",
		"terrified": "Terrified", "angry": "Angry", "coquettish": "Coquettish",
		"cute": "Cute", "pleasing": "Pleasing", "knocking": "Knocking",
		"facepalm": "Facepalm", "tongue": "Tongue Out",
	}

	seen := make(map[string]string, len(titles))
	for _, e := range Expressions() {
		body := SVGForExpression(e)
		if !bytes.Contains(body, []byte("<svg")) || !bytes.Contains(body, []byte("</svg>")) {
			t.Errorf("%s artwork is not an SVG document", e)
			continue
		}
		if !bytes.Contains(body, []byte(titles[e.String()])) {
			t.Errorf("%s artwork does not carry its own name", e)
		}
		if prev, dup := seen[string(body)]; dup {
			t.Errorf("%s duplicates %s", e, prev)
		}
		seen[string(body)] = e.String()
	}

	if got := SVGForExpression(Expression(99)); !bytes.Equal(got, SVGForExpression(Smile)) {
		t.Error("an unknown expression should fall back to Smile")
	}
}

func TestExpressionHandlerServesByPath(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		want   Expression
		status int
	}{
		{"slug with extension", "/pet/smile.svg", Smile, http.StatusOK},
		{"slug without extension", "/pet/facepalm", Facepalm, http.StatusOK},
		{"unknown expression", "/pet/nope.svg", 0, http.StatusNotFound},
		{"bare mount point", "/pet/", 0, http.StatusNotFound},
	}

	h := ExpressionHandler()
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", tc.path, nil))

		if rec.Code != tc.status {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.status)
			continue
		}
		if tc.status != http.StatusOK {
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "image/svg+xml") {
			t.Errorf("%s: Content-Type = %q, want image/svg+xml", tc.name, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") {
			t.Errorf("%s: Cache-Control = %q, want a max-age", tc.name, cc)
		}
		if !bytes.Equal(rec.Body.Bytes(), SVGForExpression(tc.want)) {
			t.Errorf("%s: body is not the %s artwork", tc.name, tc.want)
		}
	}
}

// The artwork is embedded at build time; a malformed edit would render as a
// broken image with no other test failing.
func TestExpressionSVGsAreWellFormedXML(t *testing.T) {
	for _, e := range Expressions() {
		body := SVGForExpression(e)
		dec := xml.NewDecoder(bytes.NewReader(body))
		for {
			_, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s is not well-formed XML: %v", e, err)
			}
		}
		if !bytes.Contains(body, []byte(`viewBox="0 0 320 400"`)) {
			t.Errorf("%s is missing its 320x400 viewBox", e)
		}
	}
}
