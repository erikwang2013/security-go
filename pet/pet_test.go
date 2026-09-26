// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package pet

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// A malformed SVG renders as a broken image in the README and in any browser
// hitting Handler, so parse it rather than trusting the asset.
func TestSVGIsWellFormedXML(t *testing.T) {
	dec := xml.NewDecoder(bytes.NewReader(SVG()))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("embedded pet.svg is not well-formed XML: %v", err)
		}
	}
	if !bytes.Contains(SVG(), []byte(`viewBox="0 0 320 400"`)) {
		t.Error("pet.svg is missing its 320x400 viewBox")
	}
}

func TestHandlerServesSVG(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/pet.svg", nil))

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "image/svg+xml") {
		t.Errorf("Content-Type = %q, want image/svg+xml", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("Cache-Control = %q, want a max-age", cc)
	}
	// A bare Write would exceed net/http's 2 KiB sniff buffer and chunk the
	// response; ServeContent is what sets this.
	if got := rec.Header().Get("Content-Length"); got == "" {
		t.Error("Content-Length not set — response would be chunked")
	}
	if rec.Body.Len() != len(SVG()) {
		t.Errorf("body = %d bytes, want %d", rec.Body.Len(), len(SVG()))
	}
}

func TestBannerMentionsTheProject(t *testing.T) {
	b := Banner()
	for _, want := range []string{"哨兵鼠", "security-go", "36"} {
		if !strings.Contains(b, want) {
			t.Errorf("Banner() missing %q", want)
		}
	}
	if !strings.HasSuffix(b, "\n") {
		t.Error("Banner() should end with a newline")
	}
}
