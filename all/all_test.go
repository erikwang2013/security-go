// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package all

import (
	"testing"

	"github.com/erikwang2013/security-go"
	"github.com/erikwang2013/security-go/httpval"
	"github.com/erikwang2013/security-go/session"
	"github.com/erikwang2013/security-go/storage"
)

var detectorNames = []string{
	"xss", "sql_injection", "command_injection", "nosql_injection",
	"ldap_injection", "xpath_injection", "jndi_injection", "ssi_injection",
	"graphql_injection", "ssti", "ssrf", "xxe", "header_injection",
	"host_header", "request_smuggling", "open_redirect", "cors", "websocket",
	"dns_rebinding", "deserialization", "csv_injection", "mail_header",
	"jwt_attack", "prototype_pollution", "path_traversal", "upload", "data_leak",
}

func newEngineWithAll() *security.Engine {
	e := security.NewEngine()
	RegisterAll(e)
	return e
}

func TestRegisterAllRegistersAllDetectors(t *testing.T) {
	e := newEngineWithAll()

	for _, name := range detectorNames {
		if r := e.Detect(name, "x"); r == nil {
			t.Errorf("detector %q not registered", name)
		}
	}
}

// The number 36 is written into the mascot's shield (pet/pet.svg), its banner,
// both READMEs and every translated README. Nothing else ties those to the
// code, so this test is the one place that has to fail when a detector is
// added or removed.
func TestTotalDetectorCountIs36(t *testing.T) {
	const claimed = 36

	store := session.NewMemoryStore()
	defer store.Close()
	mem := storage.NewMemory()
	defer mem.Close()

	// The detectors RegisterAll deliberately leaves out: httpval needs
	// per-app settings and session works on *http.Request, so Tracker and
	// Signer expose Name() but not Detect(string) — the reason they sit
	// outside the Engine.
	rest := []interface{ Name() string }{
		&httpval.Method{},
		httpval.NewBodySize(1024),
		httpval.NewContentType([]string{"application/json"}),
		&httpval.CSRFOrigin{},
		httpval.NewCookieAttrs(true, true, true),
		httpval.NewNestedDepth(0, 0),
		httpval.NewIPBlacklist(mem),
		session.NewTracker(store),
		session.NewSigner([]byte("secret"), nil),
	}

	seen := map[string]bool{}
	for _, name := range detectorNames {
		seen[name] = true
	}
	for _, d := range rest {
		if seen[d.Name()] {
			t.Errorf("detector %q counted twice", d.Name())
		}
		seen[d.Name()] = true
	}

	if len(seen) != claimed {
		t.Errorf("total detectors = %d, want %d: update pet/pet.svg, pet.Banner, and the READMEs", len(seen), claimed)
	}
}

func TestRegisterAllNoHttpval(t *testing.T) {
	e := newEngineWithAll()

	// httpval detectors require per-app config and must NOT be auto-registered
	for _, name := range []string{"httpval", "http_validation"} {
		if r := e.Detect(name, "x"); r != nil {
			t.Errorf("unexpected detector %q registered", name)
		}
	}
}

func TestRegisterAllDetectAllAttackInputs(t *testing.T) {
	e := newEngineWithAll()

	cases := []struct {
		input string
		want  []string // at least these detectors must fire
	}{
		{"SELECT * FROM users WHERE id=1 OR 1=1 --", []string{"sql_injection"}},
		{"<script>alert(1)</script>", []string{"xss"}},
		{"id=1; cat /etc/passwd", []string{"command_injection"}},
		{"http://169.254.169.254/latest/meta-data/", []string{"ssrf"}},
		{"GET /../../../../etc/passwd HTTP/1.1", []string{"path_traversal"}},
		{"{{7*7}}", []string{"ssti"}},
	}

	for _, tc := range cases {
		results := e.DetectAll(tc.input)
		hit := map[string]bool{}
		for _, r := range results {
			if !r.Detected {
				t.Errorf("DetectAll returned non-detected result for %q: %+v", tc.input, r)
			}
			hit[r.Name] = true
		}
		for _, name := range tc.want {
			if !hit[name] {
				t.Errorf("input %q: expected detector %q to fire, results: %v", tc.input, name, results)
			}
		}
	}
}

func TestRegisterAllDetectAllBenignInputs(t *testing.T) {
	e := newEngineWithAll()

	for _, input := range []string{
		"this is a normal request",
		"hello world",
		"https://example.com/page?id=42&name=alice",
		"GET /index.html HTTP/1.1",
	} {
		if results := e.DetectAll(input); len(results) != 0 {
			t.Errorf("input %q: expected no detections, got %d: %v", input, len(results), results)
		}
	}
}
