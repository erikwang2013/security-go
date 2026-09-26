// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package pet

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/erikwang2013/security-go"
)

func detected(sev security.Severity) *security.Result {
	return &security.Result{Name: "x", Detected: true, Severity: sev}
}

func TestMoodOf(t *testing.T) {
	cases := []struct {
		name    string
		results []*security.Result
		want    Mood
	}{
		{"no results", nil, Calm},
		{"empty slice", []*security.Result{}, Calm},
		{"low only", []*security.Result{detected(security.SeverityLow)}, Watchful},
		{"medium only", []*security.Result{detected(security.SeverityMedium)}, Watchful},
		{"high", []*security.Result{detected(security.SeverityHigh)}, Alarmed},
		{"critical", []*security.Result{detected(security.SeverityCritical)}, Alarmed},
		{"highest wins regardless of order",
			[]*security.Result{detected(security.SeverityCritical), detected(security.SeverityLow)}, Alarmed},
		{"highest wins, reverse order",
			[]*security.Result{detected(security.SeverityLow), detected(security.SeverityHigh)}, Alarmed},
		// The bug this guards: severity is only meaningful together with
		// Detected. A detector that always stamps Severity must not be able
		// to raise the alarm on a clean scan.
		{"undetected critical stays calm", []*security.Result{
			{Name: "x", Detected: false, Severity: security.SeverityCritical},
		}, Calm},
		{"undetected ignored alongside a real hit", []*security.Result{
			{Name: "clean", Detected: false, Severity: security.SeverityCritical},
			detected(security.SeverityMedium),
		}, Watchful},
		{"nil element does not panic", []*security.Result{nil, detected(security.SeverityLow)}, Watchful},
	}

	for _, tc := range cases {
		if got := MoodOf(tc.results); got != tc.want {
			t.Errorf("%s: MoodOf = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSVGForReturnsDistinctValidArt(t *testing.T) {
	calm, watch, alarm := SVGFor(Calm), SVGFor(Watchful), SVGFor(Alarmed)

	if !bytes.Equal(calm, SVG()) {
		t.Error("Calm must be the base artwork returned by SVG()")
	}
	if bytes.Equal(calm, watch) || bytes.Equal(watch, alarm) || bytes.Equal(calm, alarm) {
		t.Fatal("each mood must have its own artwork")
	}
	for mood, body := range map[Mood][]byte{Calm: calm, Watchful: watch, Alarmed: alarm} {
		if !bytes.Contains(body, []byte("<svg")) || !bytes.Contains(body, []byte("</svg>")) {
			t.Errorf("mood %v artwork is not an SVG document", mood)
		}
	}
	if got := SVGFor(Mood(99)); !bytes.Equal(got, calm) {
		t.Error("an unknown mood should fall back to Calm")
	}
}

func TestMoodHandlerServesLivePosture(t *testing.T) {
	var mood = Calm
	h := MoodHandler(func(*http.Request) Mood { return mood })

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/pet.svg", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "image/svg+xml") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store — the posture changes per scan", cc)
	}
	if !bytes.Equal(rec.Body.Bytes(), SVGFor(Calm)) {
		t.Error("body should be the Calm artwork while the mood is Calm")
	}

	// Same handler, changed state: the output must follow.
	mood = Alarmed
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/pet.svg", nil))
	if !bytes.Equal(rec.Body.Bytes(), SVGFor(Alarmed)) {
		t.Error("body should switch to the Alarmed artwork once the mood changes")
	}
}

// End-to-end wiring: a real scan of a real request drives the artwork.
func TestMoodHandlerEndToEndWithEngine(t *testing.T) {
	e := security.NewEngine()
	e.Register(&stubDetector{})

	h := MoodHandler(func(r *http.Request) Mood { return MoodOf(e.DetectRequest(r)) })

	benign := httptest.NewRecorder()
	h.ServeHTTP(benign, httptest.NewRequest("GET", "/?q=hello", nil))
	if !bytes.Equal(benign.Body.Bytes(), SVGFor(Calm)) {
		t.Error("a benign request should render Calm")
	}

	hostile := httptest.NewRecorder()
	h.ServeHTTP(hostile, httptest.NewRequest("GET", "/?q=attack", nil))
	if !bytes.Equal(hostile.Body.Bytes(), SVGFor(Alarmed)) {
		t.Error("a request the engine flags Critical should render Alarmed")
	}
}

type stubDetector struct{}

func (s *stubDetector) Name() string { return "stub" }
func (s *stubDetector) Detect(input string) *security.Result {
	hit := strings.Contains(input, "attack")
	return &security.Result{Name: "stub", Detected: hit, Severity: security.SeverityCritical}
}
