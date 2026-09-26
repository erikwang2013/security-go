// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package pet

import (
	"bytes"
	_ "embed"
	"net/http"
	"time"

	"github.com/erikwang2013/security-go"
)

// Mood is the mascot's posture, derived from what a scan actually found.
// It exists so the mascot can be driven by detection results instead of being
// a static image: the shield and magnifier recolour to report threat level at
// a glance.
type Mood int

const (
	// Calm means the scan came back clean.
	Calm Mood = iota
	// Watchful means something fired, but nothing High or Critical.
	Watchful
	// Alarmed means at least one High or Critical result — act on it.
	Alarmed
)

//go:embed mood-watchful.svg
var watchfulSVG []byte

//go:embed mood-alarmed.svg
var alarmedSVG []byte

// MoodOf classifies detection results into a mood. Only results with
// Detected set are considered, so a detector that reports Severity critical
// on a clean input cannot raise the alarm. The most severe hit wins.
func MoodOf(results []*security.Result) Mood {
	mood := Calm
	for _, r := range results {
		if r == nil || !r.Detected {
			continue
		}
		switch r.Severity {
		case security.SeverityHigh, security.SeverityCritical:
			return Alarmed
		default:
			mood = Watchful
		}
	}
	return mood
}

// SVGFor returns the mascot's artwork for the given mood. An unrecognised
// mood falls back to Calm. Like SVG, the slice is shared and must not be
// modified by the caller.
func SVGFor(m Mood) []byte {
	switch m {
	case Watchful:
		return watchfulSVG
	case Alarmed:
		return alarmedSVG
	default:
		return svg
	}
}

// MoodHandler serves the mascot in whatever mood moodFor reports for the
// request, so a status or debug route can render live threat state.
//
// The response is marked no-store: unlike Handler, this output changes with
// the scan, so caching it for a day would serve a stale posture.
func MoodHandler(moodFor func(*http.Request) Mood) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, "pet.svg", time.Time{}, bytes.NewReader(SVGFor(moodFor(r))))
	})
}
