// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

// Package pet carries the project mascot, 哨兵鼠 (Sentinel Gopher), as a
// build-time asset: raw SVG for serving over HTTP, and a plain-text banner
// for startup logs.
//
// The mascot is a Go gopher on sentinel duty — shield reading 36 for the
// detector count, magnifier for the per-request scan.
//
//	http.Handle("/pet.svg", pet.Handler())  // serve the SVG
//	log.Println(pet.Banner())               // print at startup
package pet

import (
	"bytes"
	_ "embed"
	"net/http"
	"time"
)

//go:embed pet.svg
var svg []byte

// SVG returns the mascot as SVG bytes. The slice is shared and must not be
// modified by the caller.
func SVG() []byte { return svg }

// Handler serves the mascot as image/svg+xml, tagged cacheable for a day.
// Mount it on a diagnostics or debug route; it has no side effects.
//
// ServeContent sets Content-Length and answers Range and HEAD requests; a
// bare Write would exceed net/http's 2 KiB sniff buffer and chunk the
// response instead.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeContent(w, r, "pet.svg", time.Time{}, bytes.NewReader(svg))
	})
}

// Banner returns the mascot as a plain-text banner, for printing once at
// service startup. Trailing newline included.
func Banner() string { return banner }

const banner = `        .--------.
      .'  .--.    '.        哨兵鼠 · Sentinel Gopher
     /   /    \     \       ------------------------
    |   | o  o |     |      security-go — 36 detectors
    |   |  __  |     |      Detect · DetectAll · DetectRequest
     \   \ '--' /    /      Tracker · Signer · IPBlacklist
      '.  '----'  .'
        '--------'
`
