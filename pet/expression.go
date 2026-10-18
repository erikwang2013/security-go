// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package pet

import (
	"bytes"
	_ "embed"
	"net/http"
	"path"
	"strings"
	"time"
)

// Expression identifies one of the mascot's animated expression forms.
// The zero value is Smile.
type Expression int

const (
	Smile Expression = iota
	Joy
	Cry
	Depressed
	Terrified
	Angry
	Coquettish
	Cute
	Pleasing
	Knocking
	Facepalm
	Tongue
)

//go:embed expressions/smile.svg
var smileSVG []byte

//go:embed expressions/joy.svg
var joySVG []byte

//go:embed expressions/cry.svg
var crySVG []byte

//go:embed expressions/depressed.svg
var depressedSVG []byte

//go:embed expressions/terrified.svg
var terrifiedSVG []byte

//go:embed expressions/angry.svg
var angrySVG []byte

//go:embed expressions/coquettish.svg
var coquettishSVG []byte

//go:embed expressions/cute.svg
var cuteSVG []byte

//go:embed expressions/pleasing.svg
var pleasingSVG []byte

//go:embed expressions/knocking.svg
var knockingSVG []byte

//go:embed expressions/facepalm.svg
var facepalmSVG []byte

//go:embed expressions/tongue.svg
var tongueSVG []byte

// expressionArts is indexed by Expression: the order is both the display
// order and the slug set accepted by ExpressionOf and ExpressionHandler.
var expressionArts = [...]struct {
	slug string
	svg  []byte
}{
	{"smile", smileSVG},
	{"joy", joySVG},
	{"cry", crySVG},
	{"depressed", depressedSVG},
	{"terrified", terrifiedSVG},
	{"angry", angrySVG},
	{"coquettish", coquettishSVG},
	{"cute", cuteSVG},
	{"pleasing", pleasingSVG},
	{"knocking", knockingSVG},
	{"facepalm", facepalmSVG},
	{"tongue", tongueSVG},
}

// Expressions returns every expression form in display order. The returned
// slice is a fresh copy and may be modified by the caller.
func Expressions() []Expression {
	out := make([]Expression, len(expressionArts))
	for i := range expressionArts {
		out[i] = Expression(i)
	}
	return out
}

// String returns the stable lower-case slug for e, e.g. "smile". An
// unrecognised value returns "unknown".
func (e Expression) String() string {
	if e < 0 || int(e) >= len(expressionArts) {
		return "unknown"
	}
	return expressionArts[e].slug
}

// ExpressionOf resolves a slug such as "smile" to an Expression. The match is
// exact. It reports false when the slug is unknown.
func ExpressionOf(name string) (Expression, bool) {
	for i := range expressionArts {
		if expressionArts[i].slug == name {
			return Expression(i), true
		}
	}
	return Smile, false
}

// SVGForExpression returns the artwork for e. An unrecognised value falls
// back to Smile. Like SVG, the slice is shared and must not be modified by
// the caller.
func SVGForExpression(e Expression) []byte {
	if e < 0 || int(e) >= len(expressionArts) {
		return expressionArts[Smile].svg
	}
	return expressionArts[e].svg
}

// ExpressionHandler serves expression artwork by the last path segment of the
// request URL: "/pet/smile.svg" and "/pet/smile" both serve Smile. The ".svg"
// suffix is optional. Unknown names return 404. Responses are cacheable for a
// day, matching Handler.
//
// Mount it on its own prefix; any leading path segments are ignored:
//
//	http.Handle("/pet/", pet.ExpressionHandler())
func ExpressionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(path.Base(r.URL.Path), ".svg")
		e, ok := ExpressionOf(name)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeContent(w, r, e.String()+".svg", time.Time{}, bytes.NewReader(SVGForExpression(e)))
	})
}
