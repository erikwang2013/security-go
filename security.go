// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package security

import "net/http"

// Severity represents the severity level of a detection result.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Result is the unified detection result from any detector.
type Result struct {
	Name     string
	Detected bool
	Message  string
	Severity Severity
	Details  map[string]interface{}
}

// Detector is the interface all attack detectors implement.
type Detector interface {
	Name() string
	Detect(input string) *Result
}

// Engine manages detector registration and orchestration.
type Engine struct {
	detectors map[string]Detector
}

// NewEngine creates a new Engine.
func NewEngine() *Engine {
	return &Engine{detectors: make(map[string]Detector)}
}

// Register adds a detector to the engine.
func (e *Engine) Register(d Detector) {
	e.detectors[d.Name()] = d
}

// Detect runs a named detector against input.
func (e *Engine) Detect(name, input string) *Result {
	if d, ok := e.detectors[name]; ok {
		return d.Detect(input)
	}
	return nil
}

// DetectAll runs all registered detectors against input.
func (e *Engine) DetectAll(input string) []*Result {
	var results []*Result
	for _, d := range e.detectors {
		if r := d.Detect(input); r != nil && r.Detected {
			results = append(results, r)
		}
	}
	return results
}

// DetectRequest runs all registered detectors against an HTTP request.
func (e *Engine) DetectRequest(r *http.Request) []*Result {
	var results []*Result
	inputs := collectRequestInputs(r)
	for _, input := range inputs {
		results = append(results, e.DetectAll(input)...)
	}
	return results
}

func collectRequestInputs(r *http.Request) []string {
	var inputs []string
	inputs = append(inputs, r.URL.String())
	inputs = append(inputs, r.URL.Query().Encode())
	for key, vals := range r.Header {
		for _, v := range vals {
			inputs = append(inputs, key+": "+v)
		}
	}
	for _, c := range r.Cookies() {
		inputs = append(inputs, c.Name+"="+c.Value)
	}
	return inputs
}
