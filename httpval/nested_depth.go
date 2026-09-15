// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package httpval

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/erikwang2013/security-go"
)

const defaultMaxDepth = 32

// NestedDepth flags JSON body bombs: excessive nesting depth or excessive
// element counts. Only well-formed JSON can ever be flagged, so the detector
// cannot fire on non-JSON input.
type NestedDepth struct {
	MaxDepth int
	MaxKeys  int // total elements across all arrays and objects; 0 = unlimited
}

// NewNestedDepth creates a NestedDepth detector. maxDepth <= 0 defaults to 32.
func NewNestedDepth(maxDepth, maxKeys int) *NestedDepth {
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	return &NestedDepth{MaxDepth: maxDepth, MaxKeys: maxKeys}
}

// Name returns the detector name.
func (d *NestedDepth) Name() string {
	return "nested_depth"
}

// Detect streams input as JSON and reports a body bomb when nesting depth
// exceeds MaxDepth or the element count exceeds MaxKeys. Empty, malformed or
// non-JSON input is never reported.
func (d *NestedDepth) Detect(input string) *security.Result {
	if input == "" {
		return &security.Result{Name: d.Name(), Detected: false}
	}
	dec := json.NewDecoder(strings.NewReader(input))
	depth, keys := 0, 0
	for {
		t, err := dec.Token()
		if err != nil {
			return &security.Result{Name: d.Name(), Detected: false}
		}
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
				if depth > d.MaxDepth {
					return d.bomb("depth",
						"JSON body bomb: nesting depth "+strconv.Itoa(depth)+"/"+strconv.Itoa(d.MaxDepth),
						depth, keys)
				}
			case '}', ']':
				depth--
			}
		default:
			keys++
			if d.MaxKeys > 0 && keys > d.MaxKeys {
				return d.bomb("keys",
					"JSON body bomb: element count "+strconv.Itoa(keys)+"/"+strconv.Itoa(d.MaxKeys),
					depth, keys)
			}
		}
	}
}

// bomb builds the detection result for one violated limit.
func (d *NestedDepth) bomb(reason, message string, depth, keys int) *security.Result {
	return &security.Result{
		Name:     d.Name(),
		Detected: true,
		Message:  message,
		Severity: security.SeverityHigh,
		Details: map[string]interface{}{
			"reason":    reason,
			"depth":     depth,
			"keys":      keys,
			"max_depth": d.MaxDepth,
			"max_keys":  d.MaxKeys,
		},
	}
}
