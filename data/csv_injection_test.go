// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import "testing"

func TestCSVInjection(t *testing.T) {
	d := &CSVInjection{}
	if r := d.Detect(""); r == nil || r.Name != "csv_injection" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected csv_injection result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"=cmd('calc')", true},
		{"=HYPERLINK(\"http://evil.com\")", true},
		{"=DDE(\"cmd\")", true},
		{"=IMPORTXML(\"http://evil.com/x\")", true},
		{"=IMPORTDATA(\"http://evil.com/x\")", true},
		{"=WEBSERVICE(\"http://evil.com/x\")", true},
		{"=IMPORTFEED(\"http://evil.com/x\")", true},
		{"@SUM(1,2)", true},
		{"@AVERAGE(1,2)", true},
		{"@COUNT(A1:A9)", true},
		{"@MAX(1,2)", true},
		{"@MIN(1,2)", true},
		{"@ROUND(1.5)", true},
		{"@IF(A1=1,\"a\",\"b\")", true},
		{"@VLOOKUP(1,A1:B9,2)", true},
		{"@HLOOKUP(1,A1:B9,2)", true},
		{"+SUM(1,2)", true},
		{"-SUM(1,2)", true},
		{"=A1+B2", true},
		{"  =cmd('calc')", true},
		{"=A1", false},
		{"==cmd('x')", false},
		{"=not_a_function(1)", false},
		{"+SUM", false},
		{"normal text", false},
		{"hello world", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
