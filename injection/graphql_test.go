// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestGraphQL(t *testing.T) {
	d := &GraphQL{}
	tests := []struct {
		input  string
		should bool
	}{
		{"{__schema{types{name}}}", true},
		{"{__type(name:\"User\"){name}}", true},
		{"{__typename}", true},
		{"mutation{deleteUser(id:1)}", true},
		{"query { user { name } }", false},
		{"normal text", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
