// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestNoSQL(t *testing.T) {
	d := &NoSQL{}
	tests := []struct {
		input  string
		should bool
	}{
		{`{"$ne": "admin"}`, true},
		{`"$gt": ""`, true},
		{`{"$regex": "^a"}`, true},
		{`"$where": "this.password == 'admin'"`, true},
		{`{"$or": [{"user": "admin"}]}`, true},
		{`normal text`, false},
		{`{"username": "admin"}`, false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
