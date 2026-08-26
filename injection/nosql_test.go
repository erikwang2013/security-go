// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestNoSQL(t *testing.T) {
	d := &NoSQL{}
	if got := d.Name(); got != "nosql_injection" {
		t.Fatalf("Name() = %q, want %q", got, "nosql_injection")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{`{"$ne": "admin"}`, true},
		{`"$gt": ""`, true},
		{`{"$gte": 1}`, true},
		{`{"$lt": 5}`, true},
		{`{"$lte": 5}`, true},
		{`{"$eq": 1}`, true},
		{`{"$in": [1,2]}`, true},
		{`{"$nin": [1,2]}`, true},
		{`{"$regex": "^a"}`, true},
		{`{"$where": "this.password == 'admin'"}`, true},
		{`{"$or": [{"user": "admin"}]}`, true},
		{`{"$and": [{"a": 1}]}`, true},
		{`{"$not": {"a": 1}}`, true},
		{`{"$exists": true}`, true},
		{`{"$type": 2}`, true},
		{`{"$text": {"$search": "x"}}`, true},
		// benign / boundary
		{`normal text`, false},
		{`{"username": "admin"}`, false},
		{`{"price": 100}`, false},
		{`{"a": {"b": 1}}`, false},
		{"", false},
	}
	var meta *security.Result
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
		if tc.should && meta == nil {
			meta = r
		}
	}
	if meta == nil {
		t.Fatal("no detected case to verify metadata")
	}
	if meta.Severity != security.SeverityHigh {
		t.Errorf("detected severity = %v, want SeverityHigh", meta.Severity)
	}
	if meta.Message == "" {
		t.Error("detected Message must not be empty")
	}
	if meta.Details["pattern"] == nil {
		t.Error("detected Details must contain pattern")
	}
	if r := d.Detect("hello"); r.Name != d.Name() || r.Detected {
		t.Errorf("undetected result: Name=%q Detected=%v, want %q/false", r.Name, r.Detected, d.Name())
	}
}
