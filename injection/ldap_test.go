// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestLDAP(t *testing.T) {
	d := &LDAP{}
	if got := d.Name(); got != "ldap_injection" {
		t.Fatalf("Name() = %q, want %q", got, "ldap_injection")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{"(|(uid=admin)(&(objectClass=*)))", true},
		{"(&(cn=*)(password=*))", true},
		{"(!(uid=*))", true},
		{"(|(uid=*))", true},
		{"(objectClass=*)", true},
		{"(objectClass=)", true},
		{"(cn=*)", true},
		{"%28|(uid=*))", true},
		{"(uid=admin)(|(password=*))", true},
		{"(>=uid)", true},
		{"(<=uid)", true},
		{"(~=uid)", true},
		// benign / boundary
		{"normal text", false},
		{"just a username", false},
		{"(uid=admin)", false},
		{"uid=admin", false},
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
