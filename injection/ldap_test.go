// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestLDAP(t *testing.T) {
	d := &LDAP{}
	tests := []struct {
		input  string
		should bool
	}{
		{"(|(uid=admin)(&(objectClass=*)))", true},
		{"(&(cn=*)(password=*))", true},
		{"(!(uid=*))", true},
		{"(|(uid=*))", true},
		{"(objectClass=*)", true},
		{"(cn=*)", true},
		{"%28|(uid=*))", true},
		{"normal text", false},
		{"just a username", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
