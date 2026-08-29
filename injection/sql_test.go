// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestSQL(t *testing.T) {
	d := &SQL{}
	if got := d.Name(); got != "sql_injection" {
		t.Fatalf("Name() = %q, want %q", got, "sql_injection")
	}
	tests := []struct {
		input  string
		should bool
	}{
		// payloads
		{"UNION SELECT * FROM users", true},
		{"UNION (SELECT * FROM users)", true},
		{"/**/UNION/**/SELECT", true},
		{"' OR '1'='1", true},
		{"' OR 1=1 --", true},
		{"1' AND 1=1 --", true},
		{"' AND 'a'='a", true},
		{"SELECT sleep(5)", true},
		{"SELECT pg_sleep(5)", true},
		{"BENCHMARK(1000000,MD5(1))", true},
		{"WAITFOR DELAY '0:0:5'", true},
		{"information_schema.tables", true},
		{"mysql.user", true},
		{"pg_catalog.pg_tables", true},
		{"sqlite_master", true},
		{"LOAD_FILE('/etc/passwd')", true},
		{"INTO OUTFILE '/tmp/evil'", true},
		{"exec master..xp_cmdshell", true},
		{"EXECUTE master..xp_cmdshell('dir')", true},
		{"execute(xp_cmdshell)", true},
		{"HEX(1)", true},
		{"CHAR(65)", true},
		{"ASCII(mid(user(),1))", true},
		{"CONCAT(1,2)", true},
		// benign / boundary
		{"normal text", false},
		{"hello world", false},
		{"SELECT name FROM users WHERE id = 1", false},
		{"SELECT * FROM users", false},
		{"", false},
		// plain -- / # / /* in text must not fire (ranges, titles, hashtags)
		{"q=2024--2025", false},
		{"chapter title -- vol.2", false},
		{"id=1--", false},
		{"q=news #top", false},
		{"q=a/*b", false},
		// comment tokens need an injection point right before them
		{"id=1'--", true},
		{"id='1'#", true},
		{"id='1'/*", true},
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
