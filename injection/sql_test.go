// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import "testing"

func TestSQL(t *testing.T) {
	d := &SQL{}
	tests := []struct {
		input  string
		should bool
	}{
		{"UNION SELECT * FROM users", true},
		{"' OR '1'='1", true},
		{"1' AND 1=1 --", true},
		{"SELECT sleep(5)", true},
		{"information_schema.tables", true},
		{"/**/UNION/**/SELECT", true},
		{"LOAD_FILE('/etc/passwd')", true},
		{"exec master..xp_cmdshell", true},
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
