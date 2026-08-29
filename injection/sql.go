// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package injection

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

var sqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:/\*.*?\*/\s*)*union(?:\s+|/\*.*?\*/)\s*(?:/\*.*?\*/\s*)*select`),
	regexp.MustCompile(`(?i)union\s*\(\s*select`),
	// schema-prefixed references are deliberate metadata probing; bare
	// `sqlite_master` and time-based primitives are common in tutorials: Medium
	regexp.MustCompile(`(?i)\b(?:information_schema|mysql|pg_catalog|sys)\.`),
	regexp.MustCompile(`(?i)\b(?:load_file|into\s+(?:out|dump)file)\b`),
	regexp.MustCompile(`(?i)(?:'|\s)(?:or|and)\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`(?i)'\s*(?:or|and)\s+'[^']*'\s*=\s*'[^']*'?`),
	regexp.MustCompile(`(?i)waitfor\s+delay`),
	regexp.MustCompile(`(?i)\b(?:exec|execute)\s+(?:master\.\.|xp_)`),
	regexp.MustCompile(`(?i)\b(?:exec|execute)\s*\(\s*(?:master\.\.|xp_)`),
	// SQL comment markers only when tied to SQL: `--` right after a quote/`)`
	// (the classic auth-bypass tail), or a SQL keyword right after the marker.
	// Bare `--` / `#` / `/*` in normal text no longer triggers.
	regexp.MustCompile(`(?i)['"]\s*(?:--|/\*)`),
	regexp.MustCompile(`(?i)['"]\s*#\s*$`),
	// comment tail after `')` / `")` (classic auth-bypass); bare `) --` in
	// normal text (e.g. "5) -- note") must not trigger
	regexp.MustCompile(`(?i)['"]\)\s*(?:--|#|/\*)`),
	// numeric comparison after `) OR (` / `) AND (` — catches `1') OR ('1'='1`
	// without flagging `if (a) or (b)` text
	regexp.MustCompile(`(?i)\)\s*(?:or|and)\s+\(?['"]?\d+['"]?\s*=\s*['"]?\d+`),
	// time-based payloads need the `' OR SLEEP(` shape; bare `sleep(8)` is
	// common in normal text and handled by the Medium list below
	regexp.MustCompile(`(?i)(?:'|\s)(?:or|and)\s+(?:sleep|benchmark|pg_sleep)\s*\(`),
	regexp.MustCompile(`(?i)(?:^|[^a-z])(?:--|#|/\*)\s*(?:(?:or|and|select|union|drop|update|insert|delete|having|group|where|order|from|limit|sleep|benchmark|exec)\b|xp_)`),
	// SQL functions must have a SQL-shaped argument list (digits, 0x hex,
	// or nested SQL functions/keywords). Bare `concat(` / `char(` no longer
	// triggers.
	regexp.MustCompile(`(?i)\b(?:hex|char|ascii|concat)\s*\(\s*[^)]*(?:\d+|0x[0-9a-f]+|\b(?:user|version|database|current_user|mid|substr|left|right|char|ascii|concat|select|from|where|union|or|and)\b)[^)]*\)`),
}

// time-based primitives and bare table names appear in tutorials and normal
// text ("sleep(8)", "SELECT * FROM sqlite_master" docs): Medium.
// `' OR SLEEP(5) --` still hits the quote+comment Critical rule above.
var sqlMediumPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(`),
	regexp.MustCompile(`(?i)\bsqlite_master\b`),
}

// SQL detects SQL injection attempts.
type SQL struct{}

func (d *SQL) Name() string {
	return "sql_injection"
}

func (d *SQL) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, sqlPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "SQL injection pattern detected: " + m,
			Severity: security.SeverityCritical,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	if m, ok := security.FirstMatch(input, sqlMediumPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Suspicious SQL function reference detected: " + m,
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"pattern": m,
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
