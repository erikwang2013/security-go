package injection

import (
	"regexp"

	"github.com/bag/security-go"
)

var sqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)union\s+(?:/\*.*?\*/\s*)*select`),
	regexp.MustCompile(`(?i)union\s*\(\s*select`),
	regexp.MustCompile(`(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(`),
	regexp.MustCompile(`(?i)\b(?:information_schema|mysql\.|pg_catalog|sys\.tables|sqlite_master)\b`),
	regexp.MustCompile(`(?i)\b(?:load_file|into\s+(?:out|dump)file)\b`),
	regexp.MustCompile(`(?i)(?:'|\s)(?:or|and)\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`(?i)'\s*(?:or|and)\s+'[^']*'\s*=\s*'[^']*'?`),
	regexp.MustCompile(`(?i)waitfor\s+delay`),
	regexp.MustCompile(`(?i)\b(?:exec|execute)\s+(?:master\.\.|xp_)`),
	regexp.MustCompile(`(?i)\b(?:exec|execute)\s*\(\s*(?:master\.\.|xp_)`),
	regexp.MustCompile(`(?i)(?:--|#|/\*).*$`),
	regexp.MustCompile(`(?i)\b(?:hex|char|ascii|concat)\s*\(`),
}

// SQL detects SQL injection attempts.
type SQL struct{}

func (d *SQL) Name() string {
	return "sql_injection"
}

func (d *SQL) Detect(input string) *security.Result {
	for _, p := range sqlPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "SQL injection pattern detected: " + p.String(),
				Severity: security.SeverityCritical,
				Details: map[string]interface{}{
					"pattern": p.String(),
				},
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
