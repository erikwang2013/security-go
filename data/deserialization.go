// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import (
	"regexp"

	"github.com/erikwang2013/security-go"
)

// PHP serialized tokens: strong signals, reported at Critical.
var phpPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)O:\d+:`),
	regexp.MustCompile(`(?i)C:\d+:`),
	regexp.MustCompile(`(?i)a:\d+:\{`),
	regexp.MustCompile(`(?i)s:\d+:"`),
	regexp.MustCompile(`(?i)__PHP_Incomplete_Class`),
}

// PHP magic-method function names. A bare occurrence is suspicious but common
// in PHP tutorials (unserialize(, __toString), so it reports at Medium.
var phpMediumPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:unserialize|__wakeup|__destruct|__toString|__call|__get|__set|__isset|__unset|__sleep)\s*\(`),
}

// Python pickle: PROTO header (bytes 0x80 + 0x04/0x05), GLOBAL module
// opcodes, and the __reduce__ reduction protocol. Case flags are pointless
// for byte markers, so these are matched literally. GLOBAL names keep their
// terminating newline so a bare word such as "cposix.h" does not match.
var pythonPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\x80[\x04\x05]`),
	regexp.MustCompile(`c\nos\nsystem\n`),
	regexp.MustCompile(`c__main__\n`),
	regexp.MustCompile(`cbinascii\n`),
	regexp.MustCompile(`cposix\n`),
	regexp.MustCompile(`__reduce__\s*\(`),
}

// Java ObjectInputStream: base64 prefix of the ACED stream magic
// (protocols 5 and 6 both start with rO0AB), array type descriptors, and
// framework form keys.
var javaPatterns = []*regexp.Regexp{
	regexp.MustCompile(`rO0A[BC]`),
	regexp.MustCompile(`\[\[Ljava\.lang\.String;`),
	regexp.MustCompile(`(?i)(?:javaObject|serializedObject)`),
}

// .NET BinaryFormatter / TypeDescriptor type names.
var dotnetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)System\.__Serialization`),
	regexp.MustCompile(`(?i)System\.Runtime\.Serialization\.Formatters\.Binary\.BinaryFormatter`),
	regexp.MustCompile(`(?i)__typeinfo`),
	regexp.MustCompile(`\[System\.IO\.FileStream`),
}

// orderedLanguages is scanned in a fixed order; the first language that
// matches wins and no later pattern set is evaluated.
var orderedLanguages = []struct {
	name     string
	patterns []*regexp.Regexp
}{
	{"php", phpPatterns},
	{"python", pythonPatterns},
	{"java", javaPatterns},
	{"dotnet", dotnetPatterns},
}

// Deserialization detects PHP, Python pickle, Java, and .NET
// deserialization attacks.
type Deserialization struct{}

// Name returns the detector name.
func (d *Deserialization) Name() string {
	return "deserialization"
}

// Detect checks input for deserialization attack patterns. Strong per-language
// signatures report at Critical; a bare PHP magic-method reference, which PHP
// tutorials trip constantly, reports at Medium.
func (d *Deserialization) Detect(input string) *security.Result {
	for _, lang := range orderedLanguages {
		if m, ok := security.FirstMatch(input, lang.patterns); ok {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "Deserialization attack pattern detected (" + lang.name + "): " + m,
				Severity: security.SeverityCritical,
				Details: map[string]interface{}{
					"pattern":  m,
					"language": lang.name,
				},
			}
		}
	}
	if m, ok := security.FirstMatch(input, phpMediumPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Suspicious deserialization function reference detected: " + m,
			Severity: security.SeverityMedium,
			Details: map[string]interface{}{
				"pattern":  m,
				"language": "php",
			},
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
