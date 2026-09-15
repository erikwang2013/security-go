// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import (
	"strings"
	"testing"

	"github.com/erikwang2013/security-go"
)

func TestDeserialization(t *testing.T) {
	d := &Deserialization{}
	if d.Name() != "deserialization" {
		t.Fatalf("Name() = %q, want %q", d.Name(), "deserialization")
	}
	if r := d.Detect(""); r == nil || r.Name != "deserialization" || r.Detected || r.Details != nil {
		t.Fatalf("empty input: got %+v, want not-detected deserialization result", r)
	}
	tests := []struct {
		name   string
		input  string
		should bool
		lang   string
		medium bool
	}{
		// PHP strong signals.
		{"php object", `O:8:"stdClass":0:{}`, true, "php", false},
		{"php object zero length", `O:0:"x":0:{}`, true, "php", false},
		{"php custom class", `C:11:"ArrayObject":21:{x:i:0;a:0:{}}`, true, "php", false},
		{"php array", `a:2:{i:0;s:4:"test";i:1;s:5:"hello";}`, true, "php", false},
		{"php string", `s:4:"test"`, true, "php", false},
		{"php incomplete class", `__PHP_Incomplete_Class`, true, "php", false},

		// PHP magic-method names: suspicious but tutorial-common, so Medium.
		{"php unserialize", `unserialize($payload)`, true, "php", true},
		{"php __wakeup", `__wakeup()`, true, "php", true},
		{"php __destruct", `__destruct()`, true, "php", true},
		{"php __toString", `__toString()`, true, "php", true},
		{"php __call", `__call()`, true, "php", true},
		{"php __get", `__get()`, true, "php", true},
		{"php __set", `__set()`, true, "php", true},
		{"php __isset", `__isset()`, true, "php", true},
		{"php __unset", `__unset()`, true, "php", true},
		{"php __sleep", `__sleep()`, true, "php", true},

		// Python pickle.
		{"python pickle protocol 5", "\x80\x05c\nos\nsystem\n(S'calc'\ntR.", true, "python", false},
		{"python pickle global main", "c__main__\n", true, "python", false},
		{"python __reduce__", "__reduce__()", true, "python", false},

		// Java.
		{"java stream magic", "rO0ABXc2AQACAAgACgAIAEYACgAMAEoADQAQABEAFAAYABkAGgAaABwAHgAgACEA=", true, "java", false},
		{"java array descriptor", "[[Ljava.lang.String;", true, "java", false},
		{"java shiro form key", "javaObject=AAAA", true, "java", false},
		{"java form key casefold", "serializedObject=AAAA", true, "java", false},

		// .NET.
		{"dotnet serialization", "System.__Serialization", true, "dotnet", false},
		{"dotnet binary formatter", "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", true, "dotnet", false},
		{"dotnet filestream type", "[System.IO.FileStream", true, "dotnet", false},
		{"dotnet typeinfo", "__typeinfo", true, "dotnet", false},

		// Negatives — the regression cases that matter most.
		{"nonnumeric object", `O:abc:{}`, false, "", false},
		{"serialize verb", `serialize($data)`, false, "", false},
		{"plain text", `normal text`, false, "", false},
		{"greeting", `hello world`, false, "", false},
		{"oop json document", `{"title": "Object-Oriented Programming", "body": "Classes and objects support code reuse; serialization formats include JSON and XML."}`, false, "", false},
		{"oop sentence", `The design is an object-oriented class hierarchy with several output formats.`, false, "", false},
		{"query string", `?object=123&class=Widget&format=json`, false, "", false},
		{"reduce without paren", `__reduce__ is a pickle opcode`, false, "", false},
		{"short java prefix", `rO0 alone`, false, "", false},
		{"pickle protocol 3", "\x80\x03cos", false, "", false},
		{"descriptor without array prefix", `Ljava.lang.String;`, false, "", false},
		{"stream without type prefix", `System.IO.Stream`, false, "", false},
		{"plain string word", `a plain String value`, false, "", false},
		{"bare cposix", `cposix.h`, false, "", false},
		{"bare cbinascii", `#include <cbinascii>`, false, "", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("%s: input=%q: got detected=%v, want %v", tc.name, tc.input, r.Detected, tc.should)
			continue
		}
		if !tc.should {
			continue
		}
		if tc.medium {
			if r.Severity != security.SeverityMedium {
				t.Errorf("%s: Severity = %v, want %v", tc.name, r.Severity, security.SeverityMedium)
			}
			want := "Suspicious deserialization function reference detected: "
			if !strings.HasPrefix(r.Message, want) {
				t.Errorf("%s: Message = %q, want prefix %q", tc.name, r.Message, want)
			}
		} else {
			if r.Severity != security.SeverityCritical {
				t.Errorf("%s: Severity = %v, want %v", tc.name, r.Severity, security.SeverityCritical)
			}
			want := "Deserialization attack pattern detected (" + tc.lang + "): "
			if !strings.HasPrefix(r.Message, want) {
				t.Errorf("%s: Message = %q, want prefix %q", tc.name, r.Message, want)
			}
		}
		if r.Details["language"] != tc.lang {
			t.Errorf("%s: Details[language] = %v, want %v", tc.name, r.Details["language"], tc.lang)
		}
		if p, _ := r.Details["pattern"].(string); p == "" {
			t.Errorf("%s: Details[pattern] is empty", tc.name)
		}
	}
}
