// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import "testing"

func TestPathTraversal(t *testing.T) {
	d := &PathTraversal{}
	tests := []struct {
		input  string
		should bool
	}{
		{"../../../etc/passwd", true},
		{"..\\..\\..\\windows\\win.ini", true},
		{"php://filter/convert.base64-encode/resource=index.php", true},
		{"%00", true},
		{"..%2f..%2fetc/passwd", true},
		{"/etc/passwd", true},
		{"C:\\Windows\\System32\\drivers\\etc\\hosts", true},
		{"file:///etc/hosts", true},
		{"phar://evil.phar/file", true},
		{"normal/file.txt", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
