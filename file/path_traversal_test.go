// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import "testing"

func TestPathTraversal(t *testing.T) {
	d := &PathTraversal{}
	if r := d.Detect(""); r == nil || r.Name != "path_traversal" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected path_traversal result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"../../../etc/passwd", true},
		{"..\\..\\..\\windows\\win.ini", true},
		{"..%5c..%5cwindows\\win.ini", true},
		{"%2e%2e/etc/passwd", true},
		{"%2e%2e\\windows\\win.ini", true},
		{"%252e%252e/etc/passwd", true},
		{"php://filter/convert.base64-encode/resource=index.php", true},
		{"php://input", true},
		{"data://text/plain,hello", true},
		{"expect://id", true},
		{"zip://archive.zip#evil", true},
		{"%00", true},
		{"evil\x00.jpg", true},
		{"..%2f..%2fetc/passwd", true},
		{"..%2F..%2Fetc/passwd", true},
		{"/etc/passwd", true},
		{"/etc/shadow", true},
		{"/etc/hosts", true},
		{"C:\\Windows\\System32\\drivers\\etc\\hosts", true},
		{"C:\\Windows\\win.ini", true},
		{"file:///etc/hosts", true},
		{"phar://evil.phar/file", true},
		{"normal/file.txt", false},
		{"images/photo.jpg", false},
		{"..", false},
		{"...", false},
		{"a.b.c", false},
		{"etc/passwd", false},
	}
	for _, tc := range tests {
		r := d.Detect(tc.input)
		if r.Detected != tc.should {
			t.Errorf("input=%q: got detected=%v, want %v", tc.input, r.Detected, tc.should)
		}
	}
}
