// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import "testing"

func TestMaliciousUpload(t *testing.T) {
	d := &MaliciousFileUpload{}
	if r := d.Detect(""); r == nil || r.Name != "upload" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected upload result", r)
	}
	tests := []struct {
		input  string
		should bool
	}{
		{"<?php system('id'); ?>", true},
		{"<?PHP system('id'); ?>", true},
		{"<?= 'hello' ?>", true},
		{"<% response.write 'x' %>", true},
		{"<script>alert(1)</script>", true},
		{"<SCRIPT>alert(1)</SCRIPT>", true},
		{"eval('alert(1)')", true},
		{"system('ls')", true},
		{"exec('whoami')", true},
		{"printf('%s')", false},
		{"<% no close", false},
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

func TestHasMaliciousExt(t *testing.T) {
	tests := []struct {
		filename string
		should   bool
	}{
		{"file.php", true},
		{"file.PHP", true},
		{"file.exe", true},
		{"file.sh", true},
		{"file.jpg", false},
		{"file.JPG", false},
		{"file.PNG", false},
		{"file.pdf", false},
		{"file.tar.gz", true},
		{"file.", true},
		{".htaccess", true},
		{"noextension", true},
		{"", true},
		{"file.php.png", false},
	}
	for _, tc := range tests {
		if got := HasMaliciousExt(tc.filename); got != tc.should {
			t.Errorf("HasMaliciousExt(%q): got %v, want %v", tc.filename, got, tc.should)
		}
	}
}

func TestCheckExtension(t *testing.T) {
	d := &MaliciousFileUpload{}
	tests := []struct {
		filename string
		should   bool
	}{
		{"file.jpg", false},
		{"file.JPG", false},
		{"file.png", false},
		{"file.php", true},
		{"file.exe", true},
		{"file.", true},
		{"noext", true},
		{"", true},
	}
	for _, tc := range tests {
		r := d.CheckExtension(tc.filename)
		if r.Detected != tc.should {
			t.Errorf("CheckExtension(%q): got detected=%v, want %v", tc.filename, r.Detected, tc.should)
		}
	}
}
