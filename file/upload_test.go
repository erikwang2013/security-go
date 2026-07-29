// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import "testing"

func TestMaliciousUpload(t *testing.T) {
	d := &MaliciousFileUpload{}
	tests := []struct {
		input  string
		should bool
	}{
		{"<?php system('id'); ?>", true},
		{"<?= 'hello' ?>", true},
		{"<script>alert(1)</script>", true},
		{"eval('alert(1)')", true},
		{"system('ls')", true},
		{"exec('whoami')", true},
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
	if HasMaliciousExt("file.php") != true {
		t.Error("expected .php to be malicious")
	}
	if HasMaliciousExt("file.jpg") != false {
		t.Error("expected .jpg to be allowed")
	}
	if HasMaliciousExt("noextension") != true {
		t.Error("expected no extension to be malicious")
	}
	if HasMaliciousExt("file.PHP") != true {
		t.Error("expected .PHP (uppercase) to be malicious")
	}
}

func TestCheckExtension(t *testing.T) {
	d := &MaliciousFileUpload{}

	r := d.CheckExtension("file.jpg")
	if r.Detected {
		t.Error("expected .jpg to be allowed")
	}

	r = d.CheckExtension("file.php")
	if !r.Detected {
		t.Error("expected .php to be detected")
	}

	r = d.CheckExtension("noext")
	if !r.Detected {
		t.Error("expected no extension to be detected")
	}
}
