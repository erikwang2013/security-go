// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/erikwang2013/security-go"
)

var allowedExt = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".gif":  true,
	".webp": true,
	".pdf":  true,
	".doc":  true,
	".docx": true,
	".xls":  true,
	".xlsx": true,
	".txt":  true,
	".csv":  true,
	".mp4":  true,
	".mp3":  true,
	".zip":  true,
}

var maliciousContentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\?php`),
	regexp.MustCompile(`<\?=`),
	regexp.MustCompile(`<%[^%]*%>`),
	regexp.MustCompile(`(?i)<script`),
}

// code functions are suspicious on their own (Medium) but only clearly
// malicious when combined with a script tag or PHP marker above (High)
var codeEvalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)eval\s*\(`),
	regexp.MustCompile(`(?i)system\s*\(`),
	regexp.MustCompile(`(?i)exec\s*\(`),
}

// MaliciousFileUpload is a detector for malicious file uploads.
type MaliciousFileUpload struct{}

// Name returns the detector name.
func (d *MaliciousFileUpload) Name() string {
	return "upload"
}

// Detect scans the input for malicious content patterns.
func (d *MaliciousFileUpload) Detect(input string) *security.Result {
	if m, ok := security.FirstMatch(input, maliciousContentPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Malicious content detected: " + m,
			Severity: security.SeverityHigh,
		}
	}
	if m, ok := security.FirstMatch(input, codeEvalPatterns); ok {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "Suspicious code function detected: " + m,
			Severity: security.SeverityMedium,
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}

// HasMaliciousExt checks whether the filename has a non-whitelisted extension.
func HasMaliciousExt(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		return true
	}
	return !allowedExt[ext]
}

// CheckExtension checks the filename extension and returns a detection result.
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "File has no extension",
			Severity: security.SeverityMedium,
		}
	}
	if !allowedExt[ext] {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "File extension not allowed: " + filename,
			Severity: security.SeverityMedium,
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
