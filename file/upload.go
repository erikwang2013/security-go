// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package file

import (
	"regexp"
	"strings"

	"github.com/bag/security-go"
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
	regexp.MustCompile(`<\?php`),
	regexp.MustCompile(`<\?=`),
	regexp.MustCompile(`<%[^%]*%>`),
	regexp.MustCompile(`(?i)<script`),
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
	for _, p := range maliciousContentPatterns {
		if p.MatchString(input) {
			return &security.Result{
				Name:     d.Name(),
				Detected: true,
				Message:  "Malicious content detected: " + p.String(),
				Severity: security.SeverityHigh,
			}
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}

// HasMaliciousExt checks whether the filename has a non-whitelisted extension.
func HasMaliciousExt(filename string) bool {
	idx := strings.LastIndex(filename, ".")
	if idx == -1 {
		return true
	}
	ext := strings.ToLower(filename[idx:])
	return !allowedExt[ext]
}

// CheckExtension checks the filename extension and returns a detection result.
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result {
	if strings.LastIndex(filename, ".") == -1 {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "File has no extension",
			Severity: security.SeverityMedium,
		}
	}
	if HasMaliciousExt(filename) {
		return &security.Result{
			Name:     d.Name(),
			Detected: true,
			Message:  "File extension not allowed: " + filename,
			Severity: security.SeverityMedium,
		}
	}
	return &security.Result{Name: d.Name(), Detected: false}
}
