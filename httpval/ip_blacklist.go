package httpval

import (
	"time"

	"github.com/bag/security-go"
	"github.com/bag/security-go/storage"
)

// IPBlacklist detects and blocks IPs that exceed an attack threshold.
type IPBlacklist struct {
	Storage     storage.Backend
	Threshold   int
	Window      time.Duration
	BanDuration time.Duration
}

// NewIPBlacklist creates an IPBlacklist detector. Defaults: Threshold=5,
// Window=60s, BanDuration=15min.
func NewIPBlacklist(s storage.Backend) *IPBlacklist {
	return &IPBlacklist{
		Storage:     s,
		Threshold:   5,
		Window:      60 * time.Second,
		BanDuration: 15 * time.Minute,
	}
}

// Name returns the detector name.
func (b *IPBlacklist) Name() string {
	return "ip_blacklist"
}

// Detect checks whether the given IP is currently blocked.
func (b *IPBlacklist) Detect(input string) *security.Result {
	blocked, err := b.Storage.IsBlocked(input)
	if err != nil {
		return nil
	}
	if blocked {
		return &security.Result{
			Name:     b.Name(),
			Detected: true,
			Message:  "IP is blocked: " + input,
			Severity: security.SeverityHigh,
		}
	}
	return nil
}

// RecordAttack increments the attack counter for the given IP. If the
// threshold is reached within the window, the IP is blocked and returns true.
func (b *IPBlacklist) RecordAttack(ip string) (bool, error) {
	count, err := b.Storage.Incr(ip, b.Window)
	if err != nil {
		return false, err
	}
	if count >= b.Threshold {
		if err := b.Storage.Block(ip, b.BanDuration); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
