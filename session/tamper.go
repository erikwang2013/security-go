// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/erikwang2013/security-go"
	"github.com/erikwang2013/security-go/storage"
)

// Signer defaults.
const (
	defaultMaxSkew = 5 * time.Minute
	nonceBytes     = 16
	nonceKeyPrefix = "sig:"
	signatureParts = 3
	signerName     = "data_tamper"
)

// Signer detects 篡改数据: it signs request parameters with HMAC-SHA256 and
// verifies them on the server, catching modified, forged, expired and replayed
// payloads.
type Signer struct {
	// Secret is the shared HMAC key. Generate it with crypto/rand and keep it
	// out of source control.
	Secret []byte
	// MaxSkew is how far a signature timestamp may differ from now. Default 5m.
	MaxSkew time.Duration
	// Nonces counts seen nonces so a captured signature cannot be replayed.
	// Optional: when nil only the timestamp bounds a signature's life. Reuse a
	// storage.Backend (Memory/File/Redis) to catch replays across instances.
	Nonces storage.Backend
}

// NewSigner creates a Signer. Pass nil for nonces to skip replay detection.
func NewSigner(secret []byte, nonces storage.Backend) *Signer {
	return &Signer{Secret: secret, MaxSkew: defaultMaxSkew, Nonces: nonces}
}

// Name returns the detector name.
func (s *Signer) Name() string {
	return signerName
}

// Sign returns "<unix-ts>.<nonce>.<mac>" for params. Send it alongside the
// parameters; the server recomputes it in Verify.
func (s *Signer) Sign(params map[string]string) (string, error) {
	if len(s.Secret) == 0 {
		return "", errors.New("session: signer has no secret")
	}
	buf := make([]byte, nonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := hex.EncodeToString(buf)
	return ts + "." + nonce + "." + s.mac(params, ts, nonce), nil
}

// Verify checks sig against params and returns a detection when the payload was
// altered (篡改), the signature was forged, expired, or replayed.
func (s *Signer) Verify(params map[string]string, sig string) *security.Result {
	if len(s.Secret) == 0 {
		return deny(s.Name(), "signer_not_configured",
			"signer has no secret; refusing to trust unsigned data", security.SeverityCritical)
	}
	parts := strings.Split(sig, ".")
	if len(parts) != signatureParts {
		return deny(s.Name(), "signature_malformed", "signature must have exactly three parts", security.SeverityHigh)
	}
	ts, nonce, mac := parts[0], parts[1], parts[2]

	// Freshness first: rejecting a stale signature is cheap, and it keeps old
	// nonces from being mistaken for replays.
	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return deny(s.Name(), "timestamp_invalid", "signature timestamp is not a unix time", security.SeverityHigh)
	}
	if skew := time.Since(time.Unix(secs, 0)); skew > s.maxSkew() || skew < -s.maxSkew() {
		reason := "signature_expired"
		if skew < 0 {
			reason = "timestamp_in_future"
		}
		return deny(s.Name(), reason, "signature timestamp outside ±"+s.maxSkew().String(), security.SeverityHigh)
	}

	// Signature before the replay check: a forged signature must not be able to
	// burn a legitimate nonce.
	if !hmac.Equal([]byte(mac), []byte(s.mac(params, ts, nonce))) {
		return deny(s.Name(), "signature_mismatch", "parameters do not match the signature", security.SeverityCritical)
	}

	if s.Nonces != nil {
		count, err := s.Nonces.Incr(nonceKeyPrefix+nonce, 2*s.maxSkew())
		if err == nil && count > 1 {
			return deny(s.Name(), "replay", "signature nonce has already been used", security.SeverityCritical)
		}
	}
	return &security.Result{Name: s.Name(), Detected: false}
}

// mac covers the canonical parameters plus the timestamp and nonce, so none of
// the three can be altered on their own.
func (s *Signer) mac(params map[string]string, ts, nonce string) string {
	h := hmac.New(sha256.New, s.Secret)
	h.Write([]byte(canonical(params)))
	h.Write([]byte{'\n'})
	h.Write([]byte(ts))
	h.Write([]byte{'\n'})
	h.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (s *Signer) maxSkew() time.Duration {
	if s.MaxSkew <= 0 {
		return defaultMaxSkew
	}
	return s.MaxSkew
}

// canonical renders params in a stable order with escaping, so the same
// parameters always hash the same regardless of map iteration order.
func canonical(params map[string]string) string {
	values := url.Values{}
	for key, value := range params {
		values.Set(key, value)
	}
	return values.Encode()
}
