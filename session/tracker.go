// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/erikwang2013/security-go"
)

// Tracker defaults.
const (
	defaultTTL         = 30 * time.Minute
	defaultSubnetBits  = 24
	defaultKnownNets   = 8
	defaultKnownNetTTL = 90 * 24 * time.Hour
	// defaultFailures, defaultFailureWindow and defaultLockout size the
	// brute-force lockout: that many failures inside the window lock the token
	// out for that long.
	defaultFailures      = 5
	defaultFailureWindow = 5 * time.Minute
	defaultLockout       = 15 * time.Minute
	// v6Shift widens SubnetBits for IPv6, where a /24 is a single host.
	v6Shift = 24
	// FingerprintHeader carries an optional client-side device fingerprint
	// (e.g. a value the front-end derives and keeps out of the cookie jar).
	FingerprintHeader = "X-Device-Fingerprint"
	sessionPrefix     = "sess:"
	knownNetsPrefix   = "nets:"
	failuresPrefix    = "fail:"
	lockPrefix        = "lock:"
)

// Tracker binds a token session to the client that created it and reports
// hijacking and remote-login anomalies on every later request.
//
// Tracker is deliberately not a security.Detector: Detect(input string) cannot
// see the request, and the client IP and User-Agent are the entire signal.
type Tracker struct {
	// Store holds session bindings. Required; see MemoryStore.
	Store Store
	// TTL is the sliding session lifetime, refreshed on each accepted request.
	TTL time.Duration
	// SubnetBits is the IPv4 prefix that still counts as the same place.
	// Default 24. Raise it to tolerate mobile networks changing address.
	SubnetBits int
	// CountryOf resolves an IP to a country code, e.g. from a GeoIP database.
	// Optional: when nil, only network and client changes are checked.
	CountryOf func(ip string) string
	// KnownNets caps how many login networks are remembered per user.
	KnownNets int
	// KnownNetTTL is how long a login network is remembered.
	KnownNetTTL time.Duration
	// TokenSource extracts the session token from a request.
	TokenSource func(*http.Request) string
	// TrustProxyHeaders takes the client IP from X-Forwarded-For / X-Real-IP.
	// Leave false unless a trusted proxy sets them: both headers are
	// client-controlled and would let a hijacker forge the bound IP.
	TrustProxyHeaders bool
	// FailClosed rejects requests while the store is unavailable. Default false,
	// matching IPBlacklist: an outage lets traffic through rather than locking
	// every user out.
	FailClosed bool
	// Failures is the number of authentication failures inside FailureWindow that
	// lock a token out. 0 means defaultFailures (5).
	Failures int
	// FailureWindow is how long the failure counter is kept, so failures spread
	// out beyond it no longer count. 0 means defaultFailureWindow (5 minutes).
	FailureWindow time.Duration
	// Lockout is how long a locked token stays locked. 0 means defaultLockout
	// (15 minutes).
	Lockout time.Duration
}

// NewTracker creates a Tracker with defaults: 30 minute sliding TTL, /24 IP
// matching, 8 remembered login networks, and tokens read from the
// "Authorization: Bearer" header or the "session" cookie.
func NewTracker(s Store) *Tracker {
	return &Tracker{
		Store:         s,
		TTL:           defaultTTL,
		SubnetBits:    defaultSubnetBits,
		KnownNets:     defaultKnownNets,
		KnownNetTTL:   defaultKnownNetTTL,
		TokenSource:   DefaultTokenSource,
		Failures:      defaultFailures,
		FailureWindow: defaultFailureWindow,
		Lockout:       defaultLockout,
	}
}

// Name returns the detector name.
func (t *Tracker) Name() string {
	return "session_guard"
}

// DefaultTokenSource reads "Authorization: Bearer <token>", falling back to the
// "session" cookie. Replace TokenSource for any other scheme.
func DefaultTokenSource(r *http.Request) string {
	if r == nil {
		return ""
	}
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if c, err := r.Cookie("session"); err == nil {
		return c.Value
	}
	return ""
}

// Issue binds token to the client that made r. Call once, at login, before the
// token is handed to the client.
func (t *Tracker) Issue(token string, r *http.Request) error {
	if token == "" {
		return errors.New("session: empty token")
	}
	now := time.Now()
	s := &Session{
		IP:          t.clientIP(r),
		UserAgent:   userAgent(r),
		Fingerprint: fingerprint(r),
		IssuedAt:    now,
		LastSeen:    now,
	}
	if t.CountryOf != nil {
		s.Country = t.CountryOf(s.IP)
	}
	return t.save(token, s)
}

// Revoke drops the session bound to token, ending it immediately. Call it on
// logout, and on any hijack you decide to block.
func (t *Tracker) Revoke(token string) error {
	return t.Store.Delete(sessionKey(token))
}

// Check validates the session behind the request's token and returns a
// detection when the token is unknown or expired, the client changed
// (客户端被劫持) or the network changed (异地登录). Details["reason"] names the
// check that fired.
func (t *Tracker) Check(r *http.Request) *security.Result {
	token := ""
	if t.TokenSource != nil {
		token = t.TokenSource(r)
	}
	if token == "" {
		return deny(t.Name(), "missing_token", "request carries no session token", security.SeverityHigh)
	}

	s, err := t.load(token)
	if err != nil {
		return t.storeError(err)
	}
	if locked, until, err := t.locked(token); err != nil {
		return t.storeError(err)
	} else if locked {
		return deny(t.Name(), "token_locked", "token is locked after repeated failed attempts until "+until.Format(time.RFC3339), security.SeverityCritical)
	}
	if s == nil {
		return deny(t.Name(), "unknown_token", "session token is unknown or expired", security.SeverityHigh)
	}
	return t.verify(r, token, s)
}

// Guard wraps next with session enforcement: any detection from Check,
// including a missing or expired token, answers 401 before the handler runs.
func (t *Tracker) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if res := t.Check(r); res.Detected {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Observe remembers the network r logged in from as a known location for user
// and reports 异地登录 when that network has not been seen before. Call it at
// login, once the user is authenticated; a user's first login never alerts
// because there is no baseline to compare against.
func (t *Tracker) Observe(user string, r *http.Request) *security.Result {
	if user == "" {
		return &security.Result{Name: t.Name(), Detected: false}
	}
	key := knownNetsPrefix + user
	nets, err := t.loadNets(key)
	if err != nil {
		return t.storeError(err)
	}

	here := network(t.clientIP(r), t.subnetBits())
	for _, n := range nets {
		if n == here {
			return &security.Result{Name: t.Name(), Detected: false}
		}
	}

	known := len(nets) > 0 // no baseline yet, so nothing to compare against
	nets = append(nets, here)
	if max := t.knownNets(); len(nets) > max {
		nets = nets[len(nets)-max:]
	}
	ttl := t.KnownNetTTL
	if ttl <= 0 {
		ttl = defaultKnownNetTTL
	}
	if err := t.saveNets(key, nets, ttl); err != nil && t.FailClosed {
		return t.storeError(err)
	}
	if !known {
		return &security.Result{Name: t.Name(), Detected: false}
	}
	return deny(t.Name(), "remote_login", "login from an unseen network: "+here, security.SeverityHigh)
}

func (t *Tracker) verify(r *http.Request, token string, s *Session) *security.Result {
	ip := t.clientIP(r)

	// 客户端被劫持: the same token presented by a different client.
	if s.UserAgent != "" && userAgent(r) != s.UserAgent {
		return deny(t.Name(), "client_hijack", "user agent changed for this session", security.SeverityCritical)
	}
	if s.Fingerprint != "" {
		if fp := fingerprint(r); fp != "" && fp != s.Fingerprint {
			return deny(t.Name(), "client_hijack", "device fingerprint changed for this session", security.SeverityCritical)
		}
	}

	// 异地登录: the same token used from somewhere else.
	if t.CountryOf != nil && s.Country != "" {
		if c := t.CountryOf(ip); c != "" && c != s.Country {
			return deny(t.Name(), "remote_login", "country changed for this session: "+s.Country+" -> "+c, security.SeverityCritical)
		}
	}
	if network(ip, t.subnetBits()) != network(s.IP, t.subnetBits()) {
		return deny(t.Name(), "remote_login", "network changed for this session: "+s.IP+" -> "+ip, security.SeverityHigh)
	}

	s.LastSeen = time.Now()
	if err := t.save(token, s); err != nil && t.FailClosed {
		return t.storeError(err)
	}
	return &security.Result{Name: t.Name(), Detected: false}
}

func (t *Tracker) storeError(err error) *security.Result {
	if !t.FailClosed {
		return &security.Result{Name: t.Name(), Detected: false}
	}
	return deny(t.Name(), "store_error", "session store unavailable: "+err.Error(), security.SeverityHigh)
}

func (t *Tracker) load(token string) (*Session, error) {
	value, err := t.Store.Load(sessionKey(token))
	if err != nil || value == nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(value, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (t *Tracker) save(token string, s *Session) error {
	value, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return t.Store.Save(sessionKey(token), value, t.ttl())
}

func (t *Tracker) loadNets(key string) ([]string, error) {
	value, err := t.Store.Load(key)
	if err != nil || value == nil {
		return nil, err
	}
	var nets []string
	if err := json.Unmarshal(value, &nets); err != nil {
		return nil, err
	}
	return nets, nil
}

func (t *Tracker) saveNets(key string, nets []string, ttl time.Duration) error {
	value, err := json.Marshal(nets)
	if err != nil {
		return err
	}
	return t.Store.Save(key, value, ttl)
}

func (t *Tracker) ttl() time.Duration {
	if t.TTL <= 0 {
		return defaultTTL
	}
	return t.TTL
}

func (t *Tracker) subnetBits() int {
	if t.SubnetBits <= 0 {
		return defaultSubnetBits
	}
	return t.SubnetBits
}

func (t *Tracker) knownNets() int {
	if t.KnownNets <= 0 {
		return defaultKnownNets
	}
	return t.KnownNets
}

// clientIP returns the request's client IP without its port, honouring proxy
// headers only when TrustProxyHeaders is set.
func (t *Tracker) clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if t.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
				return ip.String()
			}
		}
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func userAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.UserAgent()
}

func fingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get(FingerprintHeader)
}

// hashToken hashes the token, so a dump of the store cannot hand out live
// session tokens.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionKey(token string) string { return sessionPrefix + hashToken(token) }

// network renders ip as the CIDR prefix that counts as one place, so a client
// moving inside its own subnet is not treated as being somewhere else. An
// address that does not parse is returned unchanged.
func network(ip string, bits int) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	size := 128
	if v4 := p.To4(); v4 != nil {
		p, size = v4, 32
	} else {
		bits += v6Shift
	}
	if bits < 0 {
		bits = 0
	}
	if bits > size {
		bits = size
	}
	return p.Mask(net.CIDRMask(bits, size)).String() + "/" + strconv.Itoa(bits)
}

// deny builds a positive detection result. Shared with Signer.
func deny(name, reason, message string, severity security.Severity) *security.Result {
	return &security.Result{
		Name:     name,
		Detected: true,
		Message:  message,
		Severity: severity,
		Details:  map[string]interface{}{"reason": reason},
	}
}
