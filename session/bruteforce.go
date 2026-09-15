// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/erikwang2013/security-go"
)

// Login-side brute-force protection. Two attacks are covered:
//
//   - one identity, many passwords — the failure counter and progressive
//     lockout in lockout.go;
//   - one client, many identities (credential stuffing) — the distinct-identity
//     list keyed by client IP.
//
// Both are reached through RecordFailure/CheckLogin, or through GuardLogin for
// an authentication endpoint.

// RecordFailure counts a failed authentication attempt for identity (a
// username, an email, or any key the application authenticates by) made from
// the client behind r, and locks the identity out once Failures attempts fail
// inside FailureWindow.
//
// Each lockout episode doubles the next one, up to MaxLockout, so a client that
// keeps going after a lockout expires escalates instead of starting over. The
// escalation is remembered for BackoffWindow.
func (t *Tracker) RecordFailure(identity string, r *http.Request) error {
	if identity == "" || t.Store == nil {
		return errors.New("session: empty identity")
	}
	value, err := t.Store.Load(failureKey(identity))
	if err != nil {
		return err
	}
	n := 0
	if value != nil {
		n, _ = strconv.Atoi(string(value))
	}
	n++

	locked, _, err := t.locked(identity)
	if err != nil {
		return err
	}
	if n >= t.failures() && !locked {
		// A fresh crossing: remember it, then lock for the escalated duration.
		strikes, err := t.bump(strikeKey(identity), t.backoffWindow())
		if err != nil {
			return err
		}
		d := t.lockFor(strikes)
		until := time.Now().Add(d).UTC().Format(time.RFC3339)
		if err := t.Store.Save(lockKey(identity), []byte(until), d); err != nil {
			return err
		}
	}

	// Stuffing is recorded before the counter so a partial failure still
	// contributes to the per-client view.
	if err := t.recordStuffing(identity, t.clientIP(r)); err != nil {
		return err
	}
	return t.Store.Save(failureKey(identity), []byte(strconv.Itoa(n)), t.failureWindow())
}

// CheckLogin is the pre-flight check for a login attempt: it reports when the
// identity is locked out (token_locked, Critical) or when the client IP has
// already failed against StuffingLimit distinct identities inside
// FailureWindow (credential_stuffing, Critical). A clean result means the
// attempt should be processed normally.
func (t *Tracker) CheckLogin(identity string, r *http.Request) *security.Result {
	if identity != "" {
		if locked, until, err := t.locked(identity); err != nil {
			return t.storeError(err)
		} else if locked {
			return deny(t.Name(), "token_locked", "identity is locked after repeated failed attempts until "+until.Format(time.RFC3339), security.SeverityCritical)
		}
	}
	if ip := t.clientIP(r); ip != "" && t.stuffingCount(ip) >= t.stuffingLimit() {
		return deny(t.Name(), "credential_stuffing", "one client failed against many distinct identities: "+ip, security.SeverityCritical)
	}
	return &security.Result{Name: t.Name(), Detected: false}
}

// GuardLogin wraps an authentication endpoint with brute-force enforcement.
// identity must be non-nil and return the key the endpoint authenticates by —
// a nil or empty result disables the identity checks for that request, so do
// not pass nil.
//
// A locked identity or a stuffing client answers 429 before the handler runs.
// After it runs, a 401 counts as a failed attempt and any 2xx clears the
// counter, so the handler only has to be honest about its status code.
func (t *Tracker) GuardLogin(next http.Handler, identity func(*http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := ""
		if identity != nil {
			id = identity(r)
		}
		if res := t.CheckLogin(id, r); res.Detected {
			if locked, until := t.IsLocked(id); locked {
				if secs := int(time.Until(until).Seconds()); secs > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(secs))
				}
			}
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}

		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		switch {
		case sw.status == http.StatusUnauthorized:
			// A store error here fails open, matching IsLocked: an outage must
			// not be able to lock every identity out.
			_ = t.RecordFailure(id, r)
		case sw.status >= 200 && sw.status < 300:
			_ = t.ClearFailures(id)
		}
	})
}

// statusWriter records the status code the wrapped handler wrote.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// bump increments a decimal counter under key and returns the new value.
func (t *Tracker) bump(key string, ttl time.Duration) (int, error) {
	value, err := t.Store.Load(key)
	if err != nil {
		return 0, err
	}
	n := 0
	if value != nil {
		n, _ = strconv.Atoi(string(value))
	}
	n++
	if err := t.Store.Save(key, []byte(strconv.Itoa(n)), ttl); err != nil {
		return 0, err
	}
	return n, nil
}

// lockFor returns the lockout after strikes threshold crossings: Lockout, then
// double for each further crossing, never above MaxLockout.
func (t *Tracker) lockFor(strikes int) time.Duration {
	d := t.lockoutDuration()
	max := t.maxLockout()
	for i := 1; i < strikes; i++ {
		if d >= max/2 {
			return max
		}
		d *= 2
	}
	if d > max {
		return max
	}
	return d
}

// recordStuffing remembers the hashed identity under the client IP, so a client
// that sweeps many identities reads as credential stuffing. Every identity is
// hashed before storage: an identity is a username, and the store should not
// hold those in the clear.
func (t *Tracker) recordStuffing(identity, ip string) error {
	if ip == "" {
		return nil
	}
	key := stuffingKey(ip)
	// Reuses the known-net list encoding: both are a capped JSON []string.
	ids, err := t.loadNets(key)
	if err != nil {
		return err
	}
	h := hashToken(identity)
	for _, id := range ids {
		if id == h {
			return nil // already counted; nothing to rewrite
		}
	}
	ids = append(ids, h)
	if max := t.stuffingLimit(); len(ids) > max {
		ids = ids[len(ids)-max:]
	}
	return t.saveNets(key, ids, t.failureWindow())
}

// stuffingCount reports how many distinct identities the client IP has failed
// against inside FailureWindow.
func (t *Tracker) stuffingCount(ip string) int {
	ids, err := t.loadNets(stuffingKey(ip))
	if err != nil {
		return 0
	}
	return len(ids)
}

func strikeKey(identity string) string { return strikesPrefix + hashToken(identity) }

func stuffingKey(ip string) string { return stuffingPrefix + hashToken(ip) }

func (t *Tracker) maxLockout() time.Duration {
	if t.MaxLockout <= 0 {
		return defaultMaxLockout
	}
	return t.MaxLockout
}

func (t *Tracker) backoffWindow() time.Duration {
	if t.BackoffWindow <= 0 {
		return defaultBackoffWindow
	}
	return t.BackoffWindow
}

func (t *Tracker) stuffingLimit() int {
	if t.StuffingLimit <= 0 {
		return defaultStuffingLimit
	}
	return t.StuffingLimit
}
