// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// RecordFailure counts a failed authentication attempt for token and locks the
// token out once Failures attempts fail within FailureWindow. Call it once per
// failed login attempt; a successful login calls ClearFailures so the count does
// not carry over.
func (t *Tracker) RecordFailure(token string) error {
	if token == "" || t.Store == nil {
		return errors.New("session: empty token")
	}
	key := failureKey(token)
	value, err := t.Store.Load(key)
	if err != nil {
		return err
	}
	n := 0
	if value != nil {
		n, _ = strconv.Atoi(string(value))
	}
	n++
	if n >= t.failures() {
		until := time.Now().Add(t.lockoutDuration())
		if err := t.Store.Save(lockKey(token), []byte(until.UTC().Format(time.RFC3339)), t.lockoutDuration()); err != nil {
			return err
		}
	}
	// The counter is written after the lock so a partial failure still leaves
	// the token locked. A lost count here only resets the counter, not the lock.
	return t.Store.Save(key, []byte(strconv.Itoa(n)), t.failureWindow())
}

// IsLocked reports whether token is locked out and, when it is, until when. A
// store error or an empty token reads as unlocked: an outage is never treated
// as a lockout.
func (t *Tracker) IsLocked(token string) (bool, time.Time) {
	if token == "" || t.Store == nil {
		return false, time.Time{}
	}
	locked, until, err := t.locked(token)
	if err != nil {
		return false, time.Time{}
	}
	return locked, until
}

// ClearFailures drops the failure counter for token, so a correct attempt does
// not count against the next one. A lockout runs on its own timer and is not
// cleared here.
func (t *Tracker) ClearFailures(token string) error {
	if token == "" || t.Store == nil {
		return errors.New("session: empty token")
	}
	return t.Store.Delete(failureKey(token))
}

func failureKey(token string) string { return failuresPrefix + hashToken(token) }

func lockKey(token string) string { return lockPrefix + hashToken(token) }

// locked reports whether token has an unexpired lockout entry and, when it
// does, until when. A missing or malformed entry reads as unlocked.
func (t *Tracker) locked(token string) (bool, time.Time, error) {
	value, err := t.Store.Load(lockKey(token))
	if err != nil {
		return false, time.Time{}, err
	}
	if value == nil {
		return false, time.Time{}, nil
	}
	until, err := time.Parse(time.RFC3339, strings.TrimSpace(string(value)))
	if err != nil {
		return false, time.Time{}, nil
	}
	if !time.Now().Before(until) {
		return false, time.Time{}, nil
	}
	return true, until, nil
}

// failures returns the number of failures within FailureWindow that lock a
// token out.
func (t *Tracker) failures() int {
	if t.Failures <= 0 {
		return defaultFailures
	}
	return t.Failures
}

// failureWindow returns how long the failure counter is kept.
func (t *Tracker) failureWindow() time.Duration {
	if t.FailureWindow <= 0 {
		return defaultFailureWindow
	}
	return t.FailureWindow
}

// lockoutDuration returns how long a lockout lasts.
func (t *Tracker) lockoutDuration() time.Duration {
	if t.Lockout <= 0 {
		return defaultLockout
	}
	return t.Lockout
}
