// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"errors"
	"strings"
	"time"
)

// Storage primitives for the brute-force lockout. RecordFailure, CheckLogin and
// GuardLogin live in bruteforce.go; this file holds the keys, the lock lookup
// and the configured durations.

// IsLocked reports whether identity is locked out and, when it is, until when. A
// store error or an empty identity reads as unlocked: an outage is never treated
// as a lockout.
func (t *Tracker) IsLocked(identity string) (bool, time.Time) {
	if identity == "" || t.Store == nil {
		return false, time.Time{}
	}
	locked, until, err := t.locked(identity)
	if err != nil {
		return false, time.Time{}
	}
	return locked, until
}

// ClearFailures drops the failure counter and the escalation strikes for
// identity, so a correct attempt does not count against the next one. A lockout
// runs on its own timer and is not cleared here.
func (t *Tracker) ClearFailures(identity string) error {
	if identity == "" || t.Store == nil {
		return errors.New("session: empty identity")
	}
	if err := t.Store.Delete(failureKey(identity)); err != nil {
		return err
	}
	return t.Store.Delete(strikeKey(identity))
}

func failureKey(identity string) string { return failuresPrefix + hashToken(identity) }

func lockKey(identity string) string { return lockPrefix + hashToken(identity) }

// locked reports whether identity has an unexpired lockout entry and, when it
// does, until when. A missing or malformed entry reads as unlocked.
func (t *Tracker) locked(identity string) (bool, time.Time, error) {
	value, err := t.Store.Load(lockKey(identity))
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

// failures returns the number of failures within FailureWindow that lock an
// identity out.
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

// lockoutDuration returns the base lockout, before any escalation.
func (t *Tracker) lockoutDuration() time.Duration {
	if t.Lockout <= 0 {
		return defaultLockout
	}
	return t.Lockout
}
