// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/erikwang2013/security-go"
)

func TestLockoutDefaults(t *testing.T) {
	tr := NewTracker(newRecordingStore())
	if tr.Failures != defaultFailures {
		t.Fatalf("expected Failures %d, got %d", defaultFailures, tr.Failures)
	}
	if tr.FailureWindow != defaultFailureWindow {
		t.Fatalf("expected FailureWindow %v, got %v", defaultFailureWindow, tr.FailureWindow)
	}
	if tr.Lockout != defaultLockout {
		t.Fatalf("expected Lockout %v, got %v", defaultLockout, tr.Lockout)
	}
	if tr.failures() != defaultFailures || tr.failureWindow() != defaultFailureWindow || tr.lockoutDuration() != defaultLockout {
		t.Fatal("effective defaults do not match the configured defaults")
	}
}

func TestLockoutZeroFieldsFallBack(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures, tr.FailureWindow, tr.Lockout = 0, 0, 0
	if tr.failures() != defaultFailures {
		t.Fatalf("expected Failures to fall back to %d, got %d", defaultFailures, tr.failures())
	}
	if tr.failureWindow() != defaultFailureWindow {
		t.Fatalf("expected FailureWindow to fall back to %v, got %v", defaultFailureWindow, tr.failureWindow())
	}
	if tr.lockoutDuration() != defaultLockout {
		t.Fatalf("expected Lockout to fall back to %v, got %v", defaultLockout, tr.lockoutDuration())
	}
}

func TestRecordFailureBelowThreshold(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 3
	for i := 0; i < 2; i++ {
		if err := tr.RecordFailure(testToken); err != nil {
			t.Fatalf("RecordFailure %d: %v", i+1, err)
		}
	}
	if locked, _ := tr.IsLocked(testToken); locked {
		t.Fatal("expected the token to stay unlocked below the threshold")
	}
}

func TestRecordFailureTriggersLockout(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 3
	for i := 0; i < 3; i++ {
		if err := tr.RecordFailure(testToken); err != nil {
			t.Fatalf("RecordFailure %d: %v", i+1, err)
		}
	}
	if locked, _ := tr.IsLocked(testToken); !locked {
		t.Fatal("expected the token to be locked at the threshold")
	}
}

func TestCheckLockedToken(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 2
	req := newRequest(testToken, "203.0.113.7:1234", "curl/8", "fp-1")
	if err := tr.Issue(testToken, req); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := tr.RecordFailure(testToken); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := tr.RecordFailure(testToken); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	res := tr.Check(req)
	if !res.Detected {
		t.Fatal("expected detection for a locked token")
	}
	if res.Name != "session_guard" {
		t.Fatalf("expected result Name %q, got %q", "session_guard", res.Name)
	}
	if res.Details["reason"] != "token_locked" {
		t.Fatalf("expected reason 'token_locked', got %v", res.Details["reason"])
	}
	if res.Severity != security.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res.Severity)
	}
	if res.Message == "" {
		t.Error("expected a non-empty message")
	}
}

func TestLockoutBeatsUnknownToken(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 1
	if err := tr.RecordFailure(testToken); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	// The token was never issued, but the lock is the more actionable signal.
	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "curl/8", ""))
	if res.Details["reason"] != "token_locked" {
		t.Fatalf("expected reason 'token_locked', got %v", res.Details["reason"])
	}
}

func TestLockoutExpiry(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := st.Save(lockKey("past-token"), []byte(past), time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if locked, until := tr.IsLocked("past-token"); locked || !until.IsZero() {
		t.Fatalf("expected an expired lock to read as unlocked, got (%v, %v)", locked, until)
	}
	res := tr.Check(newRequest("past-token", "203.0.113.7:1234", "", ""))
	if res.Details["reason"] != "unknown_token" {
		t.Fatalf("expected an expired lock to fall through to unknown_token, got %v", res.Details["reason"])
	}
}

func TestLockoutMalformedEntryReadsAsUnlocked(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := st.Save(lockKey(testToken), []byte("not a timestamp"), time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if locked, _ := tr.IsLocked(testToken); locked {
		t.Fatal("expected a malformed lock entry to read as unlocked")
	}
}

func TestClearFailuresResetsCounter(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 3
	for i := 0; i < 2; i++ {
		if err := tr.RecordFailure(testToken); err != nil {
			t.Fatalf("RecordFailure %d: %v", i+1, err)
		}
	}
	if err := tr.ClearFailures(testToken); err != nil {
		t.Fatalf("ClearFailures: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := tr.RecordFailure(testToken); err != nil {
			t.Fatalf("RecordFailure after clear %d: %v", i+1, err)
		}
	}
	if locked, _ := tr.IsLocked(testToken); locked {
		t.Fatal("expected the cleared counter to start the count over")
	}
}

func TestRecordFailureEmptyToken(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	if err := tr.RecordFailure(""); err == nil {
		t.Fatal("expected an error for an empty token")
	}
	if err := tr.ClearFailures(""); err == nil {
		t.Fatal("expected an error for an empty token")
	}
	if locked, until := tr.IsLocked(""); locked || !until.IsZero() {
		t.Fatalf("expected an empty token to read as unlocked, got (%v, %v)", locked, until)
	}
	if len(st.keys) != 0 {
		t.Fatalf("expected no store access for an empty token, saw keys %v", st.keys)
	}
}

func TestRecordFailureNilStore(t *testing.T) {
	tr := &Tracker{}
	if err := tr.RecordFailure(testToken); err == nil {
		t.Fatal("expected an error with no store configured")
	}
	if err := tr.ClearFailures(testToken); err == nil {
		t.Fatal("expected an error with no store configured")
	}
	if locked, _ := tr.IsLocked(testToken); locked {
		t.Fatal("expected IsLocked to fail open with no store configured")
	}
}

func TestLockoutFailClosed(t *testing.T) {
	tr := NewTracker(&failingStore{err: errors.New("store down")})
	tr.FailClosed = true
	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "curl/8", ""))
	if !res.Detected || res.Details["reason"] != "store_error" {
		t.Fatalf("expected store_error under FailClosed, got %+v", res)
	}
	if locked, _ := tr.IsLocked(testToken); locked {
		t.Fatal("expected IsLocked to fail open on a store error")
	}
	if err := tr.RecordFailure(testToken); err == nil {
		t.Fatal("expected RecordFailure to surface the store error")
	}
}

func TestLockoutFailOpen(t *testing.T) {
	tr := NewTracker(&failingStore{err: errors.New("store down")})
	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "curl/8", ""))
	if res.Detected {
		t.Fatalf("expected fail-open behaviour on a store error, got %+v", res)
	}
}

func TestLockoutKeysHashedAndPrefixed(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 2
	if err := tr.RecordFailure(testToken); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := tr.RecordFailure(testToken); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := tr.ClearFailures(testToken); err != nil {
		t.Fatalf("ClearFailures: %v", err)
	}

	for _, key := range st.keys {
		if strings.Contains(key, testToken) {
			t.Fatalf("store key %q leaks the session token", key)
		}
		if !strings.HasPrefix(key, failuresPrefix) && !strings.HasPrefix(key, lockPrefix) {
			t.Fatalf("unexpected store key %q", key)
		}
	}
	if len(st.keys) < 3 {
		t.Fatalf("expected a counter save, a lock save and another counter save, got %v", st.keys)
	}
}

func TestGuardAnswers401WhenLocked(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 1
	if err := tr.RecordFailure(testToken); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	handler := tr.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, newRequest(testToken, "203.0.113.7:1234", "curl/8", ""))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a locked token, got %d", rr.Code)
	}
}

func TestCheckUnaffectedWithoutFailures(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	req := newRequest(testToken, "203.0.113.7:1234", "curl/8", "fp-1")
	if err := tr.Issue(testToken, req); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if locked, _ := tr.IsLocked(testToken); locked {
		t.Fatal("expected no lockout on a fresh tracker")
	}
	if res := tr.Check(req); res.Detected {
		t.Fatalf("expected the lockout to be inert when unused, got %+v", res)
	}
}
