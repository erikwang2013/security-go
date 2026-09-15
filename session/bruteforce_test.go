// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/erikwang2013/security-go"
)

const attackerIP = "203.0.113.9:1234"

func fromIP(ip string) *http.Request {
	return newRequest("", ip, "curl/8", "")
}

func identityFromHeader(r *http.Request) string { return r.Header.Get("X-Identity") }

func withIdentity(r *http.Request, id string) *http.Request {
	r.Header.Set("X-Identity", id)
	return r
}

func TestGuardLoginLocksAfterThreshold(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 3

	handler := tr.GuardLogin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}), identityFromHeader)

	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, withIdentity(fromIP(attackerIP), "alice"))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, rr.Code)
		}
	}
	if locked, _ := tr.IsLocked("alice"); !locked {
		t.Fatal("expected alice to be locked after the threshold")
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, withIdentity(fromIP(attackerIP), "alice"))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429 once locked", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on the 429")
	}
}

func TestGuardLoginPassesThroughAndClears(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 3

	succeed := false
	handler := tr.GuardLogin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !succeed {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), identityFromHeader)

	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, withIdentity(fromIP(attackerIP), "bob"))
	}
	succeed = true
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, withIdentity(fromIP(attackerIP), "bob"))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}

	// The successful attempt cleared the counter: two more failures must not lock.
	succeed = false
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, withIdentity(fromIP(attackerIP), "bob"))
	}
	if locked, _ := tr.IsLocked("bob"); locked {
		t.Fatal("expected the counter to have been cleared by the successful login")
	}
}

func TestGuardLoginImplicitStatusCountsAsSuccess(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 2

	// A handler that writes a body without calling WriteHeader is a 200.
	handler := tr.GuardLogin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}), identityFromHeader)

	for i := 0; i < 4; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, withIdentity(fromIP(attackerIP), "carol"))
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d, want 200", rr.Code)
		}
	}
	if locked, _ := tr.IsLocked("carol"); locked {
		t.Fatal("a 200-by-write must not count as a failed attempt")
	}
}

func TestGuardLoginNilIdentityDoesNotPanic(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	handler := tr.GuardLogin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, fromIP(attackerIP))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
}

func TestCredentialStuffingDetected(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.StuffingLimit = 3
	tr.Failures = 100 // keep the identity lockout out of the way

	for _, id := range []string{"u1", "u2", "u3"} {
		if err := tr.RecordFailure(id, fromIP(attackerIP)); err != nil {
			t.Fatalf("RecordFailure(%s): %v", id, err)
		}
	}
	res := tr.CheckLogin("u4", fromIP(attackerIP))
	if !res.Detected || res.Details["reason"] != "credential_stuffing" {
		t.Fatalf("CheckLogin = %+v, want credential_stuffing", res)
	}
	if res.Severity != security.SeverityCritical {
		t.Fatalf("Severity = %v, want Critical", res.Severity)
	}
	if res.Name != "session_guard" {
		t.Fatalf("Name = %q, want session_guard", res.Name)
	}

	// A different client sweeping the same identities is not the same signal.
	if res := tr.CheckLogin("u1", fromIP("198.51.100.4:1234")); res.Detected {
		t.Fatalf("a clean client should not be flagged: %+v", res)
	}
}

func TestStuffingCountsDistinctIdentitiesOnly(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.StuffingLimit = 3
	tr.Failures = 100

	for i := 0; i < 6; i++ {
		if err := tr.RecordFailure("same", fromIP(attackerIP)); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	if res := tr.CheckLogin("same", fromIP(attackerIP)); res.Detected {
		t.Fatalf("repeating one identity is not stuffing: %+v", res)
	}
}

func TestProgressiveBackoffDoubles(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 1
	tr.Lockout = time.Minute

	if err := tr.RecordFailure("dave", fromIP(attackerIP)); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	_, first := tr.IsLocked("dave")

	// Drop the lock, as if it had expired, and cross the threshold again.
	if err := st.Delete(lockKey("dave")); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := tr.RecordFailure("dave", fromIP(attackerIP)); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	_, second := tr.IsLocked("dave")

	if !second.After(first) {
		t.Fatalf("expected the second lockout to be longer: %v then %v", first, second)
	}
	if d := time.Until(second); d < 90*time.Second {
		t.Fatalf("expected roughly a doubled lockout, got %v", d)
	}
}

func TestLockForCapsAtMaxLockout(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Lockout = time.Hour
	tr.MaxLockout = 3 * time.Hour

	tests := []struct {
		strikes int
		want    time.Duration
	}{
		{1, time.Hour},
		{2, 2 * time.Hour},
		{3, 3 * time.Hour},
		{4, 3 * time.Hour},
		{50, 3 * time.Hour},
	}
	for _, tc := range tests {
		if got := tr.lockFor(tc.strikes); got != tc.want {
			t.Errorf("lockFor(%d) = %v, want %v", tc.strikes, got, tc.want)
		}
	}
}

func TestClearFailuresResetsEscalation(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 1
	tr.Lockout = time.Minute

	if err := tr.RecordFailure("erin", fromIP(attackerIP)); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := tr.ClearFailures("erin"); err != nil {
		t.Fatalf("ClearFailures: %v", err)
	}
	if err := st.Delete(lockKey("erin")); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := tr.RecordFailure("erin", fromIP(attackerIP)); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	_, until := tr.IsLocked("erin")
	if d := time.Until(until); d > 90*time.Second {
		t.Fatalf("expected the escalation to have been reset, got %v", d)
	}
}

func TestRecordFailureKeysAreHashed(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 1

	if err := tr.RecordFailure("secret-user", fromIP("198.51.100.7:1234")); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	sawStrike, sawStuff := false, false
	for _, key := range st.keys {
		if strings.Contains(key, "secret-user") || strings.Contains(key, "198.51.100.7") {
			t.Fatalf("store key leaks an identity or client IP: %q", key)
		}
		if strings.HasPrefix(key, strikesPrefix) {
			sawStrike = true
		}
		if strings.HasPrefix(key, stuffingPrefix) {
			sawStuff = true
		}
	}
	if !sawStrike || !sawStuff {
		t.Fatalf("keys = %v, want both strike: and stuff: prefixed keys", st.keys)
	}
}

func TestCheckLoginClean(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	res := tr.CheckLogin("nobody", fromIP(attackerIP))
	if res == nil || res.Detected {
		t.Fatalf("CheckLogin = %+v, want not detected", res)
	}
	if res.Name != "session_guard" {
		t.Fatalf("Name = %q, want session_guard", res.Name)
	}
}

func TestCheckLoginReportsLockout(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.Failures = 2

	for i := 0; i < 2; i++ {
		if err := tr.RecordFailure("frank", fromIP(attackerIP)); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	res := tr.CheckLogin("frank", fromIP(attackerIP))
	if !res.Detected || res.Details["reason"] != "token_locked" {
		t.Fatalf("CheckLogin = %+v, want token_locked", res)
	}
}

func TestBruteforceDefaults(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	if tr.MaxLockout != defaultMaxLockout {
		t.Fatalf("MaxLockout = %v, want %v", tr.MaxLockout, defaultMaxLockout)
	}
	if tr.BackoffWindow != defaultBackoffWindow {
		t.Fatalf("BackoffWindow = %v, want %v", tr.BackoffWindow, defaultBackoffWindow)
	}
	if tr.StuffingLimit != defaultStuffingLimit {
		t.Fatalf("StuffingLimit = %d, want %d", tr.StuffingLimit, defaultStuffingLimit)
	}
	tr.MaxLockout, tr.BackoffWindow, tr.StuffingLimit = 0, 0, 0
	if tr.maxLockout() != defaultMaxLockout || tr.backoffWindow() != defaultBackoffWindow {
		t.Fatal("zeroed durations did not fall back to the defaults")
	}
	if tr.stuffingLimit() != defaultStuffingLimit {
		t.Fatal("a zeroed StuffingLimit did not fall back to the default")
	}
}
