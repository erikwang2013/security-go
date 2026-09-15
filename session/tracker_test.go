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

const testToken = "test-token"

// recordingStore is a MemoryStore that remembers the keys it was given.
type recordingStore struct {
	*MemoryStore
	keys []string
}

func newRecordingStore() *recordingStore {
	return &recordingStore{MemoryStore: NewMemoryStore()}
}

func (r *recordingStore) Save(key string, value []byte, ttl time.Duration) error {
	r.keys = append(r.keys, key)
	return r.MemoryStore.Save(key, value, ttl)
}

// failingStore fails every operation, to exercise the fail-open/fail-closed paths.
type failingStore struct{ err error }

func (f *failingStore) Save(string, []byte, time.Duration) error { return f.err }
func (f *failingStore) Load(string) ([]byte, error)              { return nil, f.err }
func (f *failingStore) Delete(string) error                      { return f.err }

func newRequest(token, addr, ua, fp string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = addr
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	if fp != "" {
		r.Header.Set(FingerprintHeader, fp)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestTrackerAcceptsSameClient(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "fp-1")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// A new source port is not a new client.
	if res := tr.Check(newRequest(testToken, "203.0.113.7:9999", "curl/8", "fp-1")); res.Detected {
		t.Fatalf("expected no detection for the same client, got %+v", res)
	}
}

func TestTrackerIssueRejectsEmptyToken(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue("", newRequest("", "203.0.113.7:1234", "curl/8", "")); err == nil {
		t.Fatal("expected an error for an empty token")
	}
}

func TestTrackerStoresHashedToken(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for _, key := range st.keys {
		if strings.Contains(key, testToken) {
			t.Fatalf("store key %q leaks the session token", key)
		}
	}
}

func TestTrackerDetectsMissingToken(t *testing.T) {
	tr := NewTracker(newRecordingStore())

	res := tr.Check(newRequest("", "203.0.113.7:1234", "curl/8", ""))
	if !res.Detected {
		t.Fatal("expected detection for a request with no token")
	}
	if got := res.Details["reason"]; got != "missing_token" {
		t.Fatalf("expected reason missing_token, got %v", got)
	}
}

func TestTrackerDetectsUnknownToken(t *testing.T) {
	tr := NewTracker(newRecordingStore())

	res := tr.Check(newRequest("never-issued", "203.0.113.7:1234", "curl/8", ""))
	if !res.Detected {
		t.Fatal("expected detection for an unknown token")
	}
	if got := res.Details["reason"]; got != "unknown_token" {
		t.Fatalf("expected reason unknown_token, got %v", got)
	}
}

func TestTrackerDetectsClientHijack(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "Mozilla/5.0", "fp-1")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "python-requests/2", "fp-1"))
	if !res.Detected {
		t.Fatal("expected detection when the user agent changes")
	}
	if got := res.Details["reason"]; got != "client_hijack" {
		t.Fatalf("expected reason client_hijack, got %v", got)
	}
	if res.Severity != security.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res.Severity)
	}
}

func TestTrackerDetectsFingerprintChange(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "Mozilla/5.0", "fp-1")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "Mozilla/5.0", "fp-2"))
	if !res.Detected {
		t.Fatal("expected detection when the device fingerprint changes")
	}
	if got := res.Details["reason"]; got != "client_hijack" {
		t.Fatalf("expected reason client_hijack, got %v", got)
	}
}

func TestTrackerIgnoresAbsentFingerprint(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "Mozilla/5.0", "fp-1")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// A client that stops sending the header must not look like an attacker.
	if res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "Mozilla/5.0", "")); res.Detected {
		t.Fatalf("expected no detection without a fingerprint header, got %+v", res)
	}
}

func TestTrackerDetectsNetworkChange(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	res := tr.Check(newRequest(testToken, "198.51.100.9:1234", "curl/8", ""))
	if !res.Detected {
		t.Fatal("expected detection when the session moves to another network")
	}
	if got := res.Details["reason"]; got != "remote_login" {
		t.Fatalf("expected reason remote_login, got %v", got)
	}
	if res.Severity != security.SeverityHigh {
		t.Fatalf("expected SeverityHigh, got %v", res.Severity)
	}
}

func TestTrackerAllowsSameSubnet(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Same /24: a client whose address shifts must not be flagged.
	if res := tr.Check(newRequest(testToken, "203.0.113.99:1234", "curl/8", "")); res.Detected {
		t.Fatalf("expected no detection inside the same subnet, got %+v", res)
	}
}

func TestTrackerDetectsCountryChange(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.CountryOf = func(ip string) string {
		if ip == "203.0.113.7" {
			return "CN"
		}
		return "US"
	}

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Same subnet, so only the country check can fire.
	res := tr.Check(newRequest(testToken, "203.0.113.99:1234", "curl/8", ""))
	if !res.Detected {
		t.Fatal("expected detection when the country changes")
	}
	if got := res.Details["reason"]; got != "remote_login" {
		t.Fatalf("expected reason remote_login, got %v", got)
	}
	if res.Severity != security.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res.Severity)
	}
	if !strings.Contains(res.Message, "CN -> US") {
		t.Fatalf("expected the country change in the message, got %q", res.Message)
	}
}

func TestTrackerRevoke(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := tr.Revoke(testToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "curl/8", ""))
	if !res.Detected || res.Details["reason"] != "unknown_token" {
		t.Fatalf("expected an unknown_token detection after revoke, got %+v", res)
	}
}

func TestTrackerExpiresSession(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.TTL = 20 * time.Millisecond

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "curl/8", ""))
	if !res.Detected || res.Details["reason"] != "unknown_token" {
		t.Fatalf("expected an unknown_token detection after expiry, got %+v", res)
	}
}

func TestTrackerFailOpenOnStoreError(t *testing.T) {
	tr := NewTracker(&failingStore{err: errors.New("store down")})

	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "curl/8", ""))
	if res.Detected {
		t.Fatalf("expected the default to let traffic through, got %+v", res)
	}
}

func TestTrackerFailClosedOnStoreError(t *testing.T) {
	tr := NewTracker(&failingStore{err: errors.New("store down")})
	tr.FailClosed = true

	res := tr.Check(newRequest(testToken, "203.0.113.7:1234", "curl/8", ""))
	if !res.Detected {
		t.Fatal("expected detection with FailClosed")
	}
	if got := res.Details["reason"]; got != "store_error" {
		t.Fatalf("expected reason store_error, got %v", got)
	}
}

func TestTrackerProxyHeaders(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	// Untrusted: X-Forwarded-For is ignored, so the proxy address is bound.
	issue := newRequest(testToken, "10.0.0.1:1234", "curl/8", "")
	issue.Header.Set("X-Forwarded-For", "203.0.113.7")
	if err := tr.Issue(testToken, issue); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	check := newRequest(testToken, "10.0.0.1:1234", "curl/8", "")
	check.Header.Set("X-Forwarded-For", "198.51.100.9")
	if res := tr.Check(check); res.Detected {
		t.Fatalf("expected X-Forwarded-For to be ignored by default, got %+v", res)
	}

	// Trusted: the forwarded client address is what moves the session.
	st2 := newRecordingStore()
	defer st2.Close()
	tr2 := NewTracker(st2)
	tr2.TrustProxyHeaders = true

	if err := tr2.Issue(testToken, issue); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res := tr2.Check(check); !res.Detected {
		t.Fatal("expected detection once proxy headers are trusted")
	}
}

func TestTrackerGuard(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	handler := tr.Guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(r *http.Request) int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec.Code
	}

	if code := serve(newRequest("", "203.0.113.7:1234", "curl/8", "")); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a token, got %d", code)
	}
	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if code := serve(newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); code != http.StatusOK {
		t.Fatalf("expected 200 for a valid session, got %d", code)
	}
	if code := serve(newRequest(testToken, "203.0.113.7:1234", "attacker/1", "")); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a hijacked session, got %d", code)
	}
}

func TestTrackerObserveRemoteLogin(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	login := func(addr string) *security.Result {
		return tr.Observe("u1", newRequest("", addr, "curl/8", ""))
	}

	if res := login("203.0.113.7:1234"); res.Detected {
		t.Fatal("the first login has no baseline and must not alert")
	}
	if res := login("203.0.113.99:1234"); res.Detected {
		t.Fatal("the same network must not alert")
	}
	res := login("198.51.100.9:1234")
	if !res.Detected {
		t.Fatal("expected detection for an unseen login network")
	}
	if got := res.Details["reason"]; got != "remote_login" {
		t.Fatalf("expected reason remote_login, got %v", got)
	}
	if res := login("198.51.100.9:1234"); res.Detected {
		t.Fatal("a remembered network must not alert again")
	}
}

func TestTrackerObserveEvictsOldestNetwork(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)
	tr.KnownNets = 2

	for _, addr := range []string{"203.0.113.7:1234", "198.51.100.9:1234", "192.0.2.5:1234"} {
		tr.Observe("u1", newRequest("", addr, "curl/8", ""))
	}
	// The oldest network fell out of the cap, so it reads as new again.
	if res := tr.Observe("u1", newRequest("", "203.0.113.7:1234", "curl/8", "")); !res.Detected {
		t.Fatal("expected the evicted network to alert again")
	}
}

func TestTrackerObserveEmptyUser(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if res := tr.Observe("", newRequest("", "203.0.113.7:1234", "curl/8", "")); res.Detected {
		t.Fatal("expected no detection for an empty user")
	}
	if len(st.keys) != 0 {
		t.Fatalf("expected no store writes, got %v", st.keys)
	}
}

func TestTrackerIssueReplacesBinding(t *testing.T) {
	st := newRecordingStore()
	defer st.Close()
	tr := NewTracker(st)

	if err := tr.Issue(testToken, newRequest(testToken, "203.0.113.7:1234", "curl/8", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := tr.Issue(testToken, newRequest(testToken, "198.51.100.9:1234", "wget/1", "")); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res := tr.Check(newRequest(testToken, "198.51.100.9:1234", "wget/1", "")); res.Detected {
		t.Fatalf("expected the newest binding to be accepted, got %+v", res)
	}
}

func TestNetwork(t *testing.T) {
	cases := []struct {
		a, b string
		bits int
		same bool
	}{
		{"203.0.113.7", "203.0.113.99", 24, true},
		{"203.0.113.7", "203.0.114.7", 24, false},
		{"203.0.113.7", "203.0.114.7", 16, true},
		{"203.0.113.7", "198.51.100.9", 8, false},
		{"::1", "::2", 64, true},
		{"2001:db8::1", "2001:db9::1", 24, false}, // IPv6 widens SubnetBits by 24
		{"2001:db8::1", "2001:db8::2", 24, true},
		{"203.0.113.7", "::1", 24, false},
		{"not-an-ip", "not-an-ip", 24, true},
		{"not-an-ip", "203.0.113.7", 24, false},
	}
	for _, c := range cases {
		if got := network(c.a, c.bits) == network(c.b, c.bits); got != c.same {
			t.Errorf("network(%q) == network(%q) with bits=%d: got %v, want %v",
				c.a, c.b, c.bits, got, c.same)
		}
	}
}
