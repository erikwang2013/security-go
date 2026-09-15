// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package session

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/erikwang2013/security-go"
	"github.com/erikwang2013/security-go/storage"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	mem := storage.NewMemory()
	t.Cleanup(func() { mem.Close() })
	return NewSigner([]byte("test-secret"), mem)
}

func TestSignerRoundTrip(t *testing.T) {
	s := testSigner(t)
	params := map[string]string{"amount": "100", "to": "bob"}

	sig, err := s.Sign(params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res := s.Verify(params, sig); res.Detected {
		t.Fatalf("expected no detection for a valid signature, got %+v", res)
	}
}

func TestSignerDetectsTamperedParams(t *testing.T) {
	s := testSigner(t)
	sig, err := s.Sign(map[string]string{"amount": "100", "to": "bob"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cases := map[string]map[string]string{
		"changed value":  {"amount": "10000", "to": "bob"},
		"changed target": {"amount": "100", "to": "attacker"},
		"added param":    {"amount": "100", "to": "bob", "fee": "0"},
		"removed param":  {"amount": "100"},
		"empty params":   {},
	}
	for name, params := range cases {
		res := s.Verify(params, sig)
		if !res.Detected {
			t.Errorf("%s: expected a detection, got %+v", name, res)
			continue
		}
		if got := res.Details["reason"]; got != "signature_mismatch" {
			t.Errorf("%s: expected reason signature_mismatch, got %v", name, got)
		}
		if res.Severity != security.SeverityCritical {
			t.Errorf("%s: expected SeverityCritical, got %v", name, res.Severity)
		}
	}
}

func TestSignerDetectsWrongSecret(t *testing.T) {
	s := testSigner(t)
	sig, err := s.Sign(map[string]string{"amount": "100"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	other := NewSigner([]byte("another-secret"), nil)
	if res := other.Verify(map[string]string{"amount": "100"}, sig); !res.Detected {
		t.Fatal("expected detection when the signature was made with another key")
	}
}

func TestSignerDetectsMalformedSignature(t *testing.T) {
	s := testSigner(t)
	params := map[string]string{"amount": "100"}

	for _, sig := range []string{"", "abc", "1.2", "1.2.3.4"} {
		res := s.Verify(params, sig)
		if !res.Detected {
			t.Fatalf("expected detection for signature %q, got %+v", sig, res)
		}
		if got := res.Details["reason"]; got != "signature_malformed" {
			t.Fatalf("signature %q: expected reason signature_malformed, got %v", sig, got)
		}
	}
}

func TestSignerDetectsNonNumericTimestamp(t *testing.T) {
	s := testSigner(t)
	res := s.Verify(map[string]string{"a": "1"}, "not-a-time.nonce.mac")
	if !res.Detected || res.Details["reason"] != "timestamp_invalid" {
		t.Fatalf("expected a timestamp_invalid detection, got %+v", res)
	}
}

func TestSignerDetectsExpiredTimestamp(t *testing.T) {
	s := testSigner(t)
	s.MaxSkew = time.Minute
	params := map[string]string{"amount": "100"}

	ts := strconv.FormatInt(time.Now().Add(-2*time.Minute).Unix(), 10)
	res := s.Verify(params, ts+".deadbeef."+s.mac(params, ts, "deadbeef"))
	if !res.Detected {
		t.Fatal("expected detection for a stale signature")
	}
	if got := res.Details["reason"]; got != "signature_expired" {
		t.Fatalf("expected reason signature_expired, got %v", got)
	}
}

func TestSignerDetectsFutureTimestamp(t *testing.T) {
	s := testSigner(t)
	s.MaxSkew = time.Minute
	params := map[string]string{"amount": "100"}

	ts := strconv.FormatInt(time.Now().Add(2*time.Minute).Unix(), 10)
	res := s.Verify(params, ts+".deadbeef."+s.mac(params, ts, "deadbeef"))
	if !res.Detected {
		t.Fatal("expected detection for a signature dated in the future")
	}
	if got := res.Details["reason"]; got != "timestamp_in_future" {
		t.Fatalf("expected reason timestamp_in_future, got %v", got)
	}
}

func TestSignerDetectsReplay(t *testing.T) {
	s := testSigner(t)
	params := map[string]string{"amount": "100"}
	sig, err := s.Sign(params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if res := s.Verify(params, sig); res.Detected {
		t.Fatalf("the first use must pass, got %+v", res)
	}
	res := s.Verify(params, sig)
	if !res.Detected {
		t.Fatal("expected detection when the same signature is sent twice")
	}
	if got := res.Details["reason"]; got != "replay" {
		t.Fatalf("expected reason replay, got %v", got)
	}
	if res.Severity != security.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res.Severity)
	}
}

func TestSignerForgeryDoesNotBurnNonce(t *testing.T) {
	s := testSigner(t)
	params := map[string]string{"amount": "100"}
	sig, err := s.Sign(params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parts := strings.Split(sig, ".")
	replacement := "A"
	if parts[2][len(parts[2])-1:] == "A" {
		replacement = "B"
	}
	forged := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + replacement
	if res := s.Verify(params, forged); !res.Detected {
		t.Fatal("expected the forged signature to be caught")
	}
	// The genuine signature must still work: a forgery must not consume its nonce.
	if res := s.Verify(params, sig); res.Detected {
		t.Fatalf("the forged signature burned the nonce: %+v", res)
	}
}

func TestSignerWithoutNonceStoreSkipsReplay(t *testing.T) {
	s := NewSigner([]byte("test-secret"), nil)
	params := map[string]string{"amount": "100"}
	sig, err := s.Sign(params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if res := s.Verify(params, sig); res.Detected {
		t.Fatalf("the first use must pass, got %+v", res)
	}
	// Documented limitation: without a nonce store, only the timestamp bounds reuse.
	if res := s.Verify(params, sig); res.Detected {
		t.Fatal("replay is not detectable without a nonce store")
	}
}

func TestSignerRefusesEmptySecret(t *testing.T) {
	s := NewSigner(nil, nil)

	if _, err := s.Sign(map[string]string{"a": "1"}); err == nil {
		t.Fatal("expected Sign to fail without a secret")
	}
	res := s.Verify(map[string]string{"a": "1"}, "1.2.3")
	if !res.Detected {
		t.Fatal("expected Verify to refuse unsigned data")
	}
	if got := res.Details["reason"]; got != "signer_not_configured" {
		t.Fatalf("expected reason signer_not_configured, got %v", got)
	}
}

func TestSignerCanonicalOrderAndEscaping(t *testing.T) {
	s := testSigner(t)
	sig, err := s.Sign(map[string]string{"a": "1", "b": "2", "c": "3"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if res := s.Verify(map[string]string{"c": "3", "a": "1", "b": "2"}, sig); res.Detected {
		t.Fatalf("expected map order not to matter, got %+v", res)
	}
	// Escaping must keep distinct values distinct.
	if res := s.Verify(map[string]string{"a": "1", "b": "2&c=3"}, sig); !res.Detected {
		t.Fatal("expected a value containing an escaped separator to be caught")
	}
}

func TestSignerNonceIsUnique(t *testing.T) {
	s := testSigner(t)
	params := map[string]string{"a": "1"}

	first, err := s.Sign(params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	second, err := s.Sign(params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if first == second {
		t.Fatal("expected a distinct signature per call")
	}
	if strings.Split(first, ".")[1] == strings.Split(second, ".")[1] {
		t.Fatal("expected a fresh nonce per signature")
	}
}

func TestSignerZeroMaxSkewFallsBackToDefault(t *testing.T) {
	s := NewSigner([]byte("test-secret"), nil)
	s.MaxSkew = 0
	params := map[string]string{"a": "1"}

	sig, err := s.Sign(params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res := s.Verify(params, sig); res.Detected {
		t.Fatalf("expected zero MaxSkew to fall back to the default, got %+v", res)
	}
}

func TestSignerDefaults(t *testing.T) {
	s := NewSigner([]byte("test-secret"), nil)

	if s.Name() != "data_tamper" {
		t.Fatalf("expected name 'data_tamper', got %s", s.Name())
	}
	if s.MaxSkew != defaultMaxSkew {
		t.Fatalf("expected default MaxSkew %v, got %v", defaultMaxSkew, s.MaxSkew)
	}
}
