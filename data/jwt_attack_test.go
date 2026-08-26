// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package data

import (
	"encoding/base64"
	"strings"
	"testing"
)

// b64url base64url-encodes s without padding, for building test tokens.
func b64url(s string) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(s)), "=")
}

func TestJWTName(t *testing.T) {
	d := &JWTAttack{}
	if r := d.Detect(""); r == nil || r.Name != "jwt_attack" || r.Detected {
		t.Fatalf("empty input: got %+v, want not-detected jwt_attack result", r)
	}
}

func TestJWTAlgNone(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.")
	if !r.Detected {
		t.Error("should detect alg:none")
	}
}

func TestJWTAlgNoneTwoParts(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect(b64url(`{"alg":"none","typ":"JWT"}`) + ".payload")
	if !r.Detected {
		t.Error("should detect alg:none with two parts")
	}
}

func TestJWTAlgNoneCaseInsensitive(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect(b64url(`{"alg":"NONE","typ":"JWT"}`) + ".payload.sig")
	if !r.Detected {
		t.Error("should detect alg:NONE case-insensitively")
	}
}

func TestJWTKidTraversal(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect("eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
	if !r.Detected {
		t.Error("should detect kid path traversal")
	}
}

func TestJWTKidBackslashTraversal(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect(b64url(`{"alg":"HS256","kid":"..\\..\\etc\\passwd"}`) + ".payload.sig")
	if !r.Detected {
		t.Error("should detect kid backslash path traversal")
	}
}

func TestJWTEmptySignature(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.")
	if !r.Detected {
		t.Error("should detect empty signature")
	}
}

func TestJWTEmptySignatureNoAlg(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect(b64url(`{"typ":"JWT"}`) + "." + b64url(`{"sub":"1"}`) + ".")
	if !r.Detected {
		t.Error("should detect empty signature without alg field")
	}
}

func TestJWTValidToken(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	if r.Detected {
		t.Error("should not detect valid JWT")
	}
}

func TestJWTNonStringAlg(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect(b64url(`{"alg":123,"typ":"JWT"}`) + ".payload.sig")
	if r.Detected {
		t.Error("should not detect non-string alg")
	}
}

func TestJWTTooFewParts(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect("eyJhbGciOiJub25lIn0")
	if r.Detected {
		t.Error("should not detect single-part input")
	}
}

func TestJWTInvalidHeader(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect("!!!not-base64!!!.payload.sig")
	if r.Detected {
		t.Error("should not detect invalid base64 header")
	}
}

func TestJWTNonJSONHeader(t *testing.T) {
	d := &JWTAttack{}
	r := d.Detect(b64url(`not json`) + ".payload.sig")
	if r.Detected {
		t.Error("should not detect non-JSON header")
	}
}
