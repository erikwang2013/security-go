package data

import "testing"

func TestJWTAlgNone(t *testing.T) {
	d := &JWTAttackDetector{}
	r := d.Detect("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.")
	if !r.Detected {
		t.Error("should detect alg:none")
	}
}

func TestJWTKidTraversal(t *testing.T) {
	d := &JWTAttackDetector{}
	r := d.Detect("eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
	if !r.Detected {
		t.Error("should detect kid path traversal")
	}
}

func TestJWTEmptySignature(t *testing.T) {
	d := &JWTAttackDetector{}
	r := d.Detect("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.")
	if !r.Detected {
		t.Error("should detect empty signature")
	}
}

func TestJWTValidToken(t *testing.T) {
	d := &JWTAttackDetector{}
	r := d.Detect("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	if r.Detected {
		t.Error("should not detect valid JWT")
	}
}
