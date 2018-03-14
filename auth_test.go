package auth

import (
	"testing"
)

func TestMacaroon(t *testing.T) {
	auth := NewAuth("", InMemoryNonceDB{})

	// Emulate generation token on the server, with the user id taken from other
	// token, for example jwt.
	tokenStr, err := auth.GenerateToken(100, []string{"disabled"})
	if err != nil {
		t.Fatalf("unable to generate macaroon token: %v", err)
	}

	// Emulate that client received the token, and now want to make some
	// operation on the server, he has to add time and nonce constraints,
	// before making an operation, otherwise he/she under threat of replay-attack.
	m, err := DecodeMacaroon(tokenStr)
	if err != nil {
		t.Fatalf("unable to decode macaroon: %v", err)
	}

	m, err = AddNonce(m, 10)
	if err != nil {
		t.Fatalf("unable to add nonce: %v", err)
	}

	m, err = AddCurrentTime(m)
	if err != nil {
		t.Fatalf("unable to add current time: %v", err)
	}

	tokenStr, err = EncodeMacaroon(m)
	if err != nil {
		t.Fatalf("unable to encode macaroon")
	}

	// Emulate that server received the macaroon and validating it and also
	// check that operation is permitted.
	token, err := auth.ExtractToken(tokenStr)
	if err != nil {
		t.Fatalf("operation should be not allowed")
	}

	if err = token.IsAuthorized("disabled"); err != ErrOperNotAllowed {
		t.Fatalf("operation should be not allowed")
	}
}
