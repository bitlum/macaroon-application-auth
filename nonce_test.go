package auth

import (
	"testing"
	"gopkg.in/macaroon.v2"
)

func TestCheckNonceFunction(t *testing.T) {
	m, err := macaroon.New([]byte("kek"), nil, "bitlum",
		macaroon.LatestVersion)
	if err != nil {
		t.Fatalf("unable to create macaron: %v", err)
	}

	// Check that check nonce function fail because macaroon not contains
	// nonce and time constraint/caveat/field.
	{
		db := InMemoryNonceDB{}

		if err := CheckNonce(m, 1, db, MacaroonLifetime); err == nil {
			t.Fatalf("expected to fail because don't have time and nonce fields"+
				": %v", err)
		}
	}

	nonce := int64(100)
	m, err = AddNonce(m, nonce)
	if err != nil {
		t.Fatalf("unable to add nonce: %v", err)
	}

	// Check that check nonce function fail because macaroon not contains time
	// constraint/caveat/field.
	{
		db := InMemoryNonceDB{}

		if err := CheckNonce(m, 1, db, MacaroonLifetime); err == nil {
			t.Fatalf("expected to fail because don't have time field: %v", err)
		}
	}

	m, err = AddCurrentTime(m)
	if err != nil {
		t.Fatalf("unable to add current time: %v", err)
	}

	// Check that check nonce function fail because macaroon has expired.
	// working.
	{
		db := InMemoryNonceDB{}

		if err := CheckNonce(m, 1, db, 0); err != ErrMacaroonExpired {
			t.Fatalf("expected to fail because macaron expired: %v", err)
		}
	}

	// Check that check nonce function fail because nonce has been used.
	{
		db := InMemoryNonceDB(map[uint32]int64{1: nonce})

		if err := CheckNonce(m, 1, db, MacaroonLifetime); err != ErrNonceRepeated {
			t.Fatalf("expected to fail because macaron nonce has been used"+
				": %v", err)
		}
	}

	// Check that check nonce function fail because nonce has been used.
	{
		db := InMemoryNonceDB{}

		if err := CheckNonce(m, 1, db, MacaroonLifetime); err != nil {
			t.Fatalf("unable to check macaroon")
		}
	}
}
