package auth

import (
	"encoding/binary"
	"github.com/go-errors/errors"
	"gopkg.in/macaroon.v2"
)

type Token struct {
	macaroon *macaroon.Macaroon
	userID   uint32
}

// ExtractToken checks that the given token represent the subset of macaroon
// tokens. Initially client's token do not have the nonce and time constraints
// but client is responsible for adding them to ensure that even if token
// will be intercepted by an attacker he/she couldn't use it for replay attack.
func (a *Auth) ExtractToken(tokenStr string) (*Token, error) {
	if tokenStr == "" {
		return nil, errors.Errorf("token not found")
	}

	// With the macaroon obtained, we'll now decode the hex-string
	// encoding, then unmarshal it from binary into its concrete struct
	// representation.
	m, err := DecodeMacaroon(tokenStr)
	if err != nil {
		return nil, errors.Errorf("unable to decode macaroon: %v", err)
	}

	// Checks that signature is haven't bee tempered with. Note that we pass
	// empty checker because we do the manual caveat validation.
	emptyCheck := func(_ string) error { return nil }
	if err := m.Verify(a.rootKey, emptyCheck, nil); err != nil {
		return nil, err
	}

	// TODO(andrew.shvv) Use application id instead,
	// but that would require some form of database.
	userID := binary.BigEndian.Uint32(m.Id())

	// Check that token has expired and that nonce is greater than previous
	// one used by application.
	if err := CheckNonce(m, userID, a.nonceDB, MacaroonLifetime); err != nil {
		return nil, err
	}

	return &Token{
		macaroon: m,
		userID:   userID,
	}, nil
}

// IsAuthorized checks that the given token is authorized to make given
// operation.
func (t *Token) IsAuthorized(operation string) error {
	// Check that operation application wants to access is not disabled in the
	// token.
	if !IsOperationAllowed(t.macaroon, operation) {
		return ErrOperNotAllowed
	}

	return nil
}

// UserID returns the user id which was originally stored in the macaroon
// payload.
func (t *Token) UserID() uint32 {
	return t.userID
}
