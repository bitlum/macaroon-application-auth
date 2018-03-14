package auth

import "github.com/go-errors/errors"

var (
	ErrFieldNotFound = errors.Errorf("unable to find field")
	ErrFieldExist    = errors.Errorf("field already exist")
	ErrRepeatedField = errors.Errorf("repeated conditions")

	ErrMacaroonExpired = errors.Errorf("macaroon expired")
	ErrNonceRepeated   = errors.Errorf("nonce is used already")

	ErrOperNotAllowed = errors.Errorf("operation not allowed")
)
