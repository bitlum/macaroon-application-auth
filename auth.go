package auth

import (
	"strconv"
	"encoding/binary"
	"gopkg.in/macaroon.v2"
)

const (
	UserPrefix              = "user"
	NoncePrefix             = "nonce"
	DisabledOperationPrefix = "disops"
	TimePrefix              = "time"
)

// Auth is an application authenticator which implements the auth.
// Auth and used for issuing and checking the validity of third-party tokens.
// Third-party token usually is used by trading bots, and wallet applications,
// they not have expiration time, but do have a set of permitted operations,
// which might be or might be not restricted down to read operations,
// or info operations. This type of token by default do not have a right to
// issue another applications tokens.
type Auth struct {
	rootKey  []byte
	nonceDB  NonceDB
	location string

	// TODO(andrew.shvv) Add token revocation.
}

// NewAuth creates new instance of application auth.
func NewAuth(location string, nonceDB NonceDB) *Auth {
	return &Auth{
		nonceDB:  nonceDB,
		location: location,
		// TODO(andrew.shvv) add root recycling.
		rootKey: []byte("2871tgylio"),
	}
}

// GenerateToken issues the token with the user id and operations
// constraints, this token do not have a nonce and time by default,
// so it could be used by client infinitely. Client in other hand is responsible
// for adding the nonce and time constraints to ensure that even if token
// will be intercepted by an attacker he/she couldn't use it for replay attack.
// Token without nonce and time will be discarded during validation operation.
func (a *Auth) GenerateToken(userID uint32,
	disabledOperations []string) (string, error) {

	// TODO(andrew.shvv) Use application id instead,
	// but that would require some form of database.
	var macaroonID [4]byte
	binary.BigEndian.PutUint32(macaroonID[:], userID)

	m, err := macaroon.New(a.rootKey, macaroonID[:], a.location,
		macaroon.LatestVersion)
	if err != nil {
		return "", err
	}

	if disabledOperations != nil {
		m, err = DisableOperations(m, disabledOperations)
		if err != nil {
			return "", err
		}
	}

	// Convert macaroon to check that it not contains any duplicate fields and
	// also in order to put the user id in it.
	md, err := NewMacaroonDictionary(m)
	if err != nil {
		return "", nil
	}

	// Put user id so that latter extract it from macaroon. As far as macaroon
	// is signed and later validated by us with our root key we treat user id
	// information as something which couldn't be changed.
	userIDStr := strconv.FormatUint(uint64(userID), 10)
	if err := md.Put(UserPrefix, userIDStr); err != nil {
		return "", err
	}

	return EncodeMacaroon(m)
}
