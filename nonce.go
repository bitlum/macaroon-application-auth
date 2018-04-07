package auth

import (
	"strconv"
	"time"
	"gopkg.in/macaroon.v2"
)

// MacaroonLifetime is the period of time during which macaroon remains
// fresh, after that we believe that it is outdated and could remove stored
// nonce. With this we could have a in-memory nonce database because even if
// service goes down, attacker couldn't reuse the token after lifetime.
//
// NOTE: If time becomes greater than possible service downtime we should
// implement persistent nonce database.
var MacaroonLifetime = 5 * time.Second

// AddNonce is used by the client application to add nonce,
// to the macaroon before making the request. With every request nonce should
// be increasing. This field is need to protect client from replay-attack.
func AddNonce(m *macaroon.Macaroon, nonce int64) (*macaroon.Macaroon, error) {
	newMac := m.Clone()
	md, err := NewMacaroonDictionary(newMac)
	if err != nil {
		return nil, err
	}

	return newMac, md.Put(NoncePrefix, strconv.FormatInt(nonce, 10))
}

// AddCurrentTime is used by the client to add the time when macaroon has
// been crafted/modified, after some period of time, depending on how server is
// configured macaroon become expired. This field is need to protect client from
// replay-attack.
func AddCurrentTime(m *macaroon.Macaroon) (*macaroon.Macaroon, error) {
	newMac := m.Clone()
	md, err := NewMacaroonDictionary(newMac)
	if err != nil {
		return nil, err
	}

	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	return newMac, md.Put(TimePrefix, now)
}

// CheckNonce checks that nonce hasn't been used twice. With this we protect
// user form replay-attack.
func CheckNonce(m *macaroon.Macaroon, id uint32, db DB,
	lifetime time.Duration) error {
	md, err := NewMacaroonDictionary(m)
	if err != nil {
		return err
	}

	// Extract macaroon creation time and check that macaroon hasn't expired.
	field, err := md.Get(TimePrefix)
	if err != nil {
		return err
	}

	t, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		return err
	}

	creationTime := time.Unix(0, t)

	expirationTime := creationTime.Add(lifetime)
	if time.Now().After(expirationTime) {
		return ErrMacaroonExpired
	}

	// Extract macaroon nonce and check that given macaroons greater that
	// what we have in database, otherwise we believe that we already used it.
	field, err = md.Get(NoncePrefix)
	if err != nil {
		return err
	}

	macaroonNonce, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		return err
	}

	if db.UseNonce(id, macaroonNonce) {
		return ErrNonceUsed
	}

	return nil
}
