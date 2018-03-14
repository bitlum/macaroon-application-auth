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

// NonceDB represent the storage for the nonce.
type NonceDB interface {
	GetLastNonceByID(id uint32) (int64, error)
	PutLastNonceByID(id uint32, nonce int64) error

	// TODO(andrew.shvv) Add StartTransaction,
	// EndTransaction otherwise there is time between
}

// InMemoryNonceDB represent the in-memory storage for nonce.
type InMemoryNonceDB map[uint32]int64

// Runtime check to ensure that InMemoryNonceDB implements NonceDB.
var _ NonceDB = (*InMemoryNonceDB)(nil)

func (db InMemoryNonceDB) GetLastNonceByID(id uint32) (int64, error) {
	nonce, ok := db[id]
	if !ok {
		// If service has been shutdown and started faster than macaroon
		// lifetime attacker would have a period of time where he could reuse
		// the stolen macaroon, because in this case db don't have nonce for id
		// and returns zero.
		return 0, nil
	}

	return nonce, nil
}

func (db InMemoryNonceDB) PutLastNonceByID(id uint32, nonce int64) error {
	db[id] = nonce
	return nil
}

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
func CheckNonce(m *macaroon.Macaroon, id uint32, db NonceDB,
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

	dbNonce, err := db.GetLastNonceByID(id)
	if err != nil {
		return err
	}

	if dbNonce >= macaroonNonce {
		return ErrNonceRepeated
	}

	return db.PutLastNonceByID(id, macaroonNonce)
}
