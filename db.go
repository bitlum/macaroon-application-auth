package auth

// DB represent the storage for macaroon application authentication which is
// needed to keep it secure.
type DB interface {
	// GetLastNonceByID returns last used nonce by the given user or
	// application id.
	GetLastNonceByID(id uint32) (int64, error)

	// PutLastNonceByID assigns new nonce to the given user or applciation id.
	PutLastNonceByID(id uint32, nonce int64) error

	// GetRootKey returns last stored root key.
	GetRootKey() ([]byte, error)

	// PutRootKey puts new root key. This method might be used for db
	// initialisation or key rotation.
	PutRootKey(rootKey []byte) error
}

// InMemoryDB represent the in-memory storage for nonce and keeps root key
// also in memory, such schema allows requests to proceed fast.
//
// NOTE: If macaroon lifetime becomes bigger enough such schema might become
// insecure.
type InMemoryDB struct {
	nonces  map[uint32]int64
	rootKey []byte
}

func NewInMemoryDB(rootKey []byte) *InMemoryDB {
	return &InMemoryDB{
		nonces:  make(map[uint32]int64),
		rootKey: rootKey,
	}
}

// Runtime check to ensure that InMemoryDB implements DB.
var _ DB = (*InMemoryDB)(nil)

func (db InMemoryDB) GetLastNonceByID(id uint32) (int64, error) {
	nonce, ok := db.nonces[id]
	if !ok {
		// If service has been shutdown and started faster than macaroon
		// lifetime attacker would have a period of time where he could reuse
		// the stolen macaroon, because in this case db don't have nonce for id
		// and returns zero.
		return 0, nil
	}

	return nonce, nil
}

func (db InMemoryDB) PutLastNonceByID(id uint32, nonce int64) error {
	db.nonces[id] = nonce
	return nil
}

func (db InMemoryDB) GetRootKey() ([]byte, error) {
	return db.rootKey, nil
}

func (db InMemoryDB) PutRootKey(rootKey []byte) error {
	db.rootKey = rootKey
	return nil
}
