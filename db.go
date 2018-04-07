package auth

import (
	"sync"
	"time"
	"fmt"
)

// DB represent the storage for macaroon application authentication which is
// needed to keep it secure.
type DB interface {
	// UseNonce mark the nonce as used by the given user.
	UseNonce(id uint32, nonce int64) bool

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
	nonces        map[string]time.Time
	rootKey       []byte
	nonceLifetime time.Duration

	mutex sync.Mutex
	wg    sync.WaitGroup
	quit  chan struct{}
}

func NewInMemoryDB(rootKey []byte, nonceLifetime time.Duration) *InMemoryDB {
	return &InMemoryDB{
		nonces:        make(map[string]time.Time),
		rootKey:       rootKey,
		quit:          make(chan struct{}),
		nonceLifetime: nonceLifetime,
	}
}

func (db *InMemoryDB) StartFlushing() {
	db.wg.Add(1)
	go func() {
		defer db.wg.Done()

		for {
			select {
			case <-time.After(db.nonceLifetime):
			case <-db.quit:
				return
			}

			db.mutex.Lock()

			for key, t := range db.nonces {
				if t.Add(db.nonceLifetime).Before(time.Now()) {
					delete(db.nonces, key)
				}
			}

			db.mutex.Unlock()
		}
	}()
}

func (db *InMemoryDB) StopFlushing() {
	close(db.quit)
	db.wg.Wait()
}

// Runtime check to ensure that InMemoryDB implements DB.
var _ DB = (*InMemoryDB)(nil)

func (db *InMemoryDB) UseNonce(id uint32, nonce int64) bool {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	key := getKey(id, nonce)
	if _, ok := db.nonces[key]; !ok {
		// If service has been shutdown and started faster than macaroon
		// lifetime attacker would have a period of time where he could reuse
		// the stolen macaroon, because in this case db don't have nonce for id
		// and returns zero.
		return false
	}

	db.nonces[key] = time.Now()
	return true
}

func (db *InMemoryDB) GetRootKey() ([]byte, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	return db.rootKey, nil
}

func (db *InMemoryDB) PutRootKey(rootKey []byte) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.rootKey = rootKey
	return nil
}

func getKey(id uint32, nonce int64) string {
	return fmt.Sprintf("%v_%v", id, nonce)
}
