package auth

import (
	"strings"
	"gopkg.in/macaroon.v2"
)

// DisableOperations restricts allowed operations.
func DisableOperations(m *macaroon.Macaroon, ops []string) (*macaroon.Macaroon,
	error) {
	newMac := m.Clone()
	md, err := NewMacaroonDictionary(newMac)
	if err != nil {
		return nil, err
	}

	return newMac, md.Put(DisabledOperationPrefix, strings.Join(ops, ","))
}

// IsOperationAllowed checks that incoming macaroon has the ability to access the
// desired method.
func IsOperationAllowed(m *macaroon.Macaroon, op string) bool {
	md, err := NewMacaroonDictionary(m)
	if err != nil {
		return false
	}

	data, err := md.Get(DisabledOperationPrefix)
	if err == ErrFieldNotFound {
		// If disabled operation field not found all operations are allowed.
		return true
	} else if err != nil {
		return false
	}

	disabledOperations := strings.Split(data, ",")
	for _, disOp := range disabledOperations {
		if op == disOp {
			return false
		}
	}

	return true
}
