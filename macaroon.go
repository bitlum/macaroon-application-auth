package auth

import (
	"gopkg.in/macaroon.v2"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"encoding/hex"
)

// MacaroonDictionary macaroon where conditions are represented as fields.
// This type of macaroon represents dictionary with ability to check that
// modification has been made and that original dictionary was created by us.
// Such representation allows divide the extraction and validation logic.
type MacaroonDictionary struct {
	*macaroon.Macaroon
}

func NewMacaroonDictionary(m *macaroon.Macaroon) (*MacaroonDictionary, error) {
	// Check that we don't have condition with repeated prefixes
	_, err := caveatsToMap(m.Caveats())
	if err != nil {
		return nil, err
	}

	return &MacaroonDictionary{
		Macaroon: m,
	}, nil
}

// Put puts field in the macaroon and updates the macaroon signature.
func (md *MacaroonDictionary) Put(key, value string) error {
	fields, err := caveatsToMap(md.Caveats())
	if err != nil {
		return err
	}

	if _, ok := fields[key]; ok {
		return ErrFieldExist
	}

	caveat := checkers.Condition(key, value)
	return md.AddFirstPartyCaveat([]byte(caveat))
}

// Get gets the macaroon fields by its key.
func (md *MacaroonDictionary) Get(key string) (string, error) {
	fields, err := caveatsToMap(md.Caveats())
	if err != nil {
		return "", err
	}

	if value, ok := fields[key]; ok {
		return value, nil
	}

	return "", ErrFieldNotFound
}

// DecodeMacaroon is used by client applications to decode the given macaroon.
func DecodeMacaroon(macaroonStr string) (*macaroon.Macaroon, error) {
	data, err := hex.DecodeString(macaroonStr)
	if err != nil {
		return nil, err
	}

	m := &macaroon.Macaroon{}
	if err := m.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return m, nil
}

// EncodeMacaroon is used by client application to convert macaroon back to
// byte representation.
func EncodeMacaroon(m *macaroon.Macaroon) (string, error) {
	data, err := m.MarshalBinary()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(data), nil
}

func caveatsToMap(caveats []macaroon.Caveat) (map[string]string, error) {
	fields := make(map[string]string, len(caveats))
	for _, c := range caveats {
		k, v, err := checkers.ParseCaveat(string(c.Id))
		if err != nil {
			return nil, err
		}

		if _, ok := fields[k]; ok {
			return nil, ErrRepeatedField
		}

		fields[k] = v
	}

	return fields, nil
}
