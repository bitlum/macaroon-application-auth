package auth

import (
	"testing"
	"gopkg.in/macaroon.v2"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
)

func TestRepeatedFieldAdd(t *testing.T) {
	m, err := macaroon.New([]byte("kek"), nil, "bitlum",
		macaroon.LatestVersion)
	if err != nil {
		t.Fatalf("unable to create macaron: %v", err)
	}

	md, err := NewMacaroonDictionary(m)
	if err != nil {
		t.Fatalf("unable to create macaron dictionary: %v", err)
	}

	if err := md.Put("kek", "kek"); err != nil {
		t.Fatalf("unable to put field in macaron dictionary: %v", err)
	}

	if value, err := md.Get("kek"); err != nil {
		t.Fatalf("unable to put field in macaron dictionary: %v", err)
	} else if value != "kek" {
		t.Fatalf("wrong value")
	}

	if err := md.Put("kek", "kek"); err != ErrFieldExist {
		t.Fatalf("repeate error haven't been received: %v", err)
	}

	if _, err := md.Get("nonexisting_kek"); err != ErrFieldNotFound {
		t.Fatalf("unable to put field in macaron dictionary: %v", err)
	}
}

func TestRepeatedConditionOnInit(t *testing.T) {
	m, err := macaroon.New([]byte("kek"), nil, "bitlum",
		macaroon.LatestVersion)
	if err != nil {
		t.Fatalf("unable to create macaron: %v", err)
	}

	caveat := checkers.Condition("kek", "kek")
	if err := m.AddFirstPartyCaveat([]byte(caveat)); err != nil {
		t.Fatalf("unable to add caveat: %v", err)
	}

	if err := m.AddFirstPartyCaveat([]byte(caveat)); err != nil {
		t.Fatalf("unable to add caveat: %v", err)
	}

	if _, err := NewMacaroonDictionary(m); err != ErrRepeatedField {
		t.Fatalf("expected receive repeated field value")
	}
}
