package auth

import (
	"testing"
	"gopkg.in/macaroon.v2"
)

func TestNotPermittedOperation(t *testing.T) {
	m, err := macaroon.New([]byte("kek"), nil, "bitlum",
		macaroon.LatestVersion)
	if err != nil {
		t.Fatalf("unable to create macaron: %v", err)
	}

	op := "some_operation"
	if !IsOperationAllowed(m, op) {
		t.Fatalf("expect operation to be allowed")
	}

	m, err = DisableOperations(m, []string{op})
	if err != nil {
		t.Fatalf("unable to create macaron dictionary: %v", err)
	}

	if IsOperationAllowed(m, op) {
		t.Fatalf("expect operation to be not allowed")
	}

	if !IsOperationAllowed(m, "kek") {
		t.Fatalf("expect operation to allowed")
	}
}
