package secp256k1

import (
	"context"
	"testing"
)

type testClosableSession interface {
	Close(context.Context) error
}

func closeTestSession(t testing.TB, session testClosableSession) {
	t.Helper()
	if err := session.Close(context.Background()); err != nil {
		t.Errorf("close test session: %v", err)
	}
}
