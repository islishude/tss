package secp256k1

import (
	"context"
	"testing"

	"github.com/islishude/tss/tssrun"
)

func TestLifecycleSessionStatusUsesExplicitTerminalState(t *testing.T) {
	t.Parallel()

	var nilKeygen *KeygenSession
	var nilRefresh *RefreshSession
	var nilReshare *ReshareSession
	if nilKeygen.Status() != tssrun.SessionClosed || nilRefresh.Status() != tssrun.SessionClosed || nilReshare.Status() != tssrun.SessionClosed {
		t.Fatal("nil lifecycle session did not report closed")
	}

	keygen := &KeygenSession{completed: true, state: keygenConfirmed}
	refresh := &RefreshSession{completed: true}
	reshareDealer := &ReshareSession{completed: true, isDealer: true, isReceiver: false}
	if keygen.Status() != tssrun.SessionSucceeded || refresh.Status() != tssrun.SessionSucceeded || reshareDealer.Status() != tssrun.SessionSucceeded {
		t.Fatal("terminal success did not report SessionSucceeded")
	}
	if share, ok := reshareDealer.KeyShare(); ok || share != nil {
		t.Fatal("dealer-only reshare unexpectedly produced a replacement key share")
	}

	for _, close := range []func(context.Context) error{keygen.Close, refresh.Close, reshareDealer.Close} {
		if err := close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if keygen.Status() != tssrun.SessionClosed || refresh.Status() != tssrun.SessionClosed || reshareDealer.Status() != tssrun.SessionClosed {
		t.Fatal("closed lifecycle session retained a success state")
	}
}

func TestPresignSessionStatusPreservesPersistedDescriptor(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	defer p.Destroy()
	metadata, ok := p.PublicMetadata()
	if !ok {
		t.Fatal("missing public presign metadata")
	}
	descriptor := newPersistedPresign(metadata.LifecycleSlot, metadata)
	session := &PresignSession{completed: true, persistedPresign: &descriptor}

	first, second := session.Status(), session.Status()
	if first != tssrun.SessionSucceeded || second != tssrun.SessionSucceeded {
		t.Fatal("completed presign session did not report repeatable success")
	}
	if session.persistedPresign == nil {
		t.Fatal("Status removed the persisted descriptor")
	}
	got, ok := session.Presign()
	if !ok || got.SlotID() != metadata.LifecycleSlot {
		t.Fatal("Presign did not return the persisted descriptor after status checks")
	}
}
