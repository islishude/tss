package secp256k1

import "testing"

func TestLifecycleSessionCompletedUsesTerminalState(t *testing.T) {
	t.Parallel()

	var nilKeygen *KeygenSession
	var nilRefresh *RefreshSession
	var nilReshare *ReshareSession
	if nilKeygen.Completed() || nilRefresh.Completed() || nilReshare.Completed() {
		t.Fatal("nil lifecycle session reported completion")
	}

	keygen := &KeygenSession{completed: true, state: keygenConfirmed}
	refresh := &RefreshSession{completed: true}
	reshareDealer := &ReshareSession{completed: true, isDealer: true, isReceiver: false}
	if !keygen.Completed() || !refresh.Completed() || !reshareDealer.Completed() {
		t.Fatal("terminal lifecycle state reported incomplete without an accessor result")
	}
	if share, ok := reshareDealer.KeyShare(); ok || share != nil {
		t.Fatal("dealer-only reshare unexpectedly produced a replacement key share")
	}

	keygen.Destroy()
	refresh.Destroy()
	reshareDealer.Destroy()
	if keygen.Completed() || refresh.Completed() || reshareDealer.Completed() {
		t.Fatal("destroyed lifecycle session retained completion state")
	}
}

func TestPresignSessionCompletedExposesOnlyPersistedDescriptor(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	defer p.Destroy()
	metadata, ok := p.PublicMetadata()
	if !ok {
		t.Fatal("missing public presign metadata")
	}
	descriptor := newPersistedPresign(metadata.LifecycleSlot, metadata)
	session := &PresignSession{
		completed:        true,
		persistedPresign: &descriptor,
	}

	if !session.Completed() {
		t.Fatal("completed presign session reported incomplete on first check")
	}
	if !session.Completed() {
		t.Fatal("completed presign session reported incomplete on repeated check")
	}
	if session.persistedPresign == nil {
		t.Fatal("Completed removed the persisted descriptor")
	}

	got, ok := session.Presign()
	if !ok || got.SlotID() != metadata.LifecycleSlot {
		t.Fatal("Presign did not return the persisted descriptor after status checks")
	}
}
