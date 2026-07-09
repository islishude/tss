package secp256k1

import "testing"

func TestSessionTransitionShape(t *testing.T) {
	t.Parallel()

	concrete := &helperTransition{}
	var transition sessionTransition[helperTransitionState] = concrete
	state := helperTransitionState{}
	effects, err := transition.apply(&state)
	if err != nil {
		t.Fatal(err)
	}
	if len(effects.envelopes) != 0 {
		t.Fatalf("effects contained %d envelopes", len(effects.envelopes))
	}
	transition.cleanupOnReject()
	if !concrete.cleaned {
		t.Fatal("transition cleanup was not recorded")
	}
	transition.markCommitted()
	if !state.applied {
		t.Fatal("transition did not apply")
	}
	if !concrete.committed {
		t.Fatal("transition commit was not recorded")
	}
}

type helperTransitionState struct {
	applied bool
}

type helperTransition struct {
	committed bool
	cleaned   bool
}

func (t *helperTransition) apply(state *helperTransitionState) (sessionEffects, error) {
	state.applied = true
	return sessionEffects{}, nil
}

func (t *helperTransition) cleanupOnReject() {
	if !t.committed {
		t.cleaned = true
	}
}

func (t *helperTransition) markCommitted() {
	t.committed = true
}
