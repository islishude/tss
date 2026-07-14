package secp256k1

import "github.com/islishude/tss"

func paperKeygenTestPolicies() tss.PolicySet {
	entries := CGGMP21Policies().Entries()
	for i := range entries {
		entries[i].BroadcastConsistency = tss.BroadcastConsistencyNone
		entries[i].RequireSenderSignature = false
	}
	policies, err := tss.NewPolicySet(entries...)
	if err != nil {
		panic(err)
	}
	return policies
}

func paperKeygenTestGuard(self tss.PartyID, parties tss.PartySet, sid tss.SessionID) *tss.EnvelopeGuard {
	return tss.NewTestEnvelopeGuard(self, parties, tss.ProtocolCGGMP21Secp256k1, sid, paperKeygenTestPolicies())
}
